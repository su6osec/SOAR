"""
remediate.py — SOAR Lab: Automated IAM Access Key Compromise Remediation
=========================================================================
Triggered by Amazon EventBridge when GuardDuty raises a finding of type:
  UnauthorizedAccess:IAMUser/AccessKeyLeak

Remediation steps (in order):
  1. Parse and validate the incoming GuardDuty event payload.
  2. Extract the target IAM username and compromised AccessKeyId.
  3. Deactivate (Inactive) the compromised Access Key via boto3.
  4. Attach an ExplicitDenyAll inline IAM policy to freeze the user account.
  5. Emit a structured JSON log entry to CloudWatch Logs.

Design principles:
  - Zero external dependencies (only boto3 + stdlib — pre-installed in Lambda).
  - Exponential back-off (3 attempts) on AWS API throttling errors.
  - Idempotent: safe to invoke multiple times for the same finding.
  - All sensitive data (AccessKeyId) is partially masked in logs.

Environment Variables:
  LOG_LEVEL   Python log level (default: INFO).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging — structured JSON to CloudWatch Logs
# ---------------------------------------------------------------------------
# In AWS Lambda the runtime pre-installs a StreamHandler on the root logger
# before user code runs, making basicConfig() a no-op. Grab the root logger
# directly and set its level explicitly so INFO records reach CloudWatch.

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logger = logging.getLogger()  # root logger — pre-wired to CloudWatch by Lambda
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
for handler in logger.handlers:
    handler.setFormatter(logging.Formatter("%(message)s"))  # raw JSON lines


def _log(level: str, message: str, **kwargs: Any) -> None:
    """Emit a structured JSON log record."""
    record = {
        "level": level,
        "message": message,
        "service": "soar-remediate",
        **kwargs,
    }
    log_fn = getattr(logger, level.lower(), logger.info)
    log_fn(json.dumps(record))


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# ExplicitDenyAll inline policy — blocks ALL API calls for the IAM user.
# Attached immediately after key deactivation as a belt-and-suspenders control.
DENY_ALL_POLICY_NAME = "SOARExplicitDenyAll"
DENY_ALL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ExplicitDenyAll",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
)

# Retry configuration for AWS API throttling
MAX_RETRIES = 3
RETRY_BASE_DELAY_SECONDS = 1.0  # doubles on each attempt: 1s → 2s → 4s

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _mask(value: str, visible_chars: int = 4) -> str:
    """
    Partially mask a sensitive string for safe logging.
    Example: 'AKIAIOSFODNN7EXAMPLE' → 'AKIA****************'
    """
    if not value or len(value) <= visible_chars:
        return "****"
    return value[:visible_chars] + "*" * (len(value) - visible_chars)


def _retry_on_throttle(fn, *args, **kwargs):
    """
    Call `fn(*args, **kwargs)` with exponential back-off on AWS throttling.
    Raises the original ClientError if all retries are exhausted.
    """
    delay = RETRY_BASE_DELAY_SECONDS
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return fn(*args, **kwargs)
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code in ("Throttling", "ThrottlingException", "RequestLimitExceeded"):
                if attempt == MAX_RETRIES:
                    _log(
                        "error",
                        "AWS API throttling: max retries exhausted",
                        attempt=attempt,
                        error_code=error_code,
                    )
                    raise
                _log(
                    "warning",
                    "AWS API throttling — retrying",
                    attempt=attempt,
                    retry_in_seconds=delay,
                    error_code=error_code,
                )
                time.sleep(delay)
                delay *= 2
            else:
                # Non-throttling ClientError — raise immediately
                raise


# ---------------------------------------------------------------------------
# Step 1 — Parse & validate GuardDuty event
# ---------------------------------------------------------------------------


def parse_guardduty_event(event: dict) -> dict:
    """
    Extract key fields from a GuardDuty finding delivered via EventBridge.

    Returns a dict with:
        finding_id     : GuardDuty finding ID
        finding_type   : e.g. 'UnauthorizedAccess:IAMUser/AccessKeyLeak'
        severity       : float (1-10)
        region         : AWS region of the finding
        account_id     : AWS account ID
        username       : IAM username of the affected principal
        access_key_id  : The compromised access key ID
        event_time     : ISO-8601 timestamp of the finding
        description    : Human-readable finding description
    """
    try:
        detail: dict = event["detail"]
    except KeyError:
        raise ValueError(
            "Event is missing the 'detail' key. "
            "Ensure this Lambda is only triggered by EventBridge GuardDuty events."
        )

    # Top-level finding metadata
    finding_id: str = detail.get("id", "unknown-finding-id")
    finding_type: str = detail.get("type", "UnknownType")
    severity: float = float(detail.get("severity", 0.0))
    region: str = detail.get("region", event.get("region", "unknown"))
    account_id: str = detail.get("accountId", event.get("account", "unknown"))
    event_time: str = detail.get("createdAt", detail.get("updatedAt", "unknown"))
    description: str = detail.get("description", "No description provided.")

    # Navigate to the IAM resource details
    # GuardDuty finding schema: detail.resource.accessKeyDetails
    try:
        resource: dict = detail["resource"]
    except KeyError:
        raise ValueError(
            f"GuardDuty finding '{finding_id}' is missing 'detail.resource'. "
            "Cannot identify the affected IAM resource."
        )

    try:
        access_key_details: dict = resource["accessKeyDetails"]
    except KeyError:
        raise ValueError(
            f"GuardDuty finding '{finding_id}' is missing "
            "'detail.resource.accessKeyDetails'. "
            "This finding may not be an IAM credential compromise finding."
        )

    try:
        username: str = access_key_details["userName"]
    except KeyError:
        raise ValueError(
            f"GuardDuty finding '{finding_id}' is missing "
            "'detail.resource.accessKeyDetails.userName'. "
            "Cannot identify the IAM user to remediate."
        )

    try:
        access_key_id: str = access_key_details["accessKeyId"]
    except KeyError:
        raise ValueError(
            f"GuardDuty finding '{finding_id}' is missing "
            "'detail.resource.accessKeyDetails.accessKeyId'. "
            "Cannot identify which access key to deactivate."
        )

    parsed = {
        "finding_id": finding_id,
        "finding_type": finding_type,
        "severity": severity,
        "region": region,
        "account_id": account_id,
        "username": username,
        "access_key_id": access_key_id,
        "event_time": event_time,
        "description": description,
    }

    _log(
        "info",
        "GuardDuty event parsed successfully",
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        username=username,
        access_key_id_masked=_mask(access_key_id),
        region=region,
        account_id=account_id,
    )

    return parsed


# ---------------------------------------------------------------------------
# Step 2 — Deactivate the compromised Access Key
# ---------------------------------------------------------------------------


def deactivate_access_key(iam_client, username: str, access_key_id: str) -> None:
    """
    Set the compromised IAM Access Key status to 'Inactive'.

    This is idempotent: calling it on an already-inactive key does not raise
    an error on the AWS side.
    """
    _log(
        "info",
        "Deactivating IAM Access Key",
        username=username,
        access_key_id_masked=_mask(access_key_id),
    )

    try:
        _retry_on_throttle(
            iam_client.update_access_key,
            UserName=username,
            AccessKeyId=access_key_id,
            Status="Inactive",
        )
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_msg = exc.response["Error"]["Message"]

        if error_code == "NoSuchEntity":
            # Key or user no longer exists — treat as already remediated
            _log(
                "warning",
                "Access key or user not found — may already be deleted",
                username=username,
                access_key_id_masked=_mask(access_key_id),
                error_code=error_code,
            )
            return

        _log(
            "error",
            "Failed to deactivate access key",
            username=username,
            access_key_id_masked=_mask(access_key_id),
            error_code=error_code,
            error_message=error_msg,
        )
        raise

    _log(
        "info",
        "IAM Access Key successfully deactivated",
        username=username,
        access_key_id_masked=_mask(access_key_id),
    )


# ---------------------------------------------------------------------------
# Step 3 — Freeze the IAM user (ExplicitDenyAll inline policy)
# ---------------------------------------------------------------------------


def freeze_iam_user(iam_client, username: str) -> None:
    """
    Attach an ExplicitDenyAll inline policy to the IAM user.

    This immediately blocks ALL API calls made with any credential belonging
    to this user — including credentials other than the compromised key,
    and including role assumptions if the user has permissions to do so.

    The policy name is idempotent: re-applying it simply overwrites the
    existing policy document (PutUserPolicy is a create-or-replace operation).
    """
    _log(
        "info",
        "Attaching ExplicitDenyAll inline policy to IAM user",
        username=username,
        policy_name=DENY_ALL_POLICY_NAME,
    )

    try:
        _retry_on_throttle(
            iam_client.put_user_policy,
            UserName=username,
            PolicyName=DENY_ALL_POLICY_NAME,
            PolicyDocument=DENY_ALL_POLICY_DOCUMENT,
        )
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_msg = exc.response["Error"]["Message"]

        if error_code == "NoSuchEntity":
            _log(
                "warning",
                "IAM user not found while attaching freeze policy — user may have been deleted",
                username=username,
                error_code=error_code,
            )
            return

        _log(
            "error",
            "Failed to attach ExplicitDenyAll policy",
            username=username,
            error_code=error_code,
            error_message=error_msg,
        )
        raise

    _log(
        "info",
        "ExplicitDenyAll policy attached — IAM user is now frozen",
        username=username,
        policy_name=DENY_ALL_POLICY_NAME,
    )


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------


def lambda_handler(event: dict, context: object) -> dict:
    """
    AWS Lambda entry point.

    Parameters
    ----------
    event   : EventBridge event dict containing the GuardDuty finding in `detail`.
    context : Lambda context object (used for request_id logging).

    Returns
    -------
    dict with 'statusCode' (200 = success, 500 = unrecoverable error) and
    a 'body' JSON string summarising actions taken.
    """
    request_id: str = getattr(context, "aws_request_id", "local-test")

    _log(
        "info",
        "Lambda invocation started",
        request_id=request_id,
        event_source=event.get("source", "unknown"),
        detail_type=event.get("detail-type", "unknown"),
    )

    # ------------------------------------------------------------------
    # Phase 1: Parse event
    # ------------------------------------------------------------------
    try:
        finding = parse_guardduty_event(event)
    except (ValueError, KeyError) as exc:
        _log(
            "error",
            "Failed to parse GuardDuty event — aborting remediation",
            request_id=request_id,
            error=str(exc),
        )
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Event parsing failed", "detail": str(exc)}),
        }

    username = finding["username"]
    access_key_id = finding["access_key_id"]

    # ------------------------------------------------------------------
    # Phase 2: AWS remediation actions
    # ------------------------------------------------------------------
    iam_client = boto3.client("iam")
    remediation_errors: list[str] = []

    # 2a. Deactivate the compromised Access Key
    try:
        deactivate_access_key(iam_client, username, access_key_id)
    except ClientError as exc:
        error_detail = f"deactivate_access_key failed: {exc.response['Error']['Code']} — {exc.response['Error']['Message']}"
        _log("error", error_detail, username=username, request_id=request_id)
        remediation_errors.append(error_detail)

    # 2b. Freeze the IAM user with ExplicitDenyAll
    try:
        freeze_iam_user(iam_client, username)
    except ClientError as exc:
        error_detail = f"freeze_iam_user failed: {exc.response['Error']['Code']} — {exc.response['Error']['Message']}"
        _log("error", error_detail, username=username, request_id=request_id)
        remediation_errors.append(error_detail)

    # ------------------------------------------------------------------
    # Phase 3: Final summary log
    # ------------------------------------------------------------------
    success = len(remediation_errors) == 0

    summary = {
        "finding_id": finding["finding_id"],
        "finding_type": finding["finding_type"],
        "username": username,
        "access_key_id_masked": _mask(access_key_id),
        "account_id": finding["account_id"],
        "region": finding["region"],
        "severity": finding["severity"],
        "actions_taken": [
            "access_key_deactivated",
            "explicit_deny_all_policy_attached",
        ],
        "remediation_errors": remediation_errors,
        "success": success,
        "request_id": request_id,
    }

    _log(
        "info" if success else "error",
        "Remediation completed" if success else "Remediation completed with errors",
        **summary,
    )

    return {
        "statusCode": 200 if success else 500,
        "body": json.dumps(summary),
    }
