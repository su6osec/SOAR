# =============================================================================
# main.tf — SOAR Lab: Cloud Threat Detection & Incident Response
# =============================================================================
# Deploys:
#   1. GuardDuty detector (account-level threat monitoring)
#   2. CloudWatch Log Group for Lambda structured logs
#   3. IAM execution role + least-privilege inline policy for Lambda
#   4. Lambda function (remediate.py) with zip packaging via archive_file
#   5. EventBridge rule scoped to GuardDuty AccessKeyLeak findings
#   6. EventBridge → Lambda target + invocation permission
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # ---------------------------------------------------------------------------
  # Backend: local state for portfolio/demo.
  # For production, replace with:
  #
  # backend "s3" {
  #   bucket         = "your-tfstate-bucket"
  #   key            = "soar-lab/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
  # ---------------------------------------------------------------------------
  backend "local" {
    path = "terraform.tfstate"
  }
}

# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      Owner       = var.owner
      ManagedBy   = "Terraform"
      Repository  = "soar-lab"
    }
  }
}

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

# Current account ID & ARN — used for IAM policy scoping
data "aws_caller_identity" "current" {}

# Current region — for constructing partition-safe ARNs
data "aws_partition" "current" {}

# Package the Lambda source into a zip at plan time.
# Terraform will re-zip and redeploy whenever remediate.py changes (hash check).
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/src/remediate.py"
  output_path = "${path.module}/lambda_payload.zip"
}

# ---------------------------------------------------------------------------
# 1. GuardDuty Detector
# ---------------------------------------------------------------------------
# NOTE: GuardDuty requires a one-time console activation for new AWS accounts.
# Enable it manually at: AWS Console → GuardDuty → Get Started → Enable GuardDuty
# Once enabled, import the detector ID with:
#   terraform import aws_guardduty_detector.main <detector-id>
#
# Uncomment the block below after enabling GuardDuty in the console:
#
# resource "aws_guardduty_detector" "main" {
#   enable                       = true
#   finding_publishing_frequency = var.guardduty_finding_frequency
#   tags = {
#     Name = "${var.project_name}-guardduty-detector"
#   }
# }


# ---------------------------------------------------------------------------
# 2. CloudWatch Log Group (pre-create so retention policy is applied before
#    Lambda first runs — avoids logs defaulting to "Never expire")
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}-remediate"
  retention_in_days = var.lambda_log_retention_days

  tags = {
    Name = "${var.project_name}-lambda-logs"
  }
}

# ---------------------------------------------------------------------------
# 3. IAM — Lambda Execution Role (least privilege)
# ---------------------------------------------------------------------------

# Trust policy: only AWS Lambda service can assume this role
data "aws_iam_policy_document" "lambda_trust" {
  statement {
    sid     = "LambdaAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.project_name}-lambda-exec-role"
  description        = "Least-privilege execution role for the SOAR remediation Lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json

  tags = {
    Name = "${var.project_name}-lambda-exec-role"
  }
}

# Inline policy — grants ONLY the specific actions required.
# No managed AdministratorAccess, no PowerUser, no wildcard service access.
data "aws_iam_policy_document" "lambda_permissions" {

  # CloudWatch Logs — structured logging
  statement {
    sid    = "AllowCloudWatchLogging"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      # Scope to the specific log group only
      "${aws_cloudwatch_log_group.lambda_logs.arn}",
      "${aws_cloudwatch_log_group.lambda_logs.arn}:*",
    ]
  }

  # IAM — key deactivation and user freezing
  # Scoped to the current account; not a wildcard across accounts.
  statement {
    sid    = "AllowIAMRemediation"
    effect = "Allow"

    actions = [
      "iam:UpdateAccessKey",    # Deactivate the compromised access key
      "iam:PutUserPolicy",      # Attach ExplicitDenyAll inline policy
      "iam:ListAccessKeys",     # Enumerate keys to verify deactivation
      "iam:GetUser",            # Confirm user exists before taking action
    ]

    # Scope to IAM users only (not roles, groups, or policies)
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/*"
    ]
  }

  # GuardDuty — allow Lambda to fetch full finding details if needed
  statement {
    sid    = "AllowGuardDutyGetFinding"
    effect = "Allow"

    actions = [
      "guardduty:GetFindings",
      "guardduty:ListDetectors",
    ]

    resources = ["*"] # GuardDuty GetFindings does not support resource-level ARNs
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "${var.project_name}-lambda-inline-policy"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# ---------------------------------------------------------------------------
# 4. Lambda Function — Remediation Handler
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "remediate" {
  function_name    = "${var.project_name}-remediate"
  description      = "Remediates GuardDuty IAM Access Key compromise findings: deactivates key and freezes IAM user"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = var.lambda_runtime
  handler          = "remediate.lambda_handler"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  # Ensure the log group and IAM role exist before Lambda is created
  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy.lambda_inline,
  ]

  tags = {
    Name = "${var.project_name}-remediate"
  }
}

# ---------------------------------------------------------------------------
# 5. EventBridge Rule — GuardDuty Finding Filter
# ---------------------------------------------------------------------------
# Matches ONLY the specific finding type for IAM Access Key compromise.
# EventBridge pattern uses exact string matching on detail.type.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "guardduty_finding" {
  name        = "${var.project_name}-guardduty-finding-rule"
  description = "Triggers SOAR remediation Lambda on GuardDuty IAM Access Key compromise findings"

  # EventBridge content-based filtering pattern.
  # "detail.type" is compared with prefix matching when using array values.
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [var.target_finding_type]
    }
  })

  state = "ENABLED"

  tags = {
    Name = "${var.project_name}-guardduty-finding-rule"
  }
}

# ---------------------------------------------------------------------------
# 6. EventBridge → Lambda Target
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_finding.name
  target_id = "${var.project_name}-remediation-lambda"
  arn       = aws_lambda_function.remediate.arn

  # No dead-letter queue or retry config needed here because:
  # - EventBridge retries failed Lambda invocations for up to 24 hours by default
  # - Lambda itself has error handling and structured logging
  # For production, add a DLQ:
  # dead_letter_config {
  #   arn = aws_sqs_queue.dlq.arn
  # }
}

# ---------------------------------------------------------------------------
# 7. Lambda Invocation Permission — grants EventBridge permission to invoke
# ---------------------------------------------------------------------------

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_finding.arn
}
