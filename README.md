# Cloud Threat Detection & Incident Response — SOAR Lab

[![Terraform](https://img.shields.io/badge/Terraform-≥1.6-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-GuardDuty%20%7C%20Lambda%20%7C%20EventBridge-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1078%20%7C%20T1530-red)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Portfolio Project** — An enterprise-grade, serverless Security Orchestration, Automation, and Response (SOAR) pipeline built on AWS. This architecture autonomously detects compromised IAM credentials via GuardDuty, isolates threats by instantly freezing compromised principals via Lambda, and generates structured security audit logs—achieving zero-trust containment within seconds.

---

## System Architecture

![SOAR Architecture Diagram](assets/architecture_wide.png)

### Data Flow Summary

| Step | Event | Technology |
|------|-------|-----------|
| 1 | Threat activity detected (API call anomaly, credential exposure) | AWS GuardDuty |
| 2 | Finding published to EventBridge default bus | GuardDuty → EventBridge |
| 3 | Event pattern matched: `detail.type = UnauthorizedAccess:IAMUser/AccessKeyLeak` | EventBridge Rule |
| 4 | Lambda invoked synchronously with finding JSON payload | EventBridge → Lambda |
| 5 | Access Key status → `Inactive` | Lambda → IAM API |
| 6 | `ExplicitDenyAll` inline policy attached to IAM user | Lambda → IAM API |
| 7 | Structured JSON log emitted | Lambda → CloudWatch Logs |

---

## MITRE ATT&CK Cloud Mapping

This lab detects and responds to the following ATT&CK techniques:

### T1078.004 — Valid Accounts: Cloud Accounts
- **Tactic**: Initial Access, Persistence, Privilege Escalation, Defense Evasion
- **Description**: Adversaries may obtain and abuse credentials of cloud accounts to gain initial access or maintain persistence. Compromised IAM Access Keys allow attackers to authenticate as a legitimate user, bypassing MFA and network controls.
- **Detection**: GuardDuty `UnauthorizedAccess:IAMUser/AccessKeyLeak` — identifies access keys found on public code repositories or used from anomalous geolocations.
- **Automated Response**: Key deactivated + `ExplicitDenyAll` policy attached within seconds of detection.

### T1530 — Data from Cloud Storage Object
- **Tactic**: Collection
- **Description**: Adversaries may access data from cloud storage (S3) using compromised credentials. With a leaked IAM key, an attacker can enumerate and download S3 buckets before defenders respond.
- **Detection**: GuardDuty S3 Protection monitors `s3:GetObject`, `s3:ListBuckets` calls from unusual principals/IPs.
- **Automated Response**: Freezing the IAM user with `ExplicitDenyAll` immediately blocks all S3 API calls, stopping exfiltration mid-stream.

### T1580 — Cloud Infrastructure Discovery
- **Tactic**: Discovery
- **Description**: Adversaries may attempt to discover cloud infrastructure (EC2, Lambda, RDS) after gaining initial access with compromised credentials.
- **Detection**: GuardDuty detects reconnaissance API calls (`ec2:DescribeInstances`, `iam:ListRoles`) from known malicious IPs.
- **Automated Response**: User freeze blocks all discovery API calls simultaneously.

---

## Project Structure

```
SOAR/
├── main.tf                    # Core Terraform: all AWS resources
├── variables.tf               # Parameterized input variables
├── outputs.tf                 # Key resource ARNs exposed post-deploy
├── terraform.tfvars.example   # Safe-to-commit variable template
├── src/
│   └── remediate.py           # Lambda handler (boto3 remediation logic)
└── README.md                  # This file
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Terraform | ≥ 1.6.0 | [terraform.io/downloads](https://developer.hashicorp.com/terraform/downloads) |
| AWS CLI | ≥ 2.x | [docs.aws.amazon.com/cli](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) |
| Python | ≥ 3.10 | [python.org](https://www.python.org/downloads/) |
| Stratus Red Team | Latest | `brew install datadog/stratus-red-team/stratus-red-team` |

**AWS Permissions Required** (for the deploying IAM principal):

```
guardduty:CreateDetector
guardduty:UpdateDetector
iam:CreateRole
iam:PutRolePolicy
iam:CreatePolicy
lambda:CreateFunction
lambda:AddPermission
events:PutRule
events:PutTargets
logs:CreateLogGroup
logs:PutRetentionPolicy
```

---

## Deployment Instructions

### Step 1 — Configure AWS credentials

```bash
aws configure
# Or use a named profile:
export AWS_PROFILE=your-sandbox-profile
```

Verify you are authenticated to the correct account:
```bash
aws sts get-caller-identity
```

### Step 2 — Clone and configure

```bash
git clone https://github.com/yourname/soar-lab.git
cd soar-lab

# Create your personal variable file (never commit this)
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:

```hcl
aws_region        = "us-east-1"
environment       = "dev"
owner             = "your-name"
```

### Step 3 — Initialize Terraform

```bash
terraform init
```

Expected output:
```
Terraform has been successfully initialized!
```

### Step 4 — Review the plan

```bash
terraform plan
```

Review the list of resources to be created (no changes are applied yet). Confirm you see:
- `aws_guardduty_detector.main`
- `aws_iam_role.lambda_exec`
- `aws_iam_role_policy.lambda_inline`
- `aws_lambda_function.remediate`
- `aws_cloudwatch_event_rule.guardduty_finding`
- `aws_cloudwatch_event_target.lambda_target`
- `aws_lambda_permission.allow_eventbridge`
- `aws_cloudwatch_log_group.lambda_logs`

### Step 5 — Apply

```bash
terraform apply
```

Type `yes` when prompted. Typical apply time: **~60 seconds**.

Verify the key outputs:

```bash
terraform output guardduty_detector_id
terraform output lambda_function_arn
terraform output eventbridge_rule_arn
```

---

## Testing with Stratus Red Team

[Stratus Red Team](https://stratus-red-team.cloud/) is an open-source adversary simulation tool for cloud environments developed by Datadog Security Labs.

### Option A — Stratus Red Team (Recommended)

```bash
# List available AWS IAM attack techniques
stratus list --platform aws --mitre-attack-tactic credential-access

# Warm up the attack scenario (creates prerequisite resources)
stratus warmup aws.credential-access.access-key-leak

# Detonate the attack — simulates leaking an IAM Access Key to a public endpoint
stratus detonate aws.credential-access.access-key-leak
```

> **Warning**: `stratus detonate` creates a *real* IAM user and access key in your account. GuardDuty will detect the leak within 15 minutes (per the configured finding frequency). The Lambda will then automatically deactivate the key and freeze the user.

After detonation, verify remediation:

```bash
# Check that the Lambda was invoked
aws logs tail /aws/lambda/soar-lab-remediate --follow --format short

# Confirm the access key was deactivated
aws iam list-access-keys --user-name <stratus-created-username>

# Confirm the DenyAll policy was attached
aws iam list-user-policies --user-name <stratus-created-username>

# Clean up Stratus resources
stratus cleanup aws.credential-access.access-key-leak
```

### Option B — Synthetic GuardDuty Finding via AWS Console

For a faster test (bypasses the ~15 min GuardDuty aggregation window):

1. Open the [GuardDuty Console](https://console.aws.amazon.com/guardduty)
2. Navigate to **Settings → Sample findings → Generate sample findings**
3. GuardDuty will create synthetic findings including `UnauthorizedAccess:IAMUser/AccessKeyLeak`
4. EventBridge will pick these up and invoke the Lambda within seconds

> **Note**: Sample findings use synthetic usernames and access key IDs. The Lambda will attempt IAM API calls that return `NoSuchEntity` errors for these fake identifiers — this is expected and handled gracefully.

### Option C — Direct Lambda Test Payload

Invoke the Lambda directly with a crafted test event:

```bash
cat > /tmp/test-event.json << 'EOF'
{
  "version": "0",
  "id": "a6a4b827-e4e9-4d6b-a4b3-1234567890ab",
  "source": "aws.guardduty",
  "account": "123456789012",
  "region": "us-east-1",
  "detail-type": "GuardDuty Finding",
  "detail": {
    "schemaVersion": "2.0",
    "accountId": "123456789012",
    "region": "us-east-1",
    "id": "test-finding-id-001",
    "type": "UnauthorizedAccess:IAMUser/AccessKeyLeak",
    "severity": 8.0,
    "createdAt": "2025-01-01T12:00:00Z",
    "updatedAt": "2025-01-01T12:00:00Z",
    "description": "AWS Access Key credentials for IAM user test-compromised-user were found on the internet.",
    "resource": {
      "resourceType": "AccessKey",
      "accessKeyDetails": {
        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "principalId": "AIDAEXAMPLEUSER",
        "userType": "IAMUser",
        "userName": "soar-test-user"
      }
    }
  }
}
EOF

aws lambda invoke \
  --function-name soar-lab-remediate \
  --payload file:///tmp/test-event.json \
  --cli-binary-format raw-in-base64-out \
  /tmp/lambda-response.json

cat /tmp/lambda-response.json | python3 -m json.tool
```

> **Note**: Replace `soar-test-user` with a *real* IAM username in your account (e.g., a dedicated test user). The Lambda will make real IAM API calls.

### Setting Up a Test IAM User

```bash
# Create a dedicated test user
aws iam create-user --user-name soar-test-user

# Create an access key for the test user
aws iam create-access-key --user-name soar-test-user

# After testing, clean up
aws iam delete-user-policy --user-name soar-test-user --policy-name SOARExplicitDenyAll
aws iam delete-access-key --user-name soar-test-user --access-key-id <key-id>
aws iam delete-user --user-name soar-test-user
```

---

## Incident Response Playbook

### Automated Actions (Lambda — completes in < 5 seconds)

| # | Action | AWS API Call | Outcome |
|---|--------|-------------|---------|
| 1 | Deactivate compromised key | `iam:UpdateAccessKey(Status=Inactive)` | Key can no longer authenticate API calls |
| 2 | Freeze IAM user | `iam:PutUserPolicy(ExplicitDenyAll)` | ALL API calls by this user are blocked |
| 3 | Log incident | `logs:PutLogEvents` | Structured JSON in CloudWatch for audit |

### Human Analyst Actions (Post-Automation)

**Immediate (0–30 minutes):**
- [ ] Review the CloudWatch log for the remediation summary
- [ ] Open GuardDuty finding in AWS Console and read the full finding details
- [ ] Pull CloudTrail logs for the affected IAM user for the 24 hours preceding the finding

```bash
# Pull recent CloudTrail events for the compromised user
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time $(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ') \
  --query 'Events[*].{Time:EventTime,Event:EventName,Source:EventSource}' \
  --output table
```

**Investigation (30 min – 4 hours):**
- [ ] Identify all API calls made with the compromised key
- [ ] Check S3 access logs for any `GetObject` calls (potential data exfiltration)
- [ ] Check Secrets Manager and SSM Parameter Store access
- [ ] Identify the source IPs and geolocations of API calls
- [ ] Determine how the key was leaked (public GitHub repo, CI/CD logs, etc.)
- [ ] Check for any new IAM users, roles, or policies created by the attacker

**Remediation (4–24 hours):**
- [ ] Permanently delete (not just deactivate) the compromised access key
- [ ] Remove the `SOARExplicitDenyAll` inline policy after root cause is confirmed
- [ ] Rotate all other credentials for the affected user
- [ ] If data exfiltration is confirmed, trigger your Data Breach Response Plan
- [ ] Implement SCPs to prevent future key exposure (e.g., deny key creation without MFA)

---

## Security Controls Implemented

| Control | Implementation | CIS Benchmark |
|---------|---------------|---------------|
| Threat Detection | GuardDuty with S3, K8s, and Malware Protection | CIS AWS 3.x |
| Automated Response | Lambda + EventBridge (MTTR < 60 seconds) | NIST CSF RS.RP |
| Least Privilege | IAM inline policy with 4 specific actions | CIS IAM 1.x |
| Log Retention | 30-day CloudWatch Logs retention | CIS AWS 3.10 |
| Idempotency | All remediation actions are re-runnable safely | — |
| Non-repudiation | Structured JSON logs with finding ID + masked key | SOC 2 CC7.2 |

---

## Cost Estimate

> Estimated for a **dev/portfolio** account with minimal activity.

| Service | Free Tier | Typical Monthly Cost |
|---------|-----------|---------------------|
| GuardDuty | 30-day free trial | ~$2–$10/month (based on CloudTrail volume) |
| Lambda | 1M requests free | < $0.01 (minimal invocations) |
| EventBridge | 1M events free | < $0.01 |
| CloudWatch Logs | 5GB free | < $0.50 (30-day retention) |
| **Total** | | **< $15/month** |

> **Tip**: Disable the GuardDuty detector (`enable = false`) when not actively testing to avoid ongoing charges.

---

## Cleanup

Destroy all AWS resources created by this lab:

```bash
terraform destroy
```

Type `yes` to confirm. This will:
- Disable the GuardDuty detector
- Delete the Lambda function and its IAM role
- Delete the EventBridge rule and target
- Delete the CloudWatch Log Group and all logs

> **Note**: `terraform destroy` does NOT delete the test IAM user created manually or via Stratus Red Team. Clean those up separately using the commands in the Testing section.

---

## 📚 References & Further Reading

- [AWS GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [GuardDuty EventBridge Integration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Stratus Red Team - AWS Attacks](https://stratus-red-team.cloud/attack-techniques/AWS/)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)

---

## 👤 Author

Built as a security engineering portfolio project demonstrating:
- Cloud-native SOAR architecture on AWS
- Infrastructure-as-Code with Terraform
- Python Lambda development with production-grade error handling
- MITRE ATT&CK-aligned detection and response engineering
- Adversary simulation with Stratus Red Team

---

*MIT License — free to use and adapt for educational and portfolio purposes.*
