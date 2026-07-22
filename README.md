<div align="center">

# ☁️ Cloud Threat Detection & Incident Response (SOAR Lab)

[![Terraform](https://img.shields.io/badge/Terraform-≥1.6-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-GuardDuty%20%7C%20Lambda%20%7C%20EventBridge-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1078%20%7C%20T1530-red)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Portfolio Project** — An enterprise-grade, serverless Security Orchestration, Automation, and Response (SOAR) pipeline built on AWS. This architecture autonomously detects compromised IAM credentials via GuardDuty, isolates threats by instantly freezing compromised principals via Lambda, and generates structured security audit logs—achieving zero-trust containment within seconds.

---

### System Architecture

![SOAR Architecture Diagram](assets/architecture_wide.png)

</div>

<br />

## 🔍 Data Flow Summary

| Step | Event | Technology |
|:----:|:------|:-----------|
| **1** | Threat activity detected (API call anomaly, credential exposure) | **AWS GuardDuty** |
| **2** | Finding published to EventBridge default bus | **GuardDuty → EventBridge** |
| **3** | Event pattern matched: `detail.type = UnauthorizedAccess:IAMUser/AccessKeyLeak` | **EventBridge Rule** |
| **4** | Lambda invoked synchronously with finding JSON payload | **EventBridge → Lambda** |
| **5** | Access Key status → `Inactive` | **Lambda → IAM API** |
| **6** | `ExplicitDenyAll` inline policy attached to IAM user | **Lambda → IAM API** |
| **7** | Structured JSON log emitted | **Lambda → CloudWatch Logs** |

---

## 🎯 MITRE ATT&CK Cloud Mapping

This lab detects and responds to the following ATT&CK techniques:

<details>
<summary><b>T1078.004 — Valid Accounts: Cloud Accounts</b></summary>

- **Tactic**: Initial Access, Persistence, Privilege Escalation, Defense Evasion
- **Description**: Adversaries may obtain and abuse credentials of cloud accounts to gain initial access or maintain persistence. Compromised IAM Access Keys allow attackers to authenticate as a legitimate user, bypassing MFA and network controls.
- **Detection**: GuardDuty `UnauthorizedAccess:IAMUser/AccessKeyLeak` — identifies access keys found on public code repositories or used from anomalous geolocations.
- **Automated Response**: Key deactivated + `ExplicitDenyAll` policy attached within seconds of detection.
</details>

<details>
<summary><b>T1530 — Data from Cloud Storage Object</b></summary>

- **Tactic**: Collection
- **Description**: Adversaries may access data from cloud storage (S3) using compromised credentials. With a leaked IAM key, an attacker can enumerate and download S3 buckets before defenders respond.
- **Detection**: GuardDuty S3 Protection monitors `s3:GetObject`, `s3:ListBuckets` calls from unusual principals/IPs.
- **Automated Response**: Freezing the IAM user with `ExplicitDenyAll` immediately blocks all S3 API calls, stopping exfiltration mid-stream.
</details>

<details>
<summary><b>T1580 — Cloud Infrastructure Discovery</b></summary>

- **Tactic**: Discovery
- **Description**: Adversaries may attempt to discover cloud infrastructure (EC2, Lambda, RDS) after gaining initial access with compromised credentials.
- **Detection**: GuardDuty detects reconnaissance API calls (`ec2:DescribeInstances`, `iam:ListRoles`) from known malicious IPs.
- **Automated Response**: User freeze blocks all discovery API calls simultaneously.
</details>

---

## 📁 Project Structure

```text
SOAR/
├── main.tf                    # Core Terraform: all AWS resources
├── variables.tf               # Parameterized input variables
├── outputs.tf                 # Key resource ARNs exposed post-deploy
├── terraform.tfvars.example   # Safe-to-commit variable template
├── src/
│   └── remediate.py           # Lambda handler (boto3 remediation logic)
└── README.md                  # This documentation
```

---

## 🚀 Deployment Instructions

<details>
<summary><b>View Deployment Steps</b></summary>

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Terraform | ≥ 1.6.0 | [terraform.io/downloads](https://developer.hashicorp.com/terraform/downloads) |
| AWS CLI | ≥ 2.x | [docs.aws.amazon.com/cli](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) |
| Python | ≥ 3.10 | [python.org](https://www.python.org/downloads/) |
| Stratus Red Team | Latest | `brew install datadog/stratus-red-team/stratus-red-team` |

### Step 1 — Configure AWS credentials

```bash
aws configure
# Verify authentication:
aws sts get-caller-identity
```

### Step 2 — Clone and configure

```bash
git clone https://github.com/yourname/soar-lab.git
cd soar-lab

# Create your personal variable file (never commit this)
cp terraform.tfvars.example terraform.tfvars
```

### Step 3 — Initialize & Apply

```bash
terraform init
terraform apply
```

Type `yes` when prompted. Typical apply time is **~60 seconds**.
</details>

---

## 🧪 Testing with Stratus Red Team

[Stratus Red Team](https://stratus-red-team.cloud/) is an open-source adversary simulation tool for cloud environments developed by Datadog Security Labs.

<details>
<summary><b>View Testing Options</b></summary>

### Option A — Stratus Red Team (Recommended)

```bash
# Warm up the attack scenario (creates prerequisite resources)
stratus warmup aws.credential-access.access-key-leak

# Detonate the attack (simulates leaking an IAM Access Key to a public endpoint)
stratus detonate aws.credential-access.access-key-leak
```

> **Warning**: `stratus detonate` creates a *real* IAM user and access key in your account. GuardDuty will detect the leak within 15 minutes. The Lambda will automatically deactivate the key and freeze the user.

After detonation, verify remediation:

```bash
aws logs tail /aws/lambda/soar-lab-remediate --follow --format short
aws iam list-access-keys --user-name <stratus-created-username>
```

### Option B — Direct Lambda Test Payload

Invoke the Lambda directly to see the execution in seconds:

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
```
</details>

---

## 🔒 Incident Response Playbook

<details>
<summary><b>View Analyst Actions</b></summary>

### Automated Actions (Lambda — completes in < 5 seconds)

| # | Action | AWS API Call | Outcome |
|---|--------|-------------|---------|
| 1 | Deactivate compromised key | `iam:UpdateAccessKey(Status=Inactive)` | Key can no longer authenticate API calls |
| 2 | Freeze IAM user | `iam:PutUserPolicy(ExplicitDenyAll)` | ALL API calls by this user are blocked |
| 3 | Log incident | `logs:PutLogEvents` | Structured JSON in CloudWatch for audit |

### Human Analyst Actions (Post-Automation)

**Investigation (30 min – 4 hours):**
- Identify all API calls made with the compromised key.
- Check S3 access logs for any `GetObject` calls (potential data exfiltration).
- Determine how the key was leaked (public GitHub repo, CI/CD logs, etc.).

**Remediation (4–24 hours):**
- Permanently delete (not just deactivate) the compromised access key.
- Remove the `SOARExplicitDenyAll` inline policy after root cause is confirmed.
- Implement SCPs to prevent future key exposure (e.g., deny key creation without MFA).
</details>

---

## 🛡️ Security Controls Implemented

| Control | Implementation | CIS Benchmark |
|---------|---------------|---------------|
| **Threat Detection** | GuardDuty with S3, K8s, and Malware Protection | CIS AWS 3.x |
| **Automated Response** | Lambda + EventBridge (MTTR < 60 seconds) | NIST CSF RS.RP |
| **Least Privilege** | IAM inline policy with 4 specific actions | CIS IAM 1.x |
| **Log Retention** | 30-day CloudWatch Logs retention | CIS AWS 3.10 |
| **Non-repudiation** | Structured JSON logs with finding ID + masked key | SOC 2 CC7.2 |

---

<div align="center">

## 🧹 Cleanup & Cost

Estimated for a **dev/portfolio** account: **< $15/month**

```bash
# Destroy all AWS resources created by this lab
terraform destroy
```

<br/>

**Built as a Security Engineering Portfolio Project**  
*Infrastructure-as-Code (Terraform) • Python • AWS Automation*

</div>
