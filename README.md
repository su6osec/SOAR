# Cloud Threat Detection and Incident Response (SOAR Lab)

[![Terraform](https://img.shields.io/badge/Terraform-≥1.6-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-GuardDuty%20%7C%20Lambda%20%7C%20EventBridge-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1078%20%7C%20T1530-red)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

<div style="text-align: justify;">
This project is an enterprise-grade, serverless Security Orchestration, Automation, and Response (SOAR) pipeline deployed entirely on AWS. It demonstrates a complete, real-world incident response workflow: from the initial detection of compromised cloud credentials to the instantaneous containment of the threat. Built using Infrastructure as Code (Terraform) and serverless compute (AWS Lambda), this architecture autonomously identifies compromised IAM credentials via GuardDuty, routes the alert via EventBridge, and isolates the threat by freezing the compromised principal in under five seconds—achieving zero-trust containment without human intervention.
</div>

---

### System Architecture

![SOAR Architecture Diagram](assets/architecture_wide.png)

<br />

## Data Flow and Execution Summary

| Step | Action | AWS Technology |
|:----:|:-------|:---------------|
| **1** | A threat is detected, such as leaked IAM credentials being used from an unauthorized IP address. | **AWS GuardDuty** |
| **2** | GuardDuty generates a security finding and publishes it to the default event bus. | **GuardDuty → EventBridge** |
| **3** | A custom rule matches the specific payload: `detail.type = UnauthorizedAccess:IAMUser/AccessKeyLeak`. | **EventBridge Rule** |
| **4** | The rule triggers a synchronous invocation of the remediation script, passing the finding payload. | **EventBridge → Lambda** |
| **5** | The Python script identifies the user, calls the IAM API, and changes the Access Key status to `Inactive`. | **Lambda → IAM API** |
| **6** | The script attaches a custom `ExplicitDenyAll` inline policy to the IAM user to block all further access. | **Lambda → IAM API** |
| **7** | A structured JSON audit log containing the masked key and action status is recorded for compliance. | **Lambda → CloudWatch Logs** |

---

## MITRE ATT&CK Cloud Mapping

<div style="text-align: justify;">
This architecture is engineered to detect and mitigate specific techniques documented in the MITRE ATT&CK framework for Cloud infrastructure.
</div>
<br />

<details>
<summary><b>T1078.004 — Valid Accounts: Cloud Accounts</b></summary>

- **Tactic**: Initial Access, Persistence, Privilege Escalation, Defense Evasion
- **Description**: Adversaries obtain and abuse credentials of cloud accounts to gain initial access or maintain persistence. Compromised IAM Access Keys allow attackers to authenticate as a legitimate user, bypassing network controls.
- **Detection**: GuardDuty `UnauthorizedAccess:IAMUser/AccessKeyLeak` identifies access keys found on public code repositories or used from anomalous geolocations.
- **Automated Response**: The Access Key is deactivated and an `ExplicitDenyAll` policy is attached within seconds of detection, neutralizing the account.
</details>

<details>
<summary><b>T1530 — Data from Cloud Storage Object</b></summary>

- **Tactic**: Collection
- **Description**: Adversaries access data from cloud storage (S3) using compromised credentials. With a leaked IAM key, an attacker can enumerate and download S3 buckets before defenders traditionally respond.
- **Detection**: GuardDuty S3 Protection monitors `s3:GetObject` and `s3:ListBuckets` calls from unusual principals or IPs.
- **Automated Response**: Freezing the IAM user with `ExplicitDenyAll` immediately blocks all S3 API calls, effectively halting data exfiltration mid-stream.
</details>

<details>
<summary><b>T1580 — Cloud Infrastructure Discovery</b></summary>

- **Tactic**: Discovery
- **Description**: Adversaries attempt to discover cloud infrastructure (EC2, Lambda, RDS) after gaining initial access with compromised credentials.
- **Detection**: GuardDuty detects reconnaissance API calls (e.g., `ec2:DescribeInstances`, `iam:ListRoles`) originating from known malicious IPs.
- **Automated Response**: The automated user freeze drops all discovery API permissions simultaneously.
</details>

---

## Project Structure

```text
SOAR/
├── main.tf                    # Core Terraform module defining AWS resources
├── variables.tf               # Parameterized input variables for deployment
├── outputs.tf                 # Essential resource ARNs exposed post-deployment
├── terraform.tfvars.example   # Safe-to-commit template for local variable definitions
├── src/
│   └── remediate.py           # Core Python/Boto3 Lambda remediation logic
└── README.md                  # Project documentation
```

---

## Deployment Instructions

<details>
<summary><b>View Deployment Steps</b></summary>

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform | ≥ 1.6.0 | Infrastructure provisioning |
| AWS CLI | ≥ 2.x | Cloud authentication and testing |
| Python | ≥ 3.10 | Lambda runtime environment |
| Stratus Red Team | Latest | Adversary simulation and testing |

### Step 1 — Configure AWS Authentication

```bash
aws configure
# Verify active authentication context:
aws sts get-caller-identity
```

### Step 2 — Clone and Configure Repository

```bash
git clone https://github.com/yourname/soar-lab.git
cd soar-lab

# Create your personal variable file (this file is ignored by git)
cp terraform.tfvars.example terraform.tfvars
```

### Step 3 — Initialize and Apply Infrastructure

```bash
terraform init
terraform apply
```

Review the plan and type `yes` when prompted. Typical deployment time is under 60 seconds.
</details>

---

## Testing and Simulation

<div style="text-align: justify;">
To validate the pipeline, we utilize Stratus Red Team, an open-source adversary simulation tool developed by Datadog Security Labs. This tool safely detonates cloud attack techniques to trigger GuardDuty.
</div>
<br />

<details>
<summary><b>View Testing Procedures</b></summary>

### Option A — Live Simulation (Recommended)

```bash
# Warm up the attack scenario to create necessary prerequisite resources
stratus warmup aws.credential-access.access-key-leak

# Detonate the attack (simulates leaking an IAM Access Key to a public endpoint)
stratus detonate aws.credential-access.access-key-leak
```

**Note**: `stratus detonate` generates a functional IAM user and access key within your account. GuardDuty will detect this generated leak within its aggregation window. The Lambda function will subsequently capture the event, deactivate the key, and lock out the user.

After detonation, verify the automated remediation:

```bash
# Review the structured execution logs
aws logs tail /aws/lambda/soar-lab-remediate --follow --format short

# Verify the compromised key has been set to Inactive
aws iam list-access-keys --user-name <stratus-created-username>
```

### Option B — Direct Synthetic Payload Test

To bypass the GuardDuty detection window and test the Lambda execution directly, invoke the function with a synthetic JSON payload representing a GuardDuty finding:

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

## Incident Response Playbook

<details>
<summary><b>View Analyst Workflow</b></summary>

### Automated Phase (Executes in < 5 seconds)

| Action | API Call Executed | Technical Outcome |
|--------|-------------------|-------------------|
| Deactivate Key | `iam:UpdateAccessKey(Status=Inactive)` | The compromised key is immediately invalidated for all subsequent API requests. |
| Freeze Principal | `iam:PutUserPolicy(ExplicitDenyAll)` | An inline policy explicitly denying all actions (`"Action": "*"`) is attached to the user. |
| Audit Logging | `logs:PutLogEvents` | A structured JSON record detailing the remediation status is securely stored in CloudWatch. |

### Human Analyst Phase (Post-Automation)

**Investigation (0 – 4 hours):**
- Review CloudWatch logs to confirm the automated remediation executed successfully.
- Aggregate CloudTrail logs to identify any API calls made using the compromised key prior to deactivation.
- Analyze S3 access logs for `GetObject` requests to assess potential data exfiltration.
- Investigate the root cause of the credential exposure (e.g., public GitHub repository commit, exposed CI/CD pipeline variables).

**Recovery (4 – 24 hours):**
- Permanently delete the compromised access key from the IAM console.
- Once the vulnerability is patched, remove the `SOARExplicitDenyAll` inline policy from the affected user.
- Enforce stricter Service Control Policies (SCPs) to mitigate future exposure risks, such as requiring MFA for all IAM actions.
</details>

---

## Security Controls Implemented

| Domain | Implementation Strategy | Framework Alignment |
|--------|-------------------------|---------------------|
| **Threat Detection** | Continuous monitoring via GuardDuty, spanning CloudTrail, VPC Flow Logs, and S3 Data Events. | CIS AWS Foundations |
| **Automated Response** | EventBridge routing to Lambda for sub-minute Mean Time To Respond (MTTR). | NIST CSF (RS.RP) |
| **Least Privilege** | Lambda execution role is strictly scoped to 4 highly specific IAM and CloudWatch API actions. | CIS IAM 1.x |
| **Log Integrity** | CloudWatch Logs configured with a 30-day retention policy for forensic availability. | CIS AWS 3.10 |
| **Non-repudiation** | Emitted logs contain the finding ID alongside masked identifiers, ensuring robust audit trails. | SOC 2 (CC7.2) |

---

<br />

## Infrastructure Cleanup

```bash
# Teardown all AWS resources provisioned by Terraform
terraform destroy
```

<br/>
<br/>

*Developed as a Security Engineering Portfolio Demonstration*  
**Core Technologies:** Infrastructure-as-Code (Terraform), Python, AWS Serverless Ecosystem

