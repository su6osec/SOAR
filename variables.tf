# =============================================================================
# variables.tf — SOAR Lab: Cloud Threat Detection & Incident Response
# =============================================================================
# All configurable inputs for the SOAR infrastructure. Override via a
# terraform.tfvars file (see terraform.tfvars.example). Never commit real
# secrets to source control.
# =============================================================================

# ---------------------------------------------------------------------------
# Provider / Region
# ---------------------------------------------------------------------------

variable "aws_region" {
  type        = string
  description = "AWS region in which all resources are deployed."
  default     = "us-east-1"
}

# ---------------------------------------------------------------------------
# Project metadata (used for resource naming & tagging)
# ---------------------------------------------------------------------------

variable "project_name" {
  type        = string
  description = "Short identifier prefix applied to all resource names."
  default     = "soar-lab"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.project_name))
    error_message = "project_name must be 1-20 lowercase alphanumeric characters or hyphens."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment tag (e.g. dev, staging, prod)."
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "owner" {
  type        = string
  description = "Owner tag — your name or team name for cost-allocation tagging."
  default     = "security-engineering"
}

# ---------------------------------------------------------------------------
# GuardDuty
# ---------------------------------------------------------------------------

variable "guardduty_finding_frequency" {
  type        = string
  description = <<-EOT
    How often GuardDuty publishes aggregated findings to EventBridge.
    FIFTEEN_MINUTES is best for demos; SIX_HOURS reduces noise in production.
  EOT
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_frequency)
    error_message = "Must be one of: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

variable "guardduty_s3_protection_enabled" {
  type        = bool
  description = "Enable GuardDuty S3 Protection (monitors S3 data-plane API calls)."
  default     = true
}

# ---------------------------------------------------------------------------
# EventBridge / Incident trigger
# ---------------------------------------------------------------------------

variable "target_finding_type" {
  type        = string
  description = <<-EOT
    The exact GuardDuty finding type that triggers the remediation Lambda.
    Defaults to the IAM Access Key compromise finding.
  EOT
  default     = "UnauthorizedAccess:IAMUser/AccessKeyLeak"
}

# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

variable "lambda_timeout" {
  type        = number
  description = "Maximum execution time (seconds) for the remediation Lambda."
  default     = 60

  validation {
    condition     = var.lambda_timeout >= 10 && var.lambda_timeout <= 300
    error_message = "lambda_timeout must be between 10 and 300 seconds."
  }
}

variable "lambda_memory" {
  type        = number
  description = "Memory (MB) allocated to the remediation Lambda."
  default     = 256

  validation {
    condition     = contains([128, 256, 512, 1024], var.lambda_memory)
    error_message = "lambda_memory must be one of: 128, 256, 512, 1024."
  }
}

variable "lambda_runtime" {
  type        = string
  description = "Lambda runtime identifier. Must be a Python 3.x runtime."
  default     = "python3.12"
}

variable "lambda_log_retention_days" {
  type        = number
  description = "Number of days to retain Lambda CloudWatch Logs. Set to 0 to never expire."
  default     = 30
}


