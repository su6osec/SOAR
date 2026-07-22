# =============================================================================
# outputs.tf — SOAR Lab: Cloud Threat Detection & Incident Response
# =============================================================================
# Exposes key resource identifiers after `terraform apply`. These values can
# be used for post-deploy verification, integration tests, or piped into a
# CI/CD pipeline.
# =============================================================================

# GuardDuty outputs — uncomment after enabling GuardDuty in the console
# and importing the detector into Terraform state.
#
# output "guardduty_detector_id" {
#   description = "The ID of the enabled GuardDuty detector."
#   value       = aws_guardduty_detector.main.id
# }
#
# output "guardduty_detector_arn" {
#   description = "Full ARN of the GuardDuty detector."
#   value       = aws_guardduty_detector.main.arn
# }

output "lambda_function_name" {
  description = "Name of the remediation Lambda function."
  value       = aws_lambda_function.remediate.function_name
}

output "lambda_function_arn" {
  description = "ARN of the remediation Lambda function."
  value       = aws_lambda_function.remediate.arn
}

output "lambda_iam_role_arn" {
  description = "ARN of the Lambda execution IAM role (least-privilege)."
  value       = aws_iam_role.lambda_exec.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule that captures GuardDuty findings."
  value       = aws_cloudwatch_event_rule.guardduty_finding.name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule."
  value       = aws_cloudwatch_event_rule.guardduty_finding.arn
}

output "lambda_log_group_name" {
  description = "CloudWatch Log Group name for Lambda structured logs."
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "deployment_region" {
  description = "AWS region where the SOAR stack was deployed."
  value       = var.aws_region
}
