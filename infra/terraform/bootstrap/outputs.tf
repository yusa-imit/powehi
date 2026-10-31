output "state_bucket" {
  description = "Value for `bucket` in envs/*/backend.hcl."
  value       = aws_s3_bucket.state.id
}

output "state_kms_key_arn" {
  description = "Value for `kms_key_id` in envs/*/backend.hcl."
  value       = aws_kms_key.state.arn
}

output "aws_region" {
  description = "Value for `region` in envs/*/backend.hcl and the AWS_REGION secret."
  value       = var.aws_region
}

output "deploy_role_arns" {
  description = "Per-env deploy role ARN, for the AWS_ROLE_ARN secret of each GitHub Environment."
  value       = { for env, r in aws_iam_role.deploy : env => r.arn }
}

output "plan_role_arn" {
  description = "Read-only plan role ARN, for the repository-level AWS_PLAN_ROLE_ARN secret."
  value       = aws_iam_role.plan.arn
}
