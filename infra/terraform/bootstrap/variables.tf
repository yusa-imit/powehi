variable "aws_region" {
  description = "AWS region for the state bucket and all environments (ADR-0007: Seoul)."
  type        = string
  default     = "ap-northeast-2"
}

variable "owner_email" {
  description = "Owner e-mail that receives the AWS Budgets alerts."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.owner_email))
    error_message = "owner_email must be a valid e-mail address."
  }
}

variable "github_repository" {
  description = "GitHub repository (owner/name) whose workflows may assume the roles."
  type        = string
  default     = "yusa-imit/powehi"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "github_repository must be owner/name with no wildcards."
  }
}

variable "github_repository_id" {
  description = <<-EOT
    Numeric GitHub repository ID (required). The trust policies also require the
    repository_id claim, which defeats owner/name re-registration after a rename or delete.
    Get it with: gh api repos/<owner>/<name> --jq .id
  EOT
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.github_repository_id))
    error_message = "github_repository_id must be numeric (gh api repos/<owner>/<name> --jq .id)."
  }
}

variable "allowed_account_ids" {
  description = "AWS account IDs the provider may talk to; stops a wrong-profile apply."
  type        = list(string)

  validation {
    condition     = length(var.allowed_account_ids) > 0 && alltrue([for a in var.allowed_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "allowed_account_ids must be a non-empty list of 12-digit AWS account IDs."
  }
}

variable "github_environments" {
  description = "Map of powehi env name to the GitHub Environment name allowed to deploy it."
  type        = map(string)
  default = {
    staging = "staging"
    prod    = "production"
  }

  validation {
    condition = alltrue([
      for k, v in var.github_environments : can(regex("^[a-z0-9]+$", k)) && can(regex("^[A-Za-z0-9._-]+$", v))
    ])
    error_message = "Env keys must match ^[a-z0-9]+$ (no hyphen: they are embedded in hyphen-delimited IAM names); GitHub Environment names must not contain wildcards, colons or slashes."
  }
}

variable "budget_limit_usd" {
  description = "Monthly AWS Budgets limit in USD (ADR-0007: 150)."
  type        = number
  default     = 150
}

variable "state_noncurrent_retention_days" {
  description = "Days to keep non-current state object versions."
  type        = number
  default     = 90
}
