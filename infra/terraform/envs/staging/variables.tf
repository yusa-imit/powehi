variable "environment" {
  description = "Environment name; prefix of every resource (powehi-<env>-*)."
  type        = string
  default     = "staging"

  validation {
    condition     = var.environment == "staging"
    error_message = "This root module is the staging environment."
  }
}

variable "aws_region" {
  description = "AWS region (ADR-0007: ap-northeast-2). A second region is a new env."
  type        = string
  default     = "ap-northeast-2"
}

variable "domain" {
  description = "Apex domain served through Cloudflare. Never hard-coded; set in <env>.tfvars or TF_VAR_domain."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9-]+\\.)+[a-z]{2,}$", var.domain))
    error_message = "domain must be a bare DNS name such as example.com."
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
