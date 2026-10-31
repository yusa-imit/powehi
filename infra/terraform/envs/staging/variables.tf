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

variable "cloudflare_account_id" {
  description = "Cloudflare account ID (not secret). The API token comes from CLOUDFLARE_API_TOKEN, never a variable."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be a 32-character hex string."
  }
}

variable "create_r2_token" {
  description = "Create the bucket-scoped R2 token in this stack (needs API Tokens Edit; owner-run only). False: mint it out of band."
  type        = bool
  default     = false
}

variable "r2_token_allowed_cidrs" {
  description = "Optional IPv4 CIDRs the R2 token is restricted to (task public IPs; no NAT). Only used when create_r2_token."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.r2_token_allowed_cidrs : can(cidrnetmask(c))])
    error_message = "r2_token_allowed_cidrs entries must be IPv4 CIDRs such as 198.51.100.7/32."
  }
}

variable "r2_token_expires_on" {
  description = "Optional RFC 3339 expiry of the R2 token; null means none."
  type        = string
  default     = null

  validation {
    condition     = var.r2_token_expires_on == null || can(timeadd(var.r2_token_expires_on, "0s"))
    error_message = "r2_token_expires_on must be an RFC 3339 timestamp or null."
  }
}
