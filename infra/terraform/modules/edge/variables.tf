variable "name_prefix" {
  description = "Resource name prefix, powehi-<env>."
  type        = string

  validation {
    condition     = can(regex("^powehi-(staging|prod)$", var.name_prefix))
    error_message = "name_prefix must be powehi-staging or powehi-prod."
  }
}

variable "domain" {
  description = "Apex domain of the Cloudflare zone. Never hard-coded; comes from the env's domain variable."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9-]+\\.)+[a-z]{2,}$", var.domain))
    error_message = "domain must be a bare DNS name such as example.com."
  }
}

variable "api_hostname" {
  description = "Public API hostname of this env (a name under var.domain)."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9-]+\\.)+[a-z]{2,}$", var.api_hostname))
    error_message = "api_hostname must be a DNS name."
  }
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID (not a secret; tunnel, R2 and the zone lookup are account-scoped)."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be a 32-character hex string."
  }
}

variable "origin_port" {
  description = "Port the powehi-server HTTP listener binds (crates/infra powehi-config default `port` = 8080). cloudflared runs as a sidecar in the same task, so the origin is localhost."
  type        = number
  default     = 8080

  validation {
    condition     = var.origin_port > 0 && var.origin_port < 65536
    error_message = "origin_port must be a valid TCP port."
  }
}

variable "managed_ruleset_id" {
  description = "Managed ruleset to deploy on the zone. Default is the Cloudflare Free Managed Ruleset; on Pro use the Cloudflare Managed Ruleset (efb7b8c949ac4650a09736fc376e9aee)."
  type        = string
  default     = "77454fe2d30c4220b5701f6fdfb893ba"
}

variable "auth_paths" {
  description = "Exact request paths of the unauthenticated OPAQUE register/login endpoints (crates/adapters/inbound/powehi-rest-api routes)."
  type        = list(string)
  default = [
    "/v1/auth/register/init",
    "/v1/auth/register/finish",
    "/v1/auth/login/init",
    "/v1/auth/login/finish",
  ]
}

variable "auth_rate_limit_requests" {
  description = "Requests allowed per client IP per 10 seconds on the auth paths."
  type        = number
  default     = 20

  validation {
    condition     = var.auth_rate_limit_requests >= 1 && var.auth_rate_limit_requests <= 1000
    error_message = "auth_rate_limit_requests must be 1..1000."
  }
}

variable "manage_zone" {
  description = "True in exactly one stack (staging): owns the zone-wide settings and WAF rulesets that staging and prod share. Prod passes false."
  type        = bool
}

variable "create_r2_token" {
  description = "Create the bucket-scoped R2 token here (needs the API Tokens Edit permission, owner-run apply only). False: the owner mints it out of band."
  type        = bool
  default     = false
}

variable "r2_token_allowed_cidrs" {
  description = "Optional client CIDRs the R2 token is restricted to (task public IPs; tasks have no NAT). Empty means unrestricted."
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
