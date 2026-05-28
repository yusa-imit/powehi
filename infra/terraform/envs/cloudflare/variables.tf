variable "cloudflare_api_token" {
  description = "Cloudflare API token with Zone:Edit permissions. Supply via TF_VAR_cloudflare_api_token — never hardcode."
  type        = string
  sensitive   = true
  default     = ""
}

variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID for powehi.app. Supply via TF_VAR_cloudflare_zone_id or terraform.tfvars."
  type        = string
  default     = ""
}

variable "api_origin_ip" {
  description = "Public IPv4 of the origin server that api.powehi.app points to."
  type        = string
  default     = "0.0.0.0"

  validation {
    condition     = can(regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$", var.api_origin_ip))
    error_message = "api_origin_ip must be a valid IPv4 address."
  }
}

variable "proxied" {
  description = "Whether DNS records are proxied through Cloudflare (orange-cloud). Set false only for records that must bypass the WAF."
  type        = bool
  default     = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare Account ID. Required for Workers KV namespace management. Supply via TF_VAR_cloudflare_account_id — never hardcode."
  type        = string
  default     = ""
}
