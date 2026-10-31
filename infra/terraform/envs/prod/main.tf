# Composition root for prod. Modules arrive in 9.3 (network, data), 9.4 (edge), 9.5 (compute).

locals {
  name_prefix = "powehi-${var.environment}"
  # Public hostname of this env's API; staging gets a subdomain, prod the apex (9.4).
  api_hostname = var.environment == "prod" ? "api.${var.domain}" : "api-${var.environment}.${var.domain}"
}
