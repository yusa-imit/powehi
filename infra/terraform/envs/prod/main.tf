# Composition root for prod. Modules: network, data (9.3), edge (9.4); compute arrives in 9.5.

locals {
  name_prefix = "powehi-${var.environment}"
  # Public hostname of this env's API; staging gets a subdomain, prod the apex (9.4).
  api_hostname = var.environment == "prod" ? "api.${var.domain}" : "api-${var.environment}.${var.domain}"
}

module "network" {
  source      = "../../modules/network"
  name_prefix = local.name_prefix
}

module "data" {
  source                    = "../../modules/data"
  name_prefix               = local.name_prefix
  protected                 = true
  vpc_id                    = module.network.vpc_id
  private_subnet_ids        = module.network.private_subnet_ids
  service_security_group_id = module.network.service_security_group_id
}

module "edge" {
  source                = "../../modules/edge"
  name_prefix           = local.name_prefix
  domain                = var.domain
  api_hostname          = local.api_hostname
  cloudflare_account_id = var.cloudflare_account_id
  # Shared zone: staging owns the zone-wide settings and WAF rulesets (see ../../README.md).
  manage_zone     = false
  create_r2_token = var.create_r2_token

  r2_token_allowed_cidrs = var.r2_token_allowed_cidrs
  r2_token_expires_on    = var.r2_token_expires_on
}
