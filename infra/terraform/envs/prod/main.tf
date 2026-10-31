# Composition root for prod. Modules: network, data (9.3), edge (9.4); service (9.5).

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

module "service" {
  source                    = "../../modules/service"
  name_prefix               = local.name_prefix
  aws_region                = var.aws_region
  server_image              = var.server_image
  cloudflared_image         = var.cloudflared_image
  public_subnet_ids         = module.network.public_subnet_ids
  service_security_group_id = module.network.service_security_group_id
  secret_arns               = var.secret_arns

  environment_variables = {
    POWEHI__REGION_ID     = "kr-seoul"
    POWEHI__R2_ENDPOINT   = module.edge.r2_endpoint
    POWEHI__R2_BUCKET     = module.edge.r2_bucket
    POWEHI__VAPID_CONTACT = var.vapid_contact
  }
}
