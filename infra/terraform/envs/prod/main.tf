# Composition root for prod. Modules arrive in 9.3 (network, data), 9.4 (edge), 9.5 (compute).

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
