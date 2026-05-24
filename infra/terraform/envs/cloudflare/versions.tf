terraform {
  required_version = ">= 1.6"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 4.0"
    }
  }

  # Phase 1 skeleton: local backend only.
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "cloudflare" {
  # Token is supplied exclusively via TF_VAR_cloudflare_api_token — never hardcode.
  api_token = var.cloudflare_api_token
}
