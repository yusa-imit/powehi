terraform {
  required_version = ">= 1.6"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = ">= 1.45"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }

  # State contains the k3s join token — must be encrypted at rest.
  # Configure a remote backend before any production apply:
  #   tofu init -backend-config=backend.hcl
  # See infra/terraform/envs/backend.hcl.example for required fields.
  # NEVER apply with an unencrypted local backend in production.
  backend "s3" {}
}

provider "hcloud" {
  # Token is supplied exclusively via TF_VAR_hcloud_token — never hardcode.
  token = var.hcloud_token
}
