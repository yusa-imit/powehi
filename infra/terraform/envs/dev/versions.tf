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

  # Phase 1 skeleton: local backend only.
  # Before promoting to staging/prod, replace with an encrypted S3-compatible
  # remote backend (SSE-KMS) and never commit the state file.
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "hcloud" {
  # Token is supplied exclusively via TF_VAR_hcloud_token — never hardcode.
  token = var.hcloud_token
}
