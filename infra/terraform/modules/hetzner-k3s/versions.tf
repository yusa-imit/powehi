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
}
