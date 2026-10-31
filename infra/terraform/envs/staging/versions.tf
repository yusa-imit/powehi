terraform {
  required_version = ">= 1.12.1, < 2.0.0"

  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }

  # Partial backend config: bucket, region and kms_key_id come from backend.hcl
  # (copy backend.hcl.example; values are outputs of ../../bootstrap).
  backend "s3" {
    key          = "staging/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = var.allowed_account_ids

  default_tags {
    tags = {
      Project     = "powehi"
      Environment = var.environment
      ManagedBy   = "opentofu"
    }
  }
}

# Authenticates with CLOUDFLARE_API_TOKEN from the environment (token scoped to the zone, R2
# and Tunnel; see ../../README.md). Never set it in a tfvars file.
provider "cloudflare" {}
