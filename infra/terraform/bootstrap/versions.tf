terraform {
  required_version = ">= 1.12.1, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Bootstrap runs once, by the owner, with local state (see ../README.md). The state file
  # contains no secrets, but keep it out of git and back it up; it is re-creatable by import.
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = var.allowed_account_ids

  default_tags {
    tags = {
      Project   = "powehi"
      ManagedBy = "opentofu"
      Stack     = "bootstrap"
    }
  }
}
