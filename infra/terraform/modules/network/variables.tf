variable "name_prefix" {
  description = "Resource name prefix, powehi-<env> (the deploy role is scoped to it)."
  type        = string

  validation {
    condition     = can(regex("^powehi-(staging|prod)$", var.name_prefix))
    error_message = "name_prefix must be powehi-staging or powehi-prod."
  }
}

variable "vpc_cidr" {
  description = "IPv4 CIDR of the VPC. The /20 subnets are carved from it."
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && tonumber(split("/", var.vpc_cidr)[1]) <= 18
    error_message = "vpc_cidr must be a valid CIDR no smaller than /18."
  }
}

variable "az_count" {
  description = "Availability zones used (ADR-0007: two)."
  type        = number
  default     = 2

  validation {
    condition     = var.az_count == 2
    error_message = "The topology is two AZs."
  }
}
