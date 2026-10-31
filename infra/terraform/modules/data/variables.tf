variable "name_prefix" {
  description = "Resource name prefix, powehi-<env> (the deploy role is scoped to it)."
  type        = string

  validation {
    condition     = can(regex("^powehi-(staging|prod)$", var.name_prefix))
    error_message = "name_prefix must be powehi-staging or powehi-prod."
  }
}

variable "protected" {
  description = "True for prod: deletion protection and a final snapshot on the database."
  type        = bool
}

variable "vpc_id" {
  description = "VPC the data stores live in."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets (two AZs) for the DB and cache subnet groups."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) == 2
    error_message = "Pass the two private subnets."
  }
}

variable "service_security_group_id" {
  description = "Security group of the tasks; the only source the data stores accept."
  type        = string
}

variable "db_instance_class" {
  description = "RDS instance class (ADR-0007: db.t4g.micro)."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage_gb" {
  description = "gp3 storage in GB."
  type        = number
  default     = 20

  validation {
    condition     = var.db_allocated_storage_gb >= 20 && var.db_allocated_storage_gb <= 200
    error_message = "Storage must be 20..200 GB."
  }
}

variable "cache_node_type" {
  description = "ElastiCache node type (ADR-0007: cache.t4g.micro)."
  type        = string
  default     = "cache.t4g.micro"
}
