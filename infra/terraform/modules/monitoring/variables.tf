variable "name_prefix" {
  description = "Resource name prefix, powehi-<env> (the deploy role is scoped to it)."
  type        = string

  validation {
    condition     = can(regex("^powehi-(staging|prod)$", var.name_prefix))
    error_message = "name_prefix must be powehi-staging or powehi-prod."
  }
}

variable "aws_region" {
  description = "AWS region of the monitored resources (ADR-0007: ap-northeast-2)."
  type        = string
  default     = "ap-northeast-2"
}

variable "alert_email" {
  description = "Owner e-mail that receives every alarm and OK notification. Never hard-coded; set in <env>.tfvars or TF_VAR_alert_email. AWS sends a confirmation mail that the owner must accept."
  type        = string

  sensitive = true
  validation {
    condition     = can(regex("^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\\.)+[A-Za-z]{2,}$", var.alert_email))
    error_message = "alert_email must be a plain e-mail address such as owner@example.com."
  }
}

variable "cluster_name" {
  description = "ECS cluster name (service module). Needs Container Insights enabled for RunningTaskCount."
  type        = string
}

variable "service_name" {
  description = "ECS service name (service module)."
  type        = string
}

variable "db_instance_identifier" {
  description = "RDS instance identifier (data module)."
  type        = string
}

variable "cache_cluster_id" {
  description = "ElastiCache node (cache cluster) ID of the single Valkey node (data module). Node-level metrics are keyed by it."
  type        = string
}

variable "db_cpu_threshold_percent" {
  description = "RDS CPUUtilization alarm threshold (average over 15 minutes)."
  type        = number
  default     = 80

  validation {
    condition     = var.db_cpu_threshold_percent > 0 && var.db_cpu_threshold_percent <= 100
    error_message = "db_cpu_threshold_percent must be in (0, 100]."
  }
}

variable "db_free_storage_threshold_gb" {
  description = "RDS FreeStorageSpace alarm threshold in GB (alarms below it). Default 4 is 20 percent of the 20 GB gp3 volume."
  type        = number
  default     = 4

  validation {
    condition     = var.db_free_storage_threshold_gb >= 1 && var.db_free_storage_threshold_gb <= 100
    error_message = "db_free_storage_threshold_gb must be 1..100."
  }
}

variable "db_connections_threshold" {
  description = "RDS DatabaseConnections alarm threshold. db.t4g.micro (1 GiB) allows about 112 connections, so 80 leaves headroom."
  type        = number
  default     = 80

  validation {
    condition     = var.db_connections_threshold >= 1 && var.db_connections_threshold <= 5000 && floor(var.db_connections_threshold) == var.db_connections_threshold
    error_message = "db_connections_threshold must be a whole number in 1..5000."
  }
}

variable "cache_memory_threshold_percent" {
  description = "ElastiCache DatabaseMemoryUsagePercentage alarm threshold."
  type        = number
  default     = 80

  validation {
    condition     = var.cache_memory_threshold_percent > 0 && var.cache_memory_threshold_percent <= 100
    error_message = "cache_memory_threshold_percent must be in (0, 100]."
  }
}

variable "cache_engine_cpu_threshold_percent" {
  description = "ElastiCache EngineCPUUtilization alarm threshold (the Valkey main thread, not the whole node)."
  type        = number
  default     = 80

  validation {
    condition     = var.cache_engine_cpu_threshold_percent > 0 && var.cache_engine_cpu_threshold_percent <= 100
    error_message = "cache_engine_cpu_threshold_percent must be in (0, 100]."
  }
}
