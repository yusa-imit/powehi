variable "name_prefix" {
  description = "Resource name prefix, powehi-<env> (the deploy role is scoped to it)."
  type        = string

  validation {
    condition     = can(regex("^powehi-(staging|prod)$", var.name_prefix))
    error_message = "name_prefix must be powehi-staging or powehi-prod."
  }
}

variable "aws_region" {
  description = "AWS region of the task and its log group (ADR-0007: ap-northeast-2)."
  type        = string
  default     = "ap-northeast-2"
}

variable "server_image" {
  description = "powehi-server image pinned by digest, ghcr.io/yusa-imit/powehi-server@sha256:<64 hex>. A tag is refused: the deploy workflow (9.8) passes the digest it just signed."
  type        = string

  validation {
    condition     = can(regex("^ghcr\\.io/yusa-imit/powehi-server@sha256:[0-9a-f]{64}$", var.server_image))
    error_message = "server_image must be the yusa-imit ghcr.io image pinned by sha256 digest."
  }
}

variable "cloudflared_image" {
  description = "cloudflared sidecar image pinned by digest (docker.io/cloudflare/cloudflared@sha256:<64 hex>)."
  type        = string

  validation {
    condition     = can(regex("^(docker\\.io/)?cloudflare/cloudflared@sha256:[0-9a-f]{64}$", var.cloudflared_image))
    error_message = "cloudflared_image must be cloudflare/cloudflared pinned by sha256 digest."
  }
}

variable "cpu_architecture" {
  description = "Fargate CPU architecture. ADR-0007 targets ARM64, but release.yml builds linux/amd64 only; switch to ARM64 together with a multi-arch image (9.8)."
  type        = string
  default     = "X86_64"

  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "cpu_architecture must be X86_64 or ARM64."
  }
}

variable "public_subnet_ids" {
  description = "Subnets for the tasks (public IP for outbound only; the security group has no ingress)."
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_ids) == 2
    error_message = "Pass the two public subnets."
  }
}

variable "service_security_group_id" {
  description = "Security group of the tasks (network module): no ingress."
  type        = string
}

variable "task_cpu" {
  description = "Task CPU units (Fargate size)."
  type        = number
  default     = 512

  validation {
    condition     = contains([256, 512, 1024, 2048], var.task_cpu)
    error_message = "task_cpu must be 256, 512, 1024 or 2048."
  }
}

variable "task_memory" {
  description = "Task memory in MiB (must be valid for task_cpu)."
  type        = number
  default     = 1024

  validation {
    condition     = var.task_memory >= 512 && var.task_memory <= 4096
    error_message = "task_memory must be 512..4096 MiB."
  }
}

variable "desired_count" {
  description = "Running tasks. Startup migrations are serialised by sqlx's Postgres advisory lock, so more than one is safe."
  type        = number
  default     = 1

  validation {
    condition     = var.desired_count >= 1 && var.desired_count <= 4
    error_message = "desired_count must be 1..4."
  }
}

variable "log_retention_days" {
  description = "CloudWatch retention of the service log group."
  type        = number
  default     = 14

  validation {
    condition     = var.log_retention_days == 14
    error_message = "Retention is 14 days (9.5)."
  }
}

variable "environment_variables" {
  description = "Non-secret POWEHI__* settings for the server (region id, R2 endpoint and bucket, VAPID contact). The listener settings and credentials are owned by this module."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for k in keys(var.environment_variables) :
      can(regex("^POWEHI__[A-Z0-9_]+$", k)) &&
      !contains(["POWEHI__HOST", "POWEHI__PORT", "POWEHI__ADMIN_PORT"], k) &&
      !can(regex("(SECRET|PASSWORD|TOKEN|PRIVATE|_URL$|ACCESS_KEY)", k))
    ])
    error_message = "environment_variables take non-secret POWEHI__* keys only; credentials go through secret_arns."
  }
}

variable "secret_arns" {
  description = "Secrets Manager ARNs created out of band under powehi/<env>/ (never values). Keys: database_url, redis_url, r2_access_key_id, r2_secret_access_key, vapid_private_key_pem, handle_oracle_secret_token, tunnel_token."
  type        = map(string)

  validation {
    condition = toset(keys(var.secret_arns)) == toset([
      "database_url", "redis_url", "r2_access_key_id", "r2_secret_access_key",
      "vapid_private_key_pem", "handle_oracle_secret_token", "tunnel_token",
    ])
    error_message = "secret_arns needs exactly the seven documented keys."
  }

  validation {
    condition = alltrue([
      for a in values(var.secret_arns) :
      can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:powehi/(staging|prod)/[A-Za-z0-9/_+=.@-]+$", a))
    ])
    error_message = "Each ARN must be a Secrets Manager secret under powehi/<env>/ (the task boundary only reads that path)."
  }
}
