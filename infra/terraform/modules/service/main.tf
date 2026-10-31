# ECS Fargate service: powehi-server plus a cloudflared sidecar in one task. The task security
# group has no ingress (network module); traffic arrives through the Cloudflare Tunnel, which the
# sidecar dials out to. No credential value appears in this configuration: each one is a Secrets
# Manager ARN the ECS agent resolves at launch. Logs carry no message content or PII (rule
# no-plaintext-logging); the server only logs metadata.

data "aws_caller_identity" "this" {}

locals {
  env      = trimprefix(var.name_prefix, "powehi-")
  origin   = 8080
  admin    = 9090
  boundary = "arn:aws:iam::${data.aws_caller_identity.this.account_id}:policy/powehi-boundary-${local.env}"

  # Server setting -> Secrets Manager ARN. The tunnel token is the sidecar's TUNNEL_TOKEN.
  server_secrets = {
    POWEHI__DATABASE_URL               = var.secret_arns["database_url"]
    POWEHI__REDIS_URL                  = var.secret_arns["redis_url"]
    POWEHI__R2_ACCESS_KEY_ID           = var.secret_arns["r2_access_key_id"]
    POWEHI__R2_SECRET_ACCESS_KEY       = var.secret_arns["r2_secret_access_key"]
    POWEHI__VAPID_PRIVATE_KEY_PEM      = var.secret_arns["vapid_private_key_pem"]
    POWEHI__HANDLE_ORACLE_SECRET_TOKEN = var.secret_arns["handle_oracle_secret_token"]
  }
}

resource "aws_cloudwatch_log_group" "service" {
  name              = "/powehi/${local.env}/service"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "this" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "disabled" # metrics stay content-free and cheap; alarms come in 9.10
  }
}

# --- Roles ---------------------------------------------------------------------------------
# Both carry the env's permissions boundary (the deploy role may create no other kind) and live
# under the powehi-<env>-svc- prefix it is allowed to touch.
locals {
  ecs_tasks_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.this.account_id } }
    }]
  })
}

# The ECS agent's role: read the named secrets and write the service log group, nothing else.
# Both images come from public registries, so there are no ECR rights.
resource "aws_iam_role" "execution" {
  name                 = "${var.name_prefix}-svc-exec"
  assume_role_policy   = local.ecs_tasks_trust
  permissions_boundary = local.boundary
}

resource "aws_iam_role_policy" "execution" {
  name = "${var.name_prefix}-svc-exec"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadTaskSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = values(var.secret_arns)
      },
      {
        Sid      = "WriteServiceLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.service.arn}:*"]
      },
    ]
  })
}

# What the server's own code runs as. It calls no AWS API (Postgres, Valkey and R2 use their own
# credentials), so it has no policy at all.
resource "aws_iam_role" "task" {
  name                 = "${var.name_prefix}-svc-task"
  assume_role_policy   = local.ecs_tasks_trust
  permissions_boundary = local.boundary
}

# --- Task and service ----------------------------------------------------------------------
locals {
  log_options = {
    "awslogs-group"         = aws_cloudwatch_log_group.service.name
    "awslogs-region"        = var.aws_region
    "awslogs-stream-prefix" = "svc"
  }

  # The image is Debian slim: no curl or wget. bash's /dev/tcp reads the status line of /health.
  health_command = "exec 3<>/dev/tcp/127.0.0.1/${local.origin} && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && read -r line <&3 && [[ \\$line == *' 200 '* ]]"

  server_container = {
    name         = "powehi-server"
    image        = var.server_image
    essential    = true
    portMappings = [{ containerPort = local.origin, protocol = "tcp" }]
    environment = [
      for k, v in merge(var.environment_variables, {
        POWEHI__HOST       = "127.0.0.1" # cloudflared and the health check share the task loopback
        POWEHI__PORT       = tostring(local.origin)
        POWEHI__ADMIN_PORT = tostring(local.admin)
      }) : { name = k, value = v }
    ]
    secrets = [for k, v in local.server_secrets : { name = k, valueFrom = v }]
    healthCheck = {
      command     = ["CMD-SHELL", "bash -c \"${local.health_command}\""]
      interval    = 15
      timeout     = 5
      retries     = 3
      startPeriod = 60 # covers the startup migrations
    }
    readonlyRootFilesystem = true
    logConfiguration       = { logDriver = "awslogs", options = local.log_options }
  }

  cloudflared_container = {
    name    = "cloudflared"
    image   = var.cloudflared_image
    command = ["tunnel", "--no-autoupdate", "--metrics", "127.0.0.1:2000", "run"]
    secrets = [{ name = "TUNNEL_TOKEN", valueFrom = var.secret_arns["tunnel_token"] }]
    # The tunnel starts only once the origin answers, so Cloudflare never routes to a cold task.
    essential              = true
    dependsOn              = [{ containerName = "powehi-server", condition = "HEALTHY" }]
    readonlyRootFilesystem = true
    logConfiguration       = { logDriver = "awslogs", options = local.log_options }
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.name_prefix}-service"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  container_definitions = jsonencode([local.server_container, local.cloudflared_container])
}

resource "aws_ecs_service" "this" {
  name            = "${var.name_prefix}-service"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # Roll forward with the old tasks still serving; a task that never turns healthy rolls back.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [var.service_security_group_id]
    assign_public_ip = true # outbound only: the group has no ingress and there is no NAT
  }

  # The deploy workflow (9.8) registers new task definitions and updates the service; a plan must
  # not roll the service back to the revision this stack last applied.
  lifecycle {
    ignore_changes = [task_definition]
  }
}
