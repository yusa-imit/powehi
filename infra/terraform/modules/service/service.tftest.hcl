mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:ap-northeast-2:123456789012:log-group:/powehi/staging/service"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
}

variables {
  name_prefix               = "powehi-staging"
  server_image              = "ghcr.io/yusa-imit/powehi-server@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  cloudflared_image         = "docker.io/cloudflare/cloudflared@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  public_subnet_ids         = ["subnet-aaaa", "subnet-bbbb"]
  service_security_group_id = "sg-0123456789abcdef0"
  environment_variables = {
    POWEHI__REGION_ID     = "kr-seoul"
    POWEHI__VAPID_CONTACT = "mailto:ops@example.com"
    POWEHI__R2_BUCKET     = "powehi-staging-media"
    POWEHI__R2_ENDPOINT   = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"
  }
  secret_arns = {
    database_url               = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/database-url-AbCdEf"
    redis_url                  = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/redis-url-AbCdEf"
    r2_access_key_id           = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/r2-access-key-id-AbCdEf"
    r2_secret_access_key       = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/r2-secret-access-key-AbCdEf"
    vapid_private_key_pem      = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/vapid-AbCdEf"
    handle_oracle_secret_token = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/handle-oracle-AbCdEf"
    tunnel_token               = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/tunnel-token-AbCdEf"
  }
}

run "roles_are_bounded_and_least_privilege" {
  command = apply

  assert {
    condition     = aws_iam_role.execution.permissions_boundary == "arn:aws:iam::123456789012:policy/powehi-boundary-staging" && aws_iam_role.task.permissions_boundary == aws_iam_role.execution.permissions_boundary
    error_message = "Both roles must carry the env permissions boundary."
  }

  assert {
    condition     = startswith(aws_iam_role.execution.name, "powehi-staging-svc-") && startswith(aws_iam_role.task.name, "powehi-staging-svc-")
    error_message = "Roles must live under the svc prefix the deploy role may touch."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.execution.policy, "\"*\"")
    error_message = "The execution policy must not use wildcard actions or resources."
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.execution.policy).Statement) == 2
    error_message = "The execution role has exactly secrets-read and log-write."
  }
}

run "task_has_no_inline_credentials_and_pinned_images" {
  command = apply

  assert {
    condition     = alltrue([for c in jsondecode(aws_ecs_task_definition.this.container_definitions) : strcontains(c.image, "@sha256:")])
    error_message = "Every image must be pinned by digest."
  }

  assert {
    condition = alltrue([
      for e in jsondecode(aws_ecs_task_definition.this.container_definitions)[0].environment :
      !can(regex("(SECRET|PASSWORD|TOKEN|PRIVATE|_URL$|ACCESS_KEY)", e.name))
    ])
    error_message = "Credentials must reach the task only through secrets."
  }

  assert {
    condition     = length(jsondecode(aws_ecs_task_definition.this.container_definitions)[0].secrets) == 6 && length(jsondecode(aws_ecs_task_definition.this.container_definitions)[1].secrets) == 1
    error_message = "Six server secrets and the tunnel token."
  }

  assert {
    condition     = jsondecode(aws_ecs_task_definition.this.container_definitions)[1].dependsOn[0].condition == "HEALTHY"
    error_message = "cloudflared must wait for a healthy origin."
  }
}

run "service_has_no_load_balancer_and_rolls_back" {
  command = apply

  assert {
    condition     = aws_ecs_service.this.deployment_circuit_breaker[0].enable && aws_ecs_service.this.deployment_circuit_breaker[0].rollback
    error_message = "The circuit breaker must roll back."
  }

  assert {
    condition     = length(aws_ecs_service.this.load_balancer) == 0 && aws_ecs_service.this.network_configuration[0].assign_public_ip
    error_message = "No load balancer; the public IP is for outbound only."
  }

  assert {
    condition     = aws_cloudwatch_log_group.service.retention_in_days == 14 && aws_cloudwatch_log_group.service.name == "/powehi/staging/service"
    error_message = "Log group is /powehi/<env>/service with 14-day retention."
  }
}

run "foreign_image_owner_is_refused" {
  command = plan

  variables {
    server_image = "ghcr.io/example/powehi-server@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  }

  expect_failures = [var.server_image]
}

run "tag_image_is_refused" {
  command = plan

  variables {
    server_image = "ghcr.io/yusa-imit/powehi-server:latest"
  }

  expect_failures = [var.server_image]
}

run "foreign_secret_path_is_refused" {
  command = plan

  variables {
    secret_arns = {
      database_url               = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:other/database-url-AbCdEf"
      redis_url                  = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/redis-url-AbCdEf"
      r2_access_key_id           = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/r2-access-key-id-AbCdEf"
      r2_secret_access_key       = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/r2-secret-access-key-AbCdEf"
      vapid_private_key_pem      = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/vapid-AbCdEf"
      handle_oracle_secret_token = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/handle-oracle-AbCdEf"
      tunnel_token               = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:powehi/staging/tunnel-token-AbCdEf"
    }
  }

  expect_failures = [var.secret_arns]
}
