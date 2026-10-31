mock_provider "aws" {
  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:ap-northeast-2:123456789012:powehi-staging-alerts"
    }
  }
  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:ap-northeast-2:123456789012:key/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name_prefix            = "powehi-staging"
  alert_email            = "owner@test.invalid"
  cluster_name           = "powehi-staging"
  service_name           = "powehi-staging-server"
  db_instance_identifier = "powehi-staging-db"
  cache_cluster_id       = "powehi-staging-cache-001"
}

run "six_alarms_all_notify_the_topic_for_alarm_and_ok" {
  command = apply

  assert {
    condition     = length(output.alarm_names) == 6
    error_message = "Expected six CloudWatch alarms."
  }

  assert {
    condition = alltrue([for a in [
      aws_cloudwatch_metric_alarm.running_tasks,
      aws_cloudwatch_metric_alarm.db_cpu,
      aws_cloudwatch_metric_alarm.db_free_storage,
      aws_cloudwatch_metric_alarm.db_connections,
      aws_cloudwatch_metric_alarm.cache_memory,
      aws_cloudwatch_metric_alarm.cache_engine_cpu,
      ] : a.alarm_actions == a.ok_actions && length(a.alarm_actions) == 1 && startswith(a.alarm_name, "powehi-staging-")
    ])
    error_message = "Every alarm must notify the topic for ALARM and OK and carry the env prefix."
  }
}

run "running_tasks_alarm_uses_container_insights_and_breaches_on_missing_data" {
  command = apply

  assert {
    condition     = aws_cloudwatch_metric_alarm.running_tasks.namespace == "ECS/ContainerInsights" && aws_cloudwatch_metric_alarm.running_tasks.metric_name == "RunningTaskCount" && aws_cloudwatch_metric_alarm.running_tasks.threshold == 1 && aws_cloudwatch_metric_alarm.running_tasks.comparison_operator == "LessThanThreshold"
    error_message = "RunningTaskCount < 1 is required."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.running_tasks.treat_missing_data == "breaching" && aws_cloudwatch_metric_alarm.running_tasks.dimensions["ClusterName"] == "powehi-staging" && aws_cloudwatch_metric_alarm.running_tasks.dimensions["ServiceName"] == "powehi-staging-server"
    error_message = "Missing data must breach; dimensions are cluster and service."
  }
}

run "default_thresholds" {
  command = apply

  assert {
    condition     = aws_cloudwatch_metric_alarm.db_cpu.threshold == 80 && aws_cloudwatch_metric_alarm.db_connections.threshold == 80 && aws_cloudwatch_metric_alarm.cache_memory.threshold == 80 && aws_cloudwatch_metric_alarm.cache_engine_cpu.threshold == 80
    error_message = "Unexpected default thresholds."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.db_free_storage.threshold == 4 * 1024 * 1024 * 1024 && aws_cloudwatch_metric_alarm.db_free_storage.comparison_operator == "LessThanThreshold"
    error_message = "Free storage threshold is 4 GB in bytes, alarming below it."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.cache_memory.metric_name == "DatabaseMemoryUsagePercentage" && aws_cloudwatch_metric_alarm.cache_memory.dimensions["CacheClusterId"] == "powehi-staging-cache-001" && aws_cloudwatch_metric_alarm.db_cpu.dimensions["DBInstanceIdentifier"] == "powehi-staging-db"
    error_message = "Metric names and dimensions must match the monitored resources."
  }
}

run "thresholds_are_configurable" {
  command = apply

  variables {
    db_cpu_threshold_percent     = 90
    db_free_storage_threshold_gb = 8
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.db_cpu.threshold == 90 && aws_cloudwatch_metric_alarm.db_free_storage.threshold == 8 * 1024 * 1024 * 1024
    error_message = "Thresholds must follow the variables."
  }
}

run "restart_rule_targets_this_service_and_ignores_scheduler_stops" {
  command = apply

  assert {
    condition     = strcontains(aws_cloudwatch_event_rule.task_stopped.event_pattern, "ECS Task State Change") && strcontains(aws_cloudwatch_event_rule.task_stopped.event_pattern, "service:powehi-staging-server") && strcontains(aws_cloudwatch_event_rule.task_stopped.event_pattern, "STOPPED") && strcontains(aws_cloudwatch_event_rule.task_stopped.event_pattern, "cluster/powehi-staging")
    error_message = "The rule must match STOPPED task events of this cluster and service."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_event_rule.task_stopped.event_pattern, "ServiceSchedulerInitiated") && strcontains(aws_cloudwatch_event_rule.task_stopped.event_pattern, "anything-but")
    error_message = "Deployment stops must not notify."
  }
}

run "topic_is_cmk_encrypted_and_subscribed_by_variable" {
  command = apply

  assert {
    condition     = aws_sns_topic.alerts.kms_master_key_id == aws_kms_key.alerts.arn && aws_kms_key.alerts.enable_key_rotation
    error_message = "The topic must use the rotating CMK."
  }

  assert {
    condition     = aws_sns_topic_subscription.owner.protocol == "email" && aws_sns_topic_subscription.owner.endpoint == "owner@test.invalid"
    error_message = "The e-mail subscription must come from alert_email."
  }

  assert {
    condition     = !strcontains(file("${path.module}/main.tf"), "@")
    error_message = "No e-mail address may be hard-coded."
  }
}

run "invalid_email_is_rejected" {
  command = plan

  variables {
    alert_email = "not-an-email"
  }

  expect_failures = [var.alert_email]
}

run "invalid_thresholds_are_rejected" {
  command = plan

  variables {
    db_cpu_threshold_percent       = 0
    cache_memory_threshold_percent = 101
    db_connections_threshold       = 0
    db_free_storage_threshold_gb   = 0
  }

  expect_failures = [
    var.db_cpu_threshold_percent,
    var.cache_memory_threshold_percent,
    var.db_connections_threshold,
    var.db_free_storage_threshold_gb,
  ]
}

run "unknown_env_prefix_is_rejected" {
  command = plan

  variables {
    name_prefix = "powehi-dev"
  }

  expect_failures = [var.name_prefix]
}
