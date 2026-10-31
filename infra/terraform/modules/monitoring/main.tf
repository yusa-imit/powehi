# Monitoring for one env (ADR-0007, 9.10): CloudWatch alarms and an EventBridge rule that all
# notify one SNS topic by e-mail. Only AWS-native metrics (ECS Container Insights, RDS,
# ElastiCache) are used: no message content, no PII, no per-user labels (prd section 13). The
# alarm and event messages carry resource names, numbers and ECS stop reasons only.

data "aws_caller_identity" "current" {}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  topic_name   = "${var.name_prefix}-alerts"
  cluster_arn  = "arn:aws:ecs:${var.aws_region}:${local.account_id}:cluster/${var.cluster_name}"
  rule_arn     = "arn:aws:events:${var.aws_region}:${local.account_id}:rule/${var.name_prefix}-task-stopped"
  alarm_arns   = "arn:aws:cloudwatch:${var.aws_region}:${local.account_id}:alarm:${var.name_prefix}-*"
  gib          = 1024 * 1024 * 1024
  alarm_action = [aws_sns_topic.alerts.arn]
}

# --- Encryption: a small CMK ----------------------------------------------------------------
# The AWS-managed alias/aws/sns key cannot be used: its policy does not let CloudWatch or
# EventBridge publish. This customer key allows exactly those two service principals, scoped to
# this account.

data "aws_iam_policy_document" "key" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AlarmAndEventPublishers"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "alerts" {
  description             = "${var.name_prefix} alert topic (SNS) encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.key.json
}

resource "aws_kms_alias" "alerts" {
  name          = "alias/${local.topic_name}"
  target_key_id = aws_kms_key.alerts.key_id
}

# --- Topic and subscription -----------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name              = local.topic_name
  kms_master_key_id = aws_kms_key.alerts.arn
}

data "aws_iam_policy_document" "topic" {
  statement {
    sid       = "CloudWatchAlarms"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.alarm_arns]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "TaskStoppedRule"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.rule_arn]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.topic.json
}

# Stays "pending confirmation" until the owner accepts the AWS mail; alarms fire regardless.
resource "aws_sns_topic_subscription" "owner" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- ECS: running task count and restarts ---------------------------------------------------

# RunningTaskCount comes from Container Insights (enabled in the service module). Missing data
# means no task reports at all, which is the outage, so it counts as breaching.
resource "aws_cloudwatch_metric_alarm" "running_tasks" {
  alarm_name          = "${var.name_prefix}-running-tasks"
  alarm_description   = "ECS service has fewer than one running task."
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  dimensions          = { ClusterName = var.cluster_name, ServiceName = var.service_name }
  statistic           = "Minimum"
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  period              = 60
  evaluation_periods  = 2
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_action
  ok_actions          = local.alarm_action
}

# Every unexpected task stop for this service. Stops started by the ECS scheduler itself
# (deployments, scale-in) are excluded so a normal deploy does not page the owner.
resource "aws_cloudwatch_event_rule" "task_stopped" {
  name        = "${var.name_prefix}-task-stopped"
  description = "ECS task of ${var.name_prefix} stopped unexpectedly (restart)."

  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["ECS Task State Change"]
    detail = {
      clusterArn = [local.cluster_arn]
      group      = ["service:${var.service_name}"]
      lastStatus = ["STOPPED"]
      stopCode   = [{ "anything-but" = ["ServiceSchedulerInitiated"] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "task_stopped" {
  rule = aws_cloudwatch_event_rule.task_stopped.name
  arn  = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      stopCode      = "$.detail.stopCode"
      stoppedReason = "$.detail.stoppedReason"
      stoppedAt     = "$.detail.stoppedAt"
    }
    input_template = "\"${var.name_prefix}: ECS task stopped at <stoppedAt>, code <stopCode>, reason <stoppedReason>\""
  }
}

# --- RDS ------------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "${var.name_prefix}-db-cpu"
  alarm_description   = "RDS CPU utilization is high."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = var.db_instance_identifier }
  statistic           = "Average"
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.db_cpu_threshold_percent
  period              = 300
  evaluation_periods  = 3
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_action
  ok_actions          = local.alarm_action
}

resource "aws_cloudwatch_metric_alarm" "db_free_storage" {
  alarm_name          = "${var.name_prefix}-db-free-storage"
  alarm_description   = "RDS free storage space is low."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = var.db_instance_identifier }
  statistic           = "Minimum"
  comparison_operator = "LessThanThreshold"
  threshold           = var.db_free_storage_threshold_gb * local.gib
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_action
  ok_actions          = local.alarm_action
}

resource "aws_cloudwatch_metric_alarm" "db_connections" {
  alarm_name          = "${var.name_prefix}-db-connections"
  alarm_description   = "RDS connection count is close to the instance limit."
  namespace           = "AWS/RDS"
  metric_name         = "DatabaseConnections"
  dimensions          = { DBInstanceIdentifier = var.db_instance_identifier }
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.db_connections_threshold
  period              = 300
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_action
  ok_actions          = local.alarm_action
}

# --- ElastiCache (Valkey) -------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "cache_memory" {
  alarm_name          = "${var.name_prefix}-cache-memory"
  alarm_description   = "Valkey memory usage is high."
  namespace           = "AWS/ElastiCache"
  metric_name         = "DatabaseMemoryUsagePercentage"
  dimensions          = { CacheClusterId = var.cache_cluster_id }
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.cache_memory_threshold_percent
  period              = 300
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_action
  ok_actions          = local.alarm_action
}

resource "aws_cloudwatch_metric_alarm" "cache_engine_cpu" {
  alarm_name          = "${var.name_prefix}-cache-engine-cpu"
  alarm_description   = "Valkey engine thread CPU is high."
  namespace           = "AWS/ElastiCache"
  metric_name         = "EngineCPUUtilization"
  dimensions          = { CacheClusterId = var.cache_cluster_id }
  statistic           = "Average"
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.cache_engine_cpu_threshold_percent
  period              = 300
  evaluation_periods  = 3
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_action
  ok_actions          = local.alarm_action
}
