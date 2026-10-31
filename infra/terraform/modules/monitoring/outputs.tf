output "alerts_topic_arn" {
  description = "SNS topic that receives every alarm, OK and task-stopped notification."
  value       = aws_sns_topic.alerts.arn
}

output "alarm_names" {
  description = "Names of the CloudWatch alarms of this env."
  value = [
    aws_cloudwatch_metric_alarm.running_tasks.alarm_name,
    aws_cloudwatch_metric_alarm.db_cpu.alarm_name,
    aws_cloudwatch_metric_alarm.db_free_storage.alarm_name,
    aws_cloudwatch_metric_alarm.db_connections.alarm_name,
    aws_cloudwatch_metric_alarm.cache_memory.alarm_name,
    aws_cloudwatch_metric_alarm.cache_engine_cpu.alarm_name,
  ]
}
