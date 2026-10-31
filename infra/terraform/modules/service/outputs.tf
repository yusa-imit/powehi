output "cluster_name" {
  description = "ECS cluster name (used by the deploy workflow, 9.8)."
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.this.name
}

output "task_family" {
  description = "Task definition family the deploy workflow registers revisions of."
  value       = aws_ecs_task_definition.this.family
}

output "log_group_name" {
  description = "Service log group."
  value       = aws_cloudwatch_log_group.service.name
}
