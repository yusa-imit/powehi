output "db_endpoint" {
  description = "PostgreSQL host:port."
  value       = aws_db_instance.this.endpoint
}

output "db_master_secret_arn" {
  description = "Secrets Manager secret holding the RDS-managed master credentials."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "cache_endpoint" {
  description = "Valkey primary endpoint address."
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "cache_auth_secret_arn" {
  description = "Secrets Manager secret holding the Valkey AUTH token."
  value       = aws_secretsmanager_secret.cache_auth.arn
}
