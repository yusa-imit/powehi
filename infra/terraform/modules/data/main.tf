# RDS PostgreSQL 16 and an ElastiCache Valkey node. Both are encrypted at rest, TLS-only,
# unreachable from the internet, and accept connections only from the service security group.
# They hold only what the server may see: ciphertext envelopes and metadata (prd §3).

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-db"
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "db" {
  name        = "${var.name_prefix}-db"
  description = "PostgreSQL: service tasks only"
  vpc_id      = var.vpc_id

  tags = { Name = "${var.name_prefix}-db" }
}

resource "aws_vpc_security_group_ingress_rule" "db_from_service" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from the service security group"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = var.service_security_group_id
}

resource "aws_db_parameter_group" "this" {
  name   = "${var.name_prefix}-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "this" {
  identifier     = "${var.name_prefix}-db"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage_gb
  storage_type      = "gp3"
  storage_encrypted = true

  db_name  = "powehi"
  username = "powehi_admin"
  # RDS creates and rotates the master password in Secrets Manager; it is never in state or code.
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false
  multi_az               = false

  backup_retention_period    = 7 # automated backups + PITR
  backup_window              = "18:00-19:00"
  maintenance_window         = "sun:19:30-sun:20:30"
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true

  iam_database_authentication_enabled = true
  performance_insights_enabled        = false
  # No log export until 9.10: DETAIL lines of constraint errors can carry handle hashes and
  # ciphertext, and the RDS-created log group has no retention.
  enabled_cloudwatch_logs_exports = []

  delete_automated_backups  = !var.protected
  deletion_protection       = var.protected
  skip_final_snapshot       = !var.protected
  final_snapshot_identifier = var.protected ? "${var.name_prefix}-db-final" : null
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name_prefix}-cache"
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "cache" {
  name        = "${var.name_prefix}-cache"
  description = "Valkey: service tasks only"
  vpc_id      = var.vpc_id

  tags = { Name = "${var.name_prefix}-cache" }
}

resource "aws_vpc_security_group_ingress_rule" "cache_from_service" {
  security_group_id            = aws_security_group.cache.id
  description                  = "Valkey from the service security group"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = var.service_security_group_id
}

# AUTH token: generated here, kept in Secrets Manager for the task to read (9.5).
ephemeral "random_password" "cache_auth" {
  length           = 48
  special          = true
  override_special = "!&#$^<>-"
}

resource "aws_secretsmanager_secret" "cache_auth" {
  name                    = "${replace(var.name_prefix, "-", "/")}/cache-auth-token"
  description             = "ElastiCache AUTH token"
  recovery_window_in_days = var.protected ? 30 : 7
}

resource "aws_secretsmanager_secret_version" "cache_auth" {
  secret_id = aws_secretsmanager_secret.cache_auth.id
  # Write-only: the token never reaches state or the plan file.
  secret_string_wo         = ephemeral.random_password.cache_auth.result
  secret_string_wo_version = 1
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = "${var.name_prefix}-cache"
  description          = "powehi ${var.name_prefix} Valkey"
  engine               = "valkey"
  engine_version       = "7.2"
  node_type            = var.cache_node_type
  port                 = 6379

  num_cache_clusters         = 1
  automatic_failover_enabled = false
  multi_az_enabled           = false

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.cache.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  transit_encryption_mode    = "required"
  auth_token_wo              = ephemeral.random_password.cache_auth.result
  auth_token_wo_version      = 1

  snapshot_retention_limit = 1
  apply_immediately        = false
}
