mock_provider "aws" {
  mock_resource "aws_db_instance" {
    defaults = {
      endpoint           = "powehi-staging-db.example.ap-northeast-2.rds.amazonaws.com:5432"
      master_user_secret = [{ secret_arn = "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:rds!mock", kms_key_id = "k", secret_status = "active" }]
    }
  }
}
variables {
  name_prefix               = "powehi-staging"
  protected                 = false
  vpc_id                    = "vpc-0123456789abcdef0"
  private_subnet_ids        = ["subnet-aaaa", "subnet-bbbb"]
  service_security_group_id = "sg-0123456789abcdef0"
}

run "database_is_encrypted_tls_private_and_backed_up" {
  command = apply

  assert {
    condition     = aws_db_instance.this.storage_encrypted && !aws_db_instance.this.publicly_accessible
    error_message = "RDS must be encrypted and not public."
  }

  assert {
    condition     = [for p in aws_db_parameter_group.this.parameter : p.value if p.name == "rds.force_ssl"][0] == "1"
    error_message = "rds.force_ssl must be 1."
  }

  assert {
    condition     = aws_db_instance.this.backup_retention_period == 7 && aws_db_instance.this.storage_type == "gp3"
    error_message = "7-day backups on gp3 expected."
  }

  assert {
    condition     = aws_db_instance.this.manage_master_user_password == true && aws_db_instance.this.password == null
    error_message = "The master password must be RDS-managed, never set here."
  }

  assert {
    condition     = !aws_db_instance.this.deletion_protection && aws_db_instance.this.skip_final_snapshot
    error_message = "Staging is not protected."
  }
}

run "database_is_wired_to_private_subnets_and_its_parameter_group" {
  command = apply

  assert {
    condition     = aws_db_instance.this.parameter_group_name == aws_db_parameter_group.this.name && aws_db_instance.this.vpc_security_group_ids == toset([aws_security_group.db.id]) && aws_db_instance.this.db_subnet_group_name == aws_db_subnet_group.this.name
    error_message = "RDS must use its own parameter group, only the db SG and the subnet group."
  }

  assert {
    condition     = aws_db_subnet_group.this.subnet_ids == toset(var.private_subnet_ids) && aws_elasticache_subnet_group.this.subnet_ids == toset(var.private_subnet_ids)
    error_message = "Subnet groups must use the private subnets."
  }

  assert {
    condition     = length(aws_db_instance.this.enabled_cloudwatch_logs_exports) == 0
    error_message = "No log export until 9.10 (constraint errors can carry hashes and ciphertext)."
  }
}

run "prod_is_protected" {
  command = apply

  variables {
    protected = true
  }

  assert {
    condition     = aws_db_instance.this.deletion_protection && !aws_db_instance.this.skip_final_snapshot
    error_message = "Prod needs deletion protection and a final snapshot."
  }
}

run "cache_is_encrypted_with_auth" {
  command = apply

  assert {
    condition     = aws_elasticache_replication_group.this.at_rest_encryption_enabled && aws_elasticache_replication_group.this.transit_encryption_enabled
    error_message = "ElastiCache needs encryption at rest and in transit."
  }

  assert {
    condition     = aws_elasticache_replication_group.this.auth_token_wo_version == 1 && aws_elasticache_replication_group.this.security_group_ids == toset([aws_security_group.cache.id]) && aws_elasticache_replication_group.this.auth_token == null
    error_message = "AUTH is set write-only (never in state) and only the cache SG is attached."
  }

  assert {
    condition     = startswith(aws_secretsmanager_secret.cache_auth.name, "powehi/staging/")
    error_message = "Secret names must match the IAM scope powehi/<env>/*."
  }

  assert {
    condition     = aws_elasticache_replication_group.this.transit_encryption_mode == "required"
    error_message = "TLS must be required."
  }
}

run "stores_accept_only_the_service_sg" {
  command = apply

  assert {
    condition     = aws_vpc_security_group_ingress_rule.db_from_service.referenced_security_group_id == var.service_security_group_id && aws_vpc_security_group_ingress_rule.db_from_service.cidr_ipv4 == null
    error_message = "DB ingress must reference the service SG, no CIDR."
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.cache_from_service.referenced_security_group_id == var.service_security_group_id && aws_vpc_security_group_ingress_rule.cache_from_service.cidr_ipv4 == null
    error_message = "Cache ingress must reference the service SG, no CIDR."
  }
}
