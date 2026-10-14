terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.70" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = var.tags }
}

locals {
  name = var.name
}

# ---------------------------------------------------------------- encryption

resource "aws_kms_key" "acp" {
  description             = "${local.name}: database and secret encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "acp" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.acp.key_id
}

# ------------------------------------------------------------------ database
# Registry, desired state, deployment status, kill switches, leader lease and
# the per-replica audit chains all live here.

resource "aws_db_subnet_group" "acp" {
  name       = local.name
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "db" {
  name        = "${local.name}-db"
  description = "PostgreSQL access from the EKS cluster only"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_cluster" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = var.cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "EKS nodes"
}

resource "aws_db_parameter_group" "acp" {
  name   = local.name
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
}

resource "random_password" "db" {
  length  = 40
  special = false
}

resource "aws_db_instance" "acp" {
  identifier                          = local.name
  engine                              = "postgres"
  engine_version                      = "16.4"
  instance_class                      = var.db_instance_class
  allocated_storage                   = var.db_allocated_storage_gb
  max_allocated_storage               = var.db_allocated_storage_gb * 4
  storage_type                        = "gp3"
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.acp.arn
  db_name                             = "acp"
  username                            = "acp"
  password                            = random_password.db.result
  db_subnet_group_name                = aws_db_subnet_group.acp.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  parameter_group_name                = aws_db_parameter_group.acp.name
  multi_az                            = true
  publicly_accessible                 = false
  backup_retention_period             = 14
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${local.name}-final"
  copy_tags_to_snapshot               = true
  auto_minor_version_upgrade          = true
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.acp.arn
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}

resource "aws_secretsmanager_secret" "database_url" {
  name       = "${local.name}-database-url"
  kms_key_id = aws_kms_key.acp.arn
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = format(
    "postgresql+asyncpg://acp:%s@%s:%d/acp?ssl=require",
    random_password.db.result, aws_db_instance.acp.address, aws_db_instance.acp.port,
  )
}
