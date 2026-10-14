output "database_url_secret_name" {
  description = "Secrets Manager secret synced to Kubernetes as DATABASE_URL"
  value       = aws_secretsmanager_secret.database_url.name
}

output "kms_key_arn" {
  description = "KMS key encrypting the database and secrets; use it for the signing-key secrets"
  value       = aws_kms_key.acp.arn
}

output "database_endpoint" {
  description = "PostgreSQL endpoint (Multi-AZ)"
  value       = aws_db_instance.acp.address
}
