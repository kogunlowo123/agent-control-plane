output "database_url_secret" {
  description = "Secret Manager secret synced to Kubernetes as DATABASE_URL"
  value       = google_secret_manager_secret.database_url.secret_id
}

output "kms_crypto_key" {
  description = "CMEK used by Cloud SQL and Secret Manager; use it for the signing-key secrets"
  value       = google_kms_crypto_key.acp.id
}
