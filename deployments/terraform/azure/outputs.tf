output "key_vault_uri" {
  description = "Key Vault holding the database URL, signing keys and the fabric client secret"
  value       = azurerm_key_vault.acp.vault_uri
}

output "database_fqdn" {
  description = "PostgreSQL Flexible Server (zone-redundant HA) private FQDN"
  value       = azurerm_postgresql_flexible_server.acp.fqdn
}
