# Mapping to the server settings (passed via Secrets Manager out of band, never in tfvars):
#   r2_endpoint                -> POWEHI__R2_ENDPOINT
#   r2_bucket                  -> POWEHI__R2_BUCKET
#   r2_access_key_id           -> POWEHI__R2_ACCESS_KEY_ID      (the API token id; only if create_r2_token)
#   r2_secret_access_key       -> POWEHI__R2_SECRET_ACCESS_KEY  (sha256 of the token value)
# The sensitive outputs are redacted in plan output; the owner copies them into Secrets
# Manager (see infra/terraform/README.md). The tunnel token is not an output; see README.

output "r2_endpoint" {
  description = "S3 API endpoint of the account (POWEHI__R2_ENDPOINT)."
  value       = "https://${var.cloudflare_account_id}.r2.cloudflarestorage.com"
}

output "r2_bucket" {
  description = "Media bucket name (POWEHI__R2_BUCKET)."
  value       = cloudflare_r2_bucket.media.name
}

output "r2_access_key_id" {
  description = "S3 access key ID of the bucket-scoped token (POWEHI__R2_ACCESS_KEY_ID); null when create_r2_token is false."
  value       = one(cloudflare_api_token.r2_media[*].id)
}

output "r2_secret_access_key" {
  description = "S3 secret access key (POWEHI__R2_SECRET_ACCESS_KEY), sha256 of the token value; null when create_r2_token is false."
  value       = one(cloudflare_api_token.r2_media[*].value) == null ? null : sha256(one(cloudflare_api_token.r2_media[*].value))
  sensitive   = true
}

output "tunnel_id" {
  description = "Cloudflare Tunnel ID."
  value       = cloudflare_zero_trust_tunnel_cloudflared.this.id
}

output "api_hostname" {
  description = "Public API hostname served through the tunnel."
  value       = cloudflare_dns_record.api.name
}
