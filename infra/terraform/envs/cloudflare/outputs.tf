output "api_record_hostname" {
  description = "Fully-qualified hostname of the api A record."
  value       = cloudflare_record.api_a.hostname
}

output "wildcard_record_hostname" {
  description = "Fully-qualified hostname of the wildcard CNAME record."
  value       = cloudflare_record.wildcard_cname.hostname
}

output "zone_id" {
  description = "Cloudflare Zone ID in use."
  value       = var.cloudflare_zone_id
  # zone_id is not a secret (it is visible in the Cloudflare dashboard URL),
  # but we do NOT output the api_token — secrets are never output.
}
