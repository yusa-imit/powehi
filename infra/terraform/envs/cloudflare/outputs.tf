output "api_record_name" {
  description = "Name of the api A record (e.g. api.powehi.app)."
  value       = cloudflare_dns_record.api_a.name
}

output "wildcard_record_name" {
  description = "Name of the wildcard CNAME record."
  value       = cloudflare_dns_record.wildcard_cname.name
}

output "zone_id" {
  description = "Cloudflare Zone ID in use."
  value       = var.cloudflare_zone_id
  # zone_id is not a secret (it is visible in the Cloudflare dashboard URL),
  # but we do NOT output the api_token — secrets are never output.
}

output "region_health_kv_namespace_id" {
  description = "KV namespace ID for region health state. Copy into wrangler.toml kv_namespaces[].id before deploying the smart-router Worker."
  value       = cloudflare_workers_kv_namespace.region_health.id
}

output "smart_router_route_id" {
  description = "ID of the Worker route api.powehi.app/* → powehi-smart-router."
  value       = cloudflare_workers_route.smart_router_main.id
}
