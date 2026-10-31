output "name_prefix" {
  description = "Resource name prefix the deploy role is scoped to."
  value       = local.name_prefix
}

output "api_hostname" {
  description = "Public API hostname served by Cloudflare."
  value       = local.api_hostname
}
