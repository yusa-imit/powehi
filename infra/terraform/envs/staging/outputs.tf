output "name_prefix" {
  description = "Resource name prefix the deploy role is scoped to."
  value       = local.name_prefix
}

output "api_hostname" {
  description = "Public API hostname served by Cloudflare."
  value       = module.edge.api_hostname
}

output "tunnel_id" {
  description = "Cloudflare Tunnel ID (fetch its token out of band, see README)."
  value       = module.edge.tunnel_id
}

output "r2_endpoint" {
  description = "R2 S3 endpoint (POWEHI__R2_ENDPOINT)."
  value       = module.edge.r2_endpoint
}

output "r2_bucket" {
  description = "R2 media bucket (POWEHI__R2_BUCKET)."
  value       = module.edge.r2_bucket
}

output "r2_access_key_id" {
  description = "R2 S3 access key ID (POWEHI__R2_ACCESS_KEY_ID); null unless create_r2_token."
  value       = module.edge.r2_access_key_id
}

output "r2_secret_access_key" {
  description = "R2 S3 secret key (POWEHI__R2_SECRET_ACCESS_KEY); null unless create_r2_token. Copy to Secrets Manager out of band."
  value       = module.edge.r2_secret_access_key
  sensitive   = true
}

output "ecs_cluster_name" {
  description = "ECS cluster (deploy workflow, 9.8)."
  value       = module.service.cluster_name
}

output "ecs_service_name" {
  description = "ECS service (deploy workflow, 9.8)."
  value       = module.service.service_name
}
