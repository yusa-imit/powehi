output "cluster_endpoint" {
  description = "k3s API server endpoint."
  value       = module.k3s.cluster_endpoint
}

output "control_plane_ips" {
  description = "Public IPs of control-plane nodes."
  value       = module.k3s.control_plane_ips
}

output "worker_ips" {
  description = "Public IPs of worker nodes."
  value       = module.k3s.worker_ips
}
