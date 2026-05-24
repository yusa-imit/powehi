output "control_plane_ips" {
  description = "Public IPv4 addresses of all control-plane nodes."
  value       = hcloud_server.control_plane[*].ipv4_address
}

output "worker_ips" {
  description = "Public IPv4 addresses of all worker nodes."
  value       = hcloud_server.worker[*].ipv4_address
}

output "cluster_endpoint" {
  # Phase 1 skeleton: points at cp-0's public IP. For HA prod (control_plane_count=3)
  # replace this with a Hetzner floating-IP or load-balancer address before applying.
  description = "k3s API server endpoint. Single-node: cp-0 IP. HA: replace with LB/floating-IP."
  value       = "https://${hcloud_server.control_plane[0].ipv4_address}:6443"
}

output "node_ids" {
  description = "Hetzner server IDs for all cluster nodes (control-plane + workers)."
  value = concat(
    hcloud_server.control_plane[*].id,
    hcloud_server.worker[*].id,
  )
}
