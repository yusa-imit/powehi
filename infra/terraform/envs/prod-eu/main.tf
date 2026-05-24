# ---------------------------------------------------------------------------
# Powehi — prod-eu environment
#
# Sizing: 3 control-plane (cx41, HA) + 3 workers (cx41)
# Location: nbg1 (Nuremberg, EU-West)
# ---------------------------------------------------------------------------

module "k3s" {
  source = "../../modules/hetzner-k3s"

  cluster_name              = var.cluster_name
  location                  = var.location
  control_plane_count       = var.control_plane_count
  worker_count              = var.worker_count
  control_plane_server_type = "cx41"
  worker_server_type        = "cx41"
  image                     = "ubuntu-22.04"
  ssh_key_name              = var.ssh_key_name
  k3s_version               = var.k3s_version

  extra_tags = {
    environment = "prod"
    project     = "powehi"
  }
}
