# ---------------------------------------------------------------------------
# Powehi — dev environment
#
# Sizing: 1 control-plane (cx21) + 1 worker (cx21)
# Location: nbg1 (Nuremberg, EU-West)
# ---------------------------------------------------------------------------

module "k3s" {
  source = "../../modules/hetzner-k3s"

  cluster_name              = var.cluster_name
  location                  = var.location
  control_plane_count       = 1
  worker_count              = 1
  control_plane_server_type = "cx21"
  worker_server_type        = "cx21"
  image                     = "ubuntu-22.04"
  ssh_key_name              = var.ssh_key_name
  k3s_version               = var.k3s_version

  extra_tags = {
    environment = "dev"
    project     = "powehi"
  }
}
