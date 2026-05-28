# ---------------------------------------------------------------------------
# Powehi — prod-ap-seoul environment
#
# Sizing: 3 control-plane (cx41, HA) + 3 workers (cx41)
# Location: sin1 (Hetzner Singapore — closest available DC to Korea)
#
# PIPA DATA RESIDENCY NOTE: Hetzner does not operate a Korean datacenter.
# sin1 (Singapore) is the interim AP Tier 1 location for staging and dev.
# Real Korean user data (OPAQUE envelopes, device keys, identity) MUST NOT
# be stored here for PIPA-compliant production until a Korean DC is available.
# Block production KR user registration via feature flag until then.
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
    region      = "ap-seoul"
    project     = "powehi"
  }
}
