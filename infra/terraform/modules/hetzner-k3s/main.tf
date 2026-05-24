# ---------------------------------------------------------------------------
# hetzner-k3s module — k3s cluster nodes on Hetzner Cloud
#
# Resources created:
#   hcloud_server  — control-plane nodes (k3s server role)
#   hcloud_server  — worker nodes        (k3s agent role)
#
# k3s is installed at first boot via cloud-init user_data.
# The join token is generated locally and stored in Terraform state.
# Protect state files with encryption at rest (SSE) before using in prod.
# ---------------------------------------------------------------------------

locals {
  base_labels = merge(
    {
      managed-by = "terraform"
      cluster    = var.cluster_name
    },
    var.extra_tags,
  )

  # k3s install script respects INSTALL_K3S_VERSION when set.
  k3s_version_line = var.k3s_version != "" ? "INSTALL_K3S_VERSION=${var.k3s_version}" : ""

  # Random join token shared between control-plane and agents.
  k3s_token = random_password.k3s_token.result
}

resource "random_password" "k3s_token" {
  # random_password.result is marked sensitive by the provider, so it appears as
  # (sensitive value) in plan output. However, Terraform embeds it verbatim inside
  # hcloud_server.user_data (not a sensitive attribute), meaning the rendered
  # cloud-init YAML will appear in plan/show output. Mitigation: use an encrypted
  # remote state backend (SSE) before applying to any non-dev environment.
  length  = 48
  special = false
}

# ---------------------------------------------------------------------------
# Control-plane nodes
# ---------------------------------------------------------------------------

resource "hcloud_server" "control_plane" {
  count       = var.control_plane_count
  name        = "${var.cluster_name}-cp-${count.index}"
  server_type = var.control_plane_server_type
  image       = var.image
  location    = var.location
  ssh_keys    = var.ssh_key_name != "" ? [var.ssh_key_name] : []

  labels = merge(local.base_labels, { role = "control-plane" })

  user_data = templatefile("${path.module}/templates/control-plane-init.sh.tpl", {
    index      = count.index
    token      = local.k3s_token
    cluster    = var.cluster_name
    version_env = local.k3s_version_line
  })
}

# ---------------------------------------------------------------------------
# Worker (agent) nodes
# ---------------------------------------------------------------------------

resource "hcloud_server" "worker" {
  count       = var.worker_count
  name        = "${var.cluster_name}-worker-${count.index}"
  server_type = var.worker_server_type
  image       = var.image
  location    = var.location
  ssh_keys    = var.ssh_key_name != "" ? [var.ssh_key_name] : []

  labels = merge(local.base_labels, { role = "worker" })

  user_data = templatefile("${path.module}/templates/worker-init.sh.tpl", {
    cp0_ip      = hcloud_server.control_plane[0].ipv4_address
    token       = local.k3s_token
    version_env = local.k3s_version_line
  })

  depends_on = [hcloud_server.control_plane]
}
