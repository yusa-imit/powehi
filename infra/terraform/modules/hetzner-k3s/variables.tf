variable "cluster_name" {
  description = "Unique name prefix for all resources in this cluster."
  type        = string
}

variable "location" {
  description = "Hetzner Cloud location. nbg1 = Nuremberg (EU-West)."
  type        = string
  default     = "nbg1"
}

variable "control_plane_count" {
  description = "Number of k3s control-plane nodes. Use 1 for dev, 3 for HA prod."
  type        = number
  default     = 1

  validation {
    condition     = contains([1, 3], var.control_plane_count)
    error_message = "control_plane_count must be 1 (single) or 3 (HA)."
  }
}

variable "worker_count" {
  description = "Number of k3s worker nodes."
  type        = number
  default     = 1

  validation {
    condition     = var.worker_count >= 1
    error_message = "worker_count must be at least 1."
  }
}

variable "control_plane_server_type" {
  description = "Hetzner server type for control-plane nodes (e.g. cx21, cx41)."
  type        = string
  default     = "cx21"
}

variable "worker_server_type" {
  description = "Hetzner server type for worker nodes (e.g. cx21, cx41)."
  type        = string
  default     = "cx21"
}

variable "image" {
  description = "OS image for all nodes."
  type        = string
  default     = "ubuntu-22.04"
}

variable "ssh_key_name" {
  description = "Name of an existing Hetzner Cloud SSH key to inject into nodes."
  type        = string
  default     = ""
}

variable "k3s_version" {
  description = "k3s version string passed to the install script (e.g. v1.29.4+k3s1). Empty string = latest."
  type        = string
  default     = ""
}

variable "extra_tags" {
  description = "Additional labels applied to every hcloud_server resource."
  type        = map(string)
  default     = {}
}
