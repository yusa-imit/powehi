variable "hcloud_token" {
  description = "Hetzner Cloud API token. Supply via TF_VAR_hcloud_token — never hardcode."
  type        = string
  sensitive   = true
  default     = ""
}

variable "cluster_name" {
  description = "Name prefix for all cluster resources in this environment."
  type        = string
  default     = "powehi-dev"
}

variable "location" {
  description = "Hetzner Cloud location."
  type        = string
  default     = "nbg1"
}

variable "ssh_key_name" {
  description = "Name of a pre-existing Hetzner Cloud SSH key to inject (optional)."
  type        = string
  default     = ""
}

variable "k3s_version" {
  description = "Pinned k3s version (e.g. v1.29.4+k3s1). Empty = latest."
  type        = string
  default     = ""
}
