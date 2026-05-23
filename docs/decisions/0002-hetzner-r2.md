# ADR-0002: Hetzner Cloud + Cloudflare R2

## Status: Accepted

## Context
Need hosting infrastructure for backend services and blob storage for encrypted media.

## Decision
- Compute: Hetzner Cloud (Frankfurt, ARM64 CAX21 nodes, k3s)
- CDN/WAF: Cloudflare
- Blob storage: Cloudflare R2 (S3-compatible, no egress fees)
- DNS: Cloudflare

## Rationale
- **Cost**: Hetzner ARM64 nodes are ~70% cheaper than equivalent AWS/GCP instances
- **Data sovereignty**: Frankfurt datacenter, EU jurisdiction
- **R2 economics**: Zero egress fees for encrypted media delivery
- **Simplicity**: k3s over full k8s reduces operational overhead for solo developer
- **Cloudflare WAF**: DDoS protection included, reduces attack surface

## Consequences
- Less managed service ecosystem than AWS (more DIY)
- Must handle k3s upgrades manually
- Terraform provider less mature than AWS provider
- R2 API compatibility may have edge cases vs S3
