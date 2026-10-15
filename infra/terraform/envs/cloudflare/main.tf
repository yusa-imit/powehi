# ---------------------------------------------------------------------------
# Powehi — Cloudflare DNS stubs
#
# Records managed here:
#   api.powehi.app   A      → var.api_origin_ip  (origin: Hetzner k3s LB)
#   *.powehi.app     CNAME  → api.powehi.app     (wildcard, proxied)
#
# WAF rules: not disabled.  Any future WAF rule bypass MUST include a comment
# referencing the rule ID and a documented reason.
#
# Provider: cloudflare/cloudflare v5 — resource names updated from v4 skeleton:
#   cloudflare_record → cloudflare_dns_record (v5 rename)
#   value             → content                (v5 rename)
# ---------------------------------------------------------------------------

# Lookup: if zone_id is provided we reference it directly; no data source
# lookup needed (avoids needing a working token at plan time for the skeleton).

resource "cloudflare_dns_record" "api_a" {
  zone_id = var.cloudflare_zone_id
  name    = "api"
  type    = "A"
  content = var.api_origin_ip
  proxied = var.proxied
  ttl     = 1 # 1 = automatic when proxied = true

  comment = "Powehi API origin — managed by Terraform"
}

resource "cloudflare_dns_record" "wildcard_cname" {
  zone_id = var.cloudflare_zone_id
  name    = "*"
  type    = "CNAME"
  content = "api.powehi.app"
  proxied = var.proxied
  ttl     = 1 # 1 = automatic when proxied = true

  comment = "Wildcard → api.powehi.app — managed by Terraform"
}

# TLS 1.3 on at the edge (7.11 F11, prd §7A.3). The CLI already speaks TLS 1.3 only; this makes
# the edge negotiate it. `min_tls_version = 1.3` (dropping older web clients) is NOT set here:
# that is a compatibility policy call for the owner.
resource "cloudflare_zone_setting" "tls_1_3" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "tls_1_3"
  value      = "on"
}
