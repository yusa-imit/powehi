# ---------------------------------------------------------------------------
# Powehi — Cloudflare DNS stubs (Phase 1 skeleton)
#
# Records managed here:
#   api.powehi.app   A      → var.api_origin_ip  (origin: Hetzner k3s LB)
#   *.powehi.app     CNAME  → api.powehi.app     (wildcard, proxied)
#
# WAF rules: not disabled.  Any future WAF rule bypass MUST include a comment
# referencing the rule ID and a documented reason.
# ---------------------------------------------------------------------------

# Lookup: if zone_id is provided we reference it directly; no data source
# lookup needed (avoids needing a working token at plan time for the skeleton).

resource "cloudflare_record" "api_a" {
  zone_id = var.cloudflare_zone_id
  name    = "api"
  type    = "A"
  value   = var.api_origin_ip
  proxied = var.proxied
  ttl     = 1 # 1 = automatic when proxied = true

  comment = "Powehi API origin — managed by Terraform"
}

resource "cloudflare_record" "wildcard_cname" {
  zone_id = var.cloudflare_zone_id
  name    = "*"
  type    = "CNAME"
  value   = "api.powehi.app"
  proxied = var.proxied
  ttl     = 1 # 1 = automatic when proxied = true

  comment = "Wildcard → api.powehi.app — managed by Terraform"
}
