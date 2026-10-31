# Cloudflare edge for one env (ADR-0007): zone TLS settings, a Tunnel to the ECS task, WAF,
# and the R2 media bucket. Auth comes from CLOUDFLARE_API_TOKEN in the environment (never a
# variable or tfvars). Resources hold only ciphertext (R2) or no content at all (edge).

# Skipped when zone_id is given (the PR plan job has no Cloudflare credentials, so it cannot look it up).
data "cloudflare_zone" "this" {
  count = var.zone_id == null ? 1 : 0

  filter = {
    name    = var.domain
    account = { id = var.cloudflare_account_id }
  }
}

locals {
  zone_id = coalesce(var.zone_id, one(data.cloudflare_zone.this[*].zone_id))
}

# --- TLS (re-creates the 8.1 edge setting) ------------------------------------------------

# Zone singletons (settings, zone-level WAF rulesets) exist once per zone, but staging and
# prod share one zone. Exactly one stack owns them: staging passes manage_zone = true (it is
# applied first and the settings are zone-wide), prod false. Otherwise two states would fight
# over the same settings and rulesets. Staging's edge must never be destroyed while prod runs.
resource "cloudflare_zone_setting" "this" {
  for_each = var.manage_zone ? {
    min_tls_version  = "1.3"
    tls_1_3          = "on"
    always_use_https = "on"
    ssl              = "strict"
  } : {}

  zone_id    = local.zone_id
  setting_id = each.key
  value      = each.value
}

# --- Tunnel: api_hostname -> task (cloudflared sidecar, 9.5) -------------------------------

resource "cloudflare_zero_trust_tunnel_cloudflared" "this" {
  account_id = var.cloudflare_account_id
  name       = "${var.name_prefix}-api"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "this" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.this.id

  config = {
    ingress = [
      {
        hostname = var.api_hostname
        service  = "http://localhost:${var.origin_port}"
      },
      { service = "http_status:404" },
    ]
  }
}

resource "cloudflare_dns_record" "api" {
  zone_id = local.zone_id
  name    = var.api_hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.this.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1 # automatic; required for proxied records
}

# No tunnel secret is managed here: tunnel_secret is omitted (the server generates it) and
# the run-token data source is deliberately NOT used, so no tunnel credential lands in state.
# The owner fetches the token out of band (`cloudflared tunnel token <id>`, the dashboard or
# the API) into Secrets Manager for the 9.5 sidecar.

# --- WAF ----------------------------------------------------------------------------------
# Only the stack with manage_zone = true (staging) creates these (zone-wide, shared by both
# envs). If the zone already has a firewall_managed / ratelimit entrypoint ruleset, import it
# before apply; never delete it.
# Plan assumptions (free/pro): one managed-ruleset execute rule, one rate-limit rule with a
# 10 s period and 10 s mitigation, counted per IP. No managed rule is ever disabled here;
# overriding one needs a documented reason in this file.

resource "cloudflare_ruleset" "managed" {
  count = var.manage_zone ? 1 : 0

  zone_id     = local.zone_id
  name        = "${var.name_prefix}-managed-waf"
  description = "Deploy the Cloudflare managed ruleset"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules = [{
    action      = "execute"
    description = "Managed ruleset"
    expression  = "true"
    enabled     = true
    action_parameters = {
      id = var.managed_ruleset_id
    }
  }]
}

locals {
  auth_path_set = join(" ", [for p in var.auth_paths : "\"${p}\""])
}

# Path-only expression: the Free plan allows only the path field, and the rule must cover
# both env hostnames. The server routes these paths POST-only, so no method match is needed.
resource "cloudflare_ruleset" "auth_rate_limit" {
  count = var.manage_zone ? 1 : 0

  zone_id     = local.zone_id
  name        = "${var.name_prefix}-auth-rate-limit"
  description = "Throttle OPAQUE register/login (online guessing, enumeration)"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [{
    action      = "block"
    description = "Auth endpoints per-IP limit"
    enabled     = true
    expression  = "http.request.uri.path in {${local.auth_path_set}}"
    ratelimit = {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = 10
      requests_per_period = var.auth_rate_limit_requests
      mitigation_timeout  = 10
    }
  }]
}

# --- R2 media bucket (ciphertext only) ----------------------------------------------------
# No public access: no r2.dev managed domain and no custom domain are created. The server
# reaches it over the S3 API with the bucket-scoped token below.

resource "cloudflare_r2_bucket" "media" {
  account_id = var.cloudflare_account_id
  name       = "${var.name_prefix}-media"
  location   = "apac"

  # No lifecycle.prevent_destroy: it makes `tofu test` fail while tearing down the test
  # resources. R2 refuses to delete a non-empty bucket, which protects stored ciphertext;
  # the plan review (9.7) must still flag any destroy/replace of this bucket.
}

# The bucket-scoped token needs the account permission "API Tokens Edit", which the CI deploy
# token should not hold. Default is therefore create_r2_token = false: the owner mints the
# per-env bucket-scoped token once out of band and passes it via Secrets Manager. With true
# (owner-run apply only) the module creates it; the token value then sits in state (KMS
# encrypted), and staging state is readable by the PR plan role: accepted risk, see README.
data "cloudflare_api_token_permission_groups_list" "r2" {
  count = var.create_r2_token ? 1 : 0

  scope = "com.cloudflare.edge.r2.bucket"
}

locals {
  r2_perm_ids = var.create_r2_token ? {
    for g in data.cloudflare_api_token_permission_groups_list.r2[0].result : g.name => g.id
  } : {}
}

resource "cloudflare_api_token" "r2_media" {
  count = var.create_r2_token ? 1 : 0

  name       = "${var.name_prefix}-r2-media"
  expires_on = var.r2_token_expires_on

  condition = length(var.r2_token_allowed_cidrs) > 0 ? {
    request_ip = { in = var.r2_token_allowed_cidrs }
  } : null

  policies = [{
    effect = "allow"
    permission_groups = [
      { id = local.r2_perm_ids["Workers R2 Storage Bucket Item Read"] },
      { id = local.r2_perm_ids["Workers R2 Storage Bucket Item Write"] },
    ]
    resources = jsonencode({
      "com.cloudflare.edge.r2.bucket.${var.cloudflare_account_id}_default_${cloudflare_r2_bucket.media.name}" = "*"
    })
  }]
}
