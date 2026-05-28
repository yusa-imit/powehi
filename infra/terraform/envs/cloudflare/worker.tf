# ---------------------------------------------------------------------------
# Powehi — Cloudflare Workers smart-router infrastructure
#
# Manages:
#   - KV namespace for region health state (written by k6 synthetic monitors)
#   - Worker route: api.powehi.app/* → powehi-smart-router Worker
#
# The Worker script itself is deployed via `wrangler deploy` (not Terraform).
# Wrangler reads wrangler.toml at infra/cloudflare/workers/smart-router/.
# After `tofu apply`, copy cloudflare_workers_kv_namespace.region_health.id
# into wrangler.toml kv_namespaces[].id before deploying the Worker.
# ---------------------------------------------------------------------------

# ── KV namespace for region health state ────────────────────────────────────
#
# Keys written by the k6 synthetic monitor (infra/synthetic/cross-region-p99.js):
#   health:eu  →  "healthy" | "unhealthy"
#   health:ap  →  "healthy" | "unhealthy"
# TTL: monitor writes every 10 min; Worker treats absent key as "healthy" (fail-open).

resource "cloudflare_workers_kv_namespace" "region_health" {
  account_id = var.cloudflare_account_id
  title      = "powehi-region-health"
}

# ── Worker route: api.powehi.app/* → powehi-smart-router ────────────────────
#
# The route forwards all traffic through the smart-router Worker before it
# reaches the origin A-record (api.powehi.app → EU origin).
# The Worker rewrites the upstream based on geographic routing + health state.

resource "cloudflare_workers_route" "smart_router_main" {
  zone_id = var.cloudflare_zone_id
  pattern = "api.powehi.app/*"
  # script_name removed in provider v5 — Worker↔route binding is managed by wrangler deploy
  # via routes[] in wrangler.toml (infra/cloudflare/workers/smart-router/wrangler.toml).
}
