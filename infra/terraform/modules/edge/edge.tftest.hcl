mock_provider "cloudflare" {
  mock_data "cloudflare_zone" {
    defaults = {
      zone_id = "0123456789abcdef0123456789abcdef"
    }
  }
  mock_data "cloudflare_api_token_permission_groups_list" {
    defaults = {
      result = [
        { id = "perm-read", name = "Workers R2 Storage Bucket Item Read", category = "r2", is_selectable = true, scopes = ["com.cloudflare.edge.r2.bucket"] },
        { id = "perm-write", name = "Workers R2 Storage Bucket Item Write", category = "r2", is_selectable = true, scopes = ["com.cloudflare.edge.r2.bucket"] },
        { id = "perm-acct-read", name = "Workers R2 Storage Read", category = "r2", is_selectable = true, scopes = ["com.cloudflare.api.account"] },
        { id = "perm-acct-write", name = "Workers R2 Storage Write", category = "r2", is_selectable = true, scopes = ["com.cloudflare.api.account"] },
      ]
    }
  }
  mock_resource "cloudflare_zero_trust_tunnel_cloudflared" {
    defaults = {
      id = "11111111-2222-3333-4444-555555555555"
    }
  }
  mock_resource "cloudflare_api_token" {
    defaults = {
      id    = "tokenid0123"
      value = "mock-token-value"
    }
  }
}

variables {
  name_prefix           = "powehi-staging"
  domain                = "test.invalid"
  api_hostname          = "api-staging.test.invalid"
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
  manage_zone           = true
  create_r2_token       = true
}

run "tls_is_1_3_only_and_https_strict" {
  command = apply

  assert {
    condition     = cloudflare_zone_setting.this["min_tls_version"].value == "1.3" && cloudflare_zone_setting.this["min_tls_version"].setting_id == "min_tls_version"
    error_message = "Minimum TLS version must be 1.3."
  }

  assert {
    condition     = cloudflare_zone_setting.this["tls_1_3"].value == "on" && cloudflare_zone_setting.this["always_use_https"].value == "on" && cloudflare_zone_setting.this["ssl"].value == "strict"
    error_message = "TLS 1.3 on, always-HTTPS on and ssl strict are required."
  }
}

run "zone_singletons_exist_only_when_manage_zone" {
  command = apply

  variables {
    manage_zone = false
  }

  assert {
    condition     = length(cloudflare_zone_setting.this) == 0 && length(cloudflare_ruleset.managed) == 0 && length(cloudflare_ruleset.auth_rate_limit) == 0
    error_message = "With manage_zone = false no zone setting or zone ruleset may be created."
  }

  assert {
    condition     = cloudflare_dns_record.api.proxied && cloudflare_r2_bucket.media.location == "apac"
    error_message = "Tunnel CNAME and bucket are per-env and stay present."
  }
}

run "zone_singletons_present_when_manage_zone" {
  command = apply

  assert {
    condition     = length(cloudflare_zone_setting.this) == 4 && length(cloudflare_ruleset.managed) == 1 && length(cloudflare_ruleset.auth_rate_limit) == 1
    error_message = "With manage_zone = true the settings and both rulesets exist."
  }
}

run "r2_bucket_is_apac_private_and_token_is_bucket_scoped" {
  command = apply

  assert {
    condition     = cloudflare_r2_bucket.media.location == "apac" && cloudflare_r2_bucket.media.name == "powehi-staging-media"
    error_message = "Media bucket must be named <prefix>-media with location hint apac."
  }

  assert {
    # No custom domain or public (r2.dev) resource may exist: the module only declares the
    # bucket itself, and the token resource below is the only way in.
    condition     = length(regexall("cloudflare_r2_(custom_domain|managed_domain)", file("${path.module}/main.tf"))) == 0
    error_message = "The bucket must have no public access (no custom or managed domain)."
  }

  assert {
    condition     = length(cloudflare_api_token.r2_media[0].policies) == 1 && length(regexall("r2\\.bucket\\.${var.cloudflare_account_id}_default_powehi-staging-media\"", cloudflare_api_token.r2_media[0].policies[0].resources)) == 1 && !strcontains(cloudflare_api_token.r2_media[0].policies[0].resources, "r2.bucket.*")
    error_message = "The R2 token must be scoped to the media bucket only."
  }

  assert {
    condition     = toset([for g in cloudflare_api_token.r2_media[0].policies[0].permission_groups : g.id]) == toset(["perm-read", "perm-write"])
    error_message = "The R2 token must have bucket item read and write only."
  }

  assert {
    condition     = length(setintersection(toset([for g in cloudflare_api_token.r2_media[0].policies[0].permission_groups : g.id]), toset(["perm-acct-read", "perm-acct-write"]))) == 0
    error_message = "Account-wide Workers R2 Storage Read/Write groups must not be used."
  }

  assert {
    condition     = output.r2_endpoint == "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com" && output.r2_bucket == "powehi-staging-media"
    error_message = "S3 endpoint and bucket outputs must match the account and bucket."
  }
}

run "r2_token_is_optional_and_can_be_restricted" {
  command = apply

  variables {
    create_r2_token        = false
    r2_token_allowed_cidrs = ["198.51.100.7/32"]
  }

  assert {
    condition     = length(cloudflare_api_token.r2_media) == 0 && output.r2_access_key_id == null
    error_message = "With create_r2_token = false only the bucket exists."
  }
}

run "r2_token_ip_condition_and_expiry" {
  command = apply

  variables {
    r2_token_allowed_cidrs = ["198.51.100.7/32"]
    r2_token_expires_on    = "2030-01-01T00:00:00Z"
  }

  assert {
    condition     = cloudflare_api_token.r2_media[0].condition.request_ip.in == tolist(["198.51.100.7/32"]) && cloudflare_api_token.r2_media[0].expires_on == "2030-01-01T00:00:00Z"
    error_message = "The CIDR condition and expiry must reach the token."
  }
}

run "auth_endpoints_are_rate_limited_and_waf_deployed" {
  command = apply

  assert {
    condition     = cloudflare_ruleset.auth_rate_limit[0].phase == "http_ratelimit" && length(cloudflare_ruleset.auth_rate_limit[0].rules) == 1
    error_message = "Exactly one rate-limit rule is expected (plan limit)."
  }

  assert {
    condition     = alltrue([for p in ["/v1/auth/register/init", "/v1/auth/register/finish", "/v1/auth/login/init", "/v1/auth/login/finish"] : strcontains(cloudflare_ruleset.auth_rate_limit[0].rules[0].expression, p)])
    error_message = "The rate limit must cover register and login init/finish."
  }

  assert {
    condition     = !strcontains(cloudflare_ruleset.auth_rate_limit[0].rules[0].expression, "http.host") && !strcontains(cloudflare_ruleset.auth_rate_limit[0].rules[0].expression, "method")
    error_message = "The expression is path-only (Free plan) so it covers both env hosts."
  }

  assert {
    condition     = cloudflare_ruleset.auth_rate_limit[0].rules[0].ratelimit.period == 10 && contains(cloudflare_ruleset.auth_rate_limit[0].rules[0].ratelimit.characteristics, "ip.src")
    error_message = "Rate limit is per IP over the 10 s period allowed on the free plan."
  }

  assert {
    condition     = cloudflare_ruleset.managed[0].phase == "http_request_firewall_managed" && cloudflare_ruleset.managed[0].rules[0].action == "execute"
    error_message = "A managed ruleset must be deployed."
  }
}

run "tunnel_routes_the_api_hostname_and_nothing_else" {
  command = apply

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared.this.config_src == "cloudflare"
    error_message = "The tunnel must be remotely managed."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress[0].hostname == var.api_hostname && cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress[0].service == "http://localhost:8080" && cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress[1].service == "http_status:404"
    error_message = "Ingress must route api_hostname to the origin port and 404 everything else."
  }

  assert {
    condition     = cloudflare_dns_record.api.proxied && cloudflare_dns_record.api.type == "CNAME" && cloudflare_dns_record.api.name == var.api_hostname && cloudflare_dns_record.api.content == "11111111-2222-3333-4444-555555555555.cfargotunnel.com"
    error_message = "The API record must be a proxied CNAME to the tunnel."
  }
}

run "no_domain_is_hard_coded" {
  command = plan

  variables {
    domain       = "other.invalid"
    api_hostname = "api.other.invalid"
  }

  assert {
    condition     = cloudflare_dns_record.api.name == "api.other.invalid" && cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress[0].hostname == "api.other.invalid"
    error_message = "Every hostname must derive from the variables."
  }

  assert {
    condition     = length(regexall("[a-z0-9-]+\\.(com|net|org|io|app|dev)\"", replace(file("${path.module}/main.tf"), "cfargotunnel.com", "tunnel-suffix"))) == 0
    error_message = "No literal domain may appear in the module."
  }
}

run "explicit_zone_id_skips_the_lookup" {
  command = plan

  variables {
    zone_id = "fedcba9876543210fedcba9876543210"
  }

  assert {
    condition     = length(data.cloudflare_zone.this) == 0 && local.zone_id == "fedcba9876543210fedcba9876543210"
    error_message = "zone_id must replace the zone data source"
  }
}
