# Regression tests for no_literal_secrets.rego (check c).
package main

import rego.v1

test_is_literal_secret_value_true_for_nonempty_string if {
	is_literal_secret_value("hunter2")
}

test_is_literal_secret_value_false_for_empty_string if {
	not is_literal_secret_value("")
}

test_is_literal_secret_value_false_for_whitespace_only if {
	not is_literal_secret_value("   ")
}

test_deny_fires_for_literal_stringdata_value if {
	resource := {
		"kind": "Secret",
		"metadata": {"name": "db-creds"},
		"stringData": {"DATABASE_URL": "postgres://u:pw123@db/x"},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal secret value")
}

test_deny_fires_for_literal_data_value if {
	resource := {
		"kind": "Secret",
		"metadata": {"name": "db-creds"},
		"data": {"password": "aHVudGVyMg=="},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal secret value")
}

test_deny_absent_for_secret_with_no_string_fields if {
	resource := {"kind": "Secret", "metadata": {"name": "empty"}}
	count(deny) == 0 with input as [{"contents": resource}]
}

test_deny_absent_for_non_secret_resource if {
	resource := {"kind": "ExternalSecret", "metadata": {"name": "db-creds"}, "data": {"password": "hunter2"}}
	count(deny) == 0 with input as [{"contents": resource}]
}

# --- fail-closed resource_name: a resource missing metadata.name must still
# trip the gate, not silently drop the deny (a direct `resource.metadata.name`
# reference is undefined when the key is missing, which fails the whole rule
# body in Rego — this would let the secret escape, not just lose the name).

test_resource_name_falls_back_to_placeholder_when_metadata_missing if {
	resource_name({"kind": "Secret"}) == "<unnamed>"
}

test_resource_name_falls_back_to_placeholder_when_name_missing if {
	resource_name({"kind": "Secret", "metadata": {}}) == "<unnamed>"
}

# `metadata` present but null (not just absent) is a distinct failure mode: a
# naive `object.get(object.get(resource, "metadata", {}), "name", ...)` would
# still dereference `null` on the inner call and reproduce the exact same
# fail-open bug one level down. The path-form `object.get` must handle both.
test_resource_name_falls_back_to_placeholder_when_metadata_is_null if {
	resource_name({"kind": "Secret", "metadata": null}) == "<unnamed>"
}

test_resource_name_returns_real_name_when_present if {
	resource_name({"kind": "Secret", "metadata": {"name": "db-creds"}}) == "db-creds"
}

test_field_name_falls_back_to_placeholder_when_key_missing if {
	field_name({"value": "x"}, "name") == "<unnamed>"
}

test_field_name_returns_real_value_when_present if {
	field_name({"name": "app"}, "name") == "app"
}

test_deny_fires_for_secret_missing_metadata_name if {
	resource := {"kind": "Secret", "stringData": {"DATABASE_URL": "postgres://u:pw123@db/x"}}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal secret value")
}

test_deny_fires_for_deployment_missing_metadata_name_with_credential_env if {
	resource := {
		"kind": "Deployment",
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{"name": "DB_PASSWORD", "value": "hunter2"}],
		}]}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

test_deny_fires_for_configmap_missing_metadata_name_with_credential_entry if {
	resource := {"kind": "ConfigMap", "data": {"DB_PASSWORD": "hunter2"}}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

# A container or env entry missing its own `name` must still trip the gate —
# `container.name`/`env.name` direct references in the msg would otherwise
# silently drop the deny even though `is_credential_looking_env` correctly
# matched (the predicate doesn't require env.name at all).
test_deny_fires_for_container_missing_name_with_credential_env if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {"containers": [{
			"env": [{"name": "DB_PASSWORD", "value": "hunter2"}],
		}]}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

test_deny_fires_for_env_missing_name_with_credential_value if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{"value": "postgres://u:pw123@db/x"}],
		}]}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

# --- container env[].value credential-shaped literal checks ---

test_credential_name_pattern_matches_common_secret_names if {
	credential_name_pattern("DB_PASSWORD")
	credential_name_pattern("api-key")
	credential_name_pattern("PRIVATE_KEY")
	credential_name_pattern("ACCESS_KEY_ID")
	credential_name_pattern("AUTH_TOKEN")
}

test_credential_name_pattern_false_for_unrelated_name if {
	not credential_name_pattern("LOG_LEVEL")
	not credential_name_pattern("REGION_ID")
}

test_credential_value_pattern_matches_connection_string_with_embedded_creds if {
	credential_value_pattern("postgres://u:pw123@db/x")
}

test_credential_value_pattern_matches_aws_access_key_id if {
	credential_value_pattern("AKIAABCDEFGHIJKLMNOP")
}

test_credential_value_pattern_matches_aws_sts_temp_access_key_id if {
	credential_value_pattern("ASIAABCDEFGHIJKLMNOP")
}

test_credential_value_pattern_matches_jwt if {
	credential_value_pattern("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
}

# The pattern must catch a JWT embedded in a larger string, not just a value
# that is nothing BUT the JWT — a "Bearer <jwt>" header value or a multi-line
# ConfigMap block (Helm `|` block scalars keep the trailing newline) are the
# realistic shapes a leaked bearer token actually takes.
test_credential_value_pattern_matches_jwt_with_bearer_prefix if {
	credential_value_pattern("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
}

test_credential_value_pattern_matches_jwt_with_trailing_newline if {
	credential_value_pattern("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\n")
}

# `alg: none` unsigned JWTs render an empty signature segment.
test_credential_value_pattern_matches_jwt_with_empty_signature if {
	credential_value_pattern("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.")
}

# Base64 (as opposed to base64url) padding on the signature segment doesn't
# need its own regex handling — under unanchored `regex.match`, the pattern
# already matches as a substring up to the first `=`, so a padded value still
# matches. This asserts that behavior explicitly rather than just relying on
# it implicitly, since it's easy to assume padding needs an explicit `=*` in
# the pattern (an earlier version of this rule had one; it was dead code).
test_credential_value_pattern_matches_jwt_with_base64_padding if {
	credential_value_pattern("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk==")
}

test_credential_value_pattern_matches_pem_private_key_block if {
	credential_value_pattern("-----BEGIN PRIVATE KEY-----\nMIIB...")
}

test_credential_value_pattern_false_for_ordinary_url if {
	not credential_value_pattern("https://example.com/health")
}

test_credential_value_pattern_false_for_semver if {
	not credential_value_pattern("1.2.3")
}

test_credential_value_pattern_false_for_three_label_hostname if {
	not credential_value_pattern("sub.example.com")
}

test_is_credential_looking_env_true_for_named_secret_with_value if {
	is_credential_looking_env({"name": "DB_PASSWORD", "value": "hunter2"})
}

test_is_credential_looking_env_true_for_embedded_creds_regardless_of_name if {
	is_credential_looking_env({"name": "DATABASE_URL", "value": "postgres://u:pw123@db/x"})
}

test_is_credential_looking_env_false_for_named_secret_with_empty_value if {
	not is_credential_looking_env({"name": "DB_PASSWORD", "value": ""})
}

test_is_credential_looking_env_false_for_valuefrom_secretref if {
	not is_credential_looking_env({"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "password"}}})
}

test_is_credential_looking_env_false_for_ordinary_env if {
	not is_credential_looking_env({"name": "LOG_LEVEL", "value": "info"})
}

test_deny_fires_for_deployment_with_named_credential_env_value if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{"name": "DB_PASSWORD", "value": "hunter2"}],
		}]}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

test_deny_fires_for_deployment_with_embedded_creds_in_unnamed_env_value if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{"name": "DATABASE_URL", "value": "postgres://u:pw123@db/x"}],
		}]}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

# These two fixtures deliberately omit resources.limits/securityContext, so
# a bare `count(deny) == 0` would also (correctly) trip the sibling
# resource_limits/run_as_nonroot checks — that's not what's under test here.
# Scope the assertion to this check's own denial message instead.

test_deny_absent_for_deployment_with_secretref_env if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "password"}}}],
		}]}}},
	}
	not any_credential_deny with input as [{"contents": resource}]
}

test_deny_absent_for_deployment_with_ordinary_env_value if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{"name": "LOG_LEVEL", "value": "info"}],
		}]}}},
	}
	not any_credential_deny with input as [{"contents": resource}]
}

any_credential_deny if {
	some msg in deny
	contains(msg, "literal credential")
}

# --- ConfigMap data credential-shaped literal checks ---

test_is_credential_looking_configmap_entry_true_for_named_secret_key if {
	is_credential_looking_configmap_entry("DB_PASSWORD", "hunter2")
}

test_is_credential_looking_configmap_entry_true_for_embedded_creds_regardless_of_key if {
	is_credential_looking_configmap_entry("DATABASE_URL", "postgres://u:pw123@db/x")
}

test_is_credential_looking_configmap_entry_false_for_named_secret_key_empty_value if {
	not is_credential_looking_configmap_entry("DB_PASSWORD", "")
}

test_is_credential_looking_configmap_entry_false_for_ordinary_entry if {
	not is_credential_looking_configmap_entry("RUST_LOG", "info")
}

test_deny_fires_for_configmap_with_named_credential_key if {
	resource := {
		"kind": "ConfigMap",
		"metadata": {"name": "powehi-config"},
		"data": {"POWEHI__R2_ACCESS_KEY_ID": "hunter2"},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

test_deny_fires_for_configmap_with_embedded_creds_in_unnamed_key if {
	resource := {
		"kind": "ConfigMap",
		"metadata": {"name": "powehi-config"},
		"data": {"POWEHI__DATABASE_URL": "postgres://u:pw123@db/x"},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

test_deny_absent_for_configmap_with_ordinary_entries if {
	resource := {
		"kind": "ConfigMap",
		"metadata": {"name": "powehi-config"},
		"data": {
			"RUST_LOG": "info",
			"POWEHI__REGION_ID": "eu-frankfurt",
			"POWEHI__GRPC_TLS_KEY": "/etc/powehi/tls/tls.key",
			"POWEHI__R2_ENDPOINT": "https://abc.r2.cloudflarestorage.com",
		},
	}
	not any_credential_deny with input as [{"contents": resource}]
}

test_deny_absent_for_non_configmap_resource_with_credential_shaped_data if {
	resource := {"kind": "ExternalSecret", "metadata": {"name": "powehi-config"}, "data": {"password": "hunter2"}}
	not any_credential_deny with input as [{"contents": resource}]
}

test_deny_fires_for_configmap_with_named_credential_key_in_binarydata if {
	resource := {
		"kind": "ConfigMap",
		"metadata": {"name": "powehi-config"},
		"binaryData": {"DB_PASSWORD": "aHVudGVyMg=="},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
}

# Anti-overlap: `any_credential_deny` matches the substring "literal
# credential" that BOTH the env[].value rule and the ConfigMap rule emit —
# assert the ConfigMap-specific wording is what actually fired here, not a
# coincidental match against some other rule's message.
test_deny_message_for_configmap_is_configmap_worded_not_env_worded if {
	resource := {
		"kind": "ConfigMap",
		"metadata": {"name": "powehi-config"},
		"data": {"DB_PASSWORD": "hunter2"},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal credential")
	contains(msg, "never inlined in a ConfigMap")
	not contains(msg, "never inlined as env[].value")
}
