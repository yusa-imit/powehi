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

test_credential_value_pattern_matches_pem_private_key_block if {
	credential_value_pattern("-----BEGIN PRIVATE KEY-----\nMIIB...")
}

test_credential_value_pattern_false_for_ordinary_url if {
	not credential_value_pattern("https://example.com/health")
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
