# Check (c): no literal secret values in any rendered Secret object.
#
# Secrets must flow through the external-secrets-operator (ExternalSecret
# CRD referencing remote key paths), never as inline `data`/`stringData`
# string values baked into a rendered Secret manifest
# (helm-conventions.md: "never hardcode secrets"). This is a real check: it
# inspects every `kind: Secret` document for non-empty `data`/`stringData`
# entries and currently passes vacuously only because this chart renders no
# such object (secrets are materialized by the external-secrets-operator,
# not by Helm) — it is not a hardcoded no-op.
package main

import rego.v1

secret_string_fields := {"data", "stringData"}

deny contains msg if {
	some resource in all_resources
	resource.kind == "Secret"
	some field in secret_string_fields
	some key, value in object.get(resource, field, {})
	is_literal_secret_value(value)
	msg := sprintf(
		"Secret/%s: field %q key %q contains a literal secret value — secrets must be delivered via ExternalSecret, never inlined in a rendered Secret manifest",
		[resource.metadata.name, field, key],
	)
}

is_literal_secret_value(value) if {
	is_string(value)
	trim_space(value) != ""
}
