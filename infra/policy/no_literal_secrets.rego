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

# Container env[].value entries that look like credentials, for any
# is_workload_like resource. Complements the Secret-object check above: an
# operator could just as easily paste a real credential straight into a
# Deployment's `env: - value:` (bypassing ExternalSecret entirely) instead of
# into a Secret's data/stringData — the first check above would never see
# it, since it only inspects `kind: Secret` documents. This chart renders no
# such env entry today (every credential-bearing var is delivered via
# envFrom.secretRef pointing at the ExternalSecret-managed Secret, confirmed
# via `helm template` returning zero `env[].value` entries across all 3 real
# overlays) — pure future-regression guard, same status as check (c)'s
# Secret-object rule above.
deny contains msg if {
	some resource in all_resources
	is_workload_like(resource)
	some container in containers_of(resource)
	some env in object.get(container, "env", [])
	is_credential_looking_env(env)
	msg := sprintf(
		"%s/%s: container %q env var %q looks like a literal credential — secrets must be delivered via envFrom.secretRef (ExternalSecret), never inlined as env[].value",
		[resource.kind, resource.metadata.name, container.name, env.name],
	)
}

# A credential-shaped env entry: either the variable's own name suggests it
# holds a secret (password/token/api-key/...) and it carries any non-empty
# literal value, or the value itself is shaped like a credential regardless
# of the name (e.g. a connection string with embedded user:pass@, an AWS
# access key ID, a PEM block) — catches the DATABASE_URL=postgres://u:pw123@
# db/x case, where the var name alone gives no signal. Deliberately broad on
# both sides (name substrings like "token"/"secret" and any "-----BEGIN...."
# block, not just private-key ones) — a security gate should err toward
# false positives over silently letting a real credential through; a
# non-secret PEM cert or a config field merely named "*_token" is a cheap
# false positive to accept, once this rule ever has anything real to check
# (this chart renders zero env[].value entries today — see caller comment).
is_credential_looking_env(env) if {
	is_string(object.get(env, "value", null))
	trim_space(env.value) != ""
	credential_name_pattern(env.name)
}

is_credential_looking_env(env) if {
	is_string(object.get(env, "value", null))
	credential_value_pattern(env.value)
}

credential_name_pattern(name) if {
	regex.match(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)`, name)
}

credential_value_pattern(value) if {
	regex.match(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/]+:[^\s/@]+@`, value)
}

credential_value_pattern(value) if {
	regex.match(`AKIA[0-9A-Z]{16}`, value)
}

credential_value_pattern(value) if {
	contains(value, "-----BEGIN")
}
