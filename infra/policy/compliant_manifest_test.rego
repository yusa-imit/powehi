# Golden-path integration test: a manifest that satisfies all 5 checks
# (no_literal_secrets.rego's env[].value sub-check included) together must
# render zero denials. This is the regression test for the thing agents
# have so far only verified manually against the real Helm overlays each
# cycle (see .claude/memory/project-context.md) — a future change that
# breaks the "should pass" path for a fully compliant workload now fails
# `conftest verify`, not just a human's memory of a manual check.
package main

import rego.v1

test_fully_compliant_manifest_has_zero_denials if {
	count(deny) == 0 with input as compliant_manifest
}

compliant_manifest := [
	{"contents": {
		"kind": "Deployment",
		"metadata": {"name": "api", "namespace": "default"},
		"spec": {"template": {
			"metadata": {"labels": {"app": "api"}},
			"spec": {
				"securityContext": {"runAsNonRoot": true},
				"containers": [{
					"name": "app",
					"image": "ghcr.io/powehi/api:1.2.3",
					"resources": {
						"limits": {"cpu": "500m", "memory": "256Mi"},
						"requests": {"cpu": "250m", "memory": "128Mi"},
					},
					"env": [{
						"name": "DATABASE_URL",
						"valueFrom": {"secretKeyRef": {"name": "api-secret", "key": "DATABASE_URL"}},
					}],
				}],
			},
		}},
	}},
	{"contents": {
		"kind": "NetworkPolicy",
		"metadata": {"name": "api-deny-all", "namespace": "default"},
		"spec": {
			"podSelector": {"matchLabels": {"app": "api"}},
			"policyTypes": ["Ingress", "Egress"],
		},
	}},
]
