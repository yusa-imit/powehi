# Regression tests for run_as_nonroot.rego (check e).
package main

import rego.v1

test_run_as_nonroot_satisfied_true_at_pod_level if {
	resource := {"kind": "Deployment", "spec": {"template": {"spec": {
		"securityContext": {"runAsNonRoot": true},
		"containers": [{"name": "c"}],
	}}}}
	run_as_nonroot_satisfied(resource)
}

test_run_as_nonroot_satisfied_true_when_every_container_sets_it if {
	resource := {"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
		{"name": "a", "securityContext": {"runAsNonRoot": true}},
		{"name": "b", "securityContext": {"runAsNonRoot": true}},
	]}}}}
	run_as_nonroot_satisfied(resource)
}

test_run_as_nonroot_satisfied_false_when_one_container_missing_it if {
	resource := {"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
		{"name": "a", "securityContext": {"runAsNonRoot": true}},
		{"name": "b"},
	]}}}}
	not run_as_nonroot_satisfied(resource)
}

test_run_as_nonroot_satisfied_false_when_zero_containers_and_no_pod_setting if {
	resource := {"kind": "Deployment", "spec": {"template": {"spec": {"containers": []}}}}
	not run_as_nonroot_satisfied(resource)
}

test_deny_fires_when_root_permitted if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api", "namespace": "default"},
		"spec": {"template": {"metadata": {"labels": {}}, "spec": {
			"containers": [{"name": "app", "securityContext": {"runAsNonRoot": false}}],
		}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "runAsNonRoot must be true")
}
