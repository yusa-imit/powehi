# Regression tests for no_latest_tag.rego (check d).
package main

import rego.v1

test_is_latest_or_untagged_true_for_explicit_latest if {
	is_latest_or_untagged("ghcr.io/powehi/api:latest")
}

test_is_latest_or_untagged_true_for_no_tag_at_all if {
	is_latest_or_untagged("ghcr.io/powehi/api")
}

test_is_latest_or_untagged_false_for_pinned_tag if {
	not is_latest_or_untagged("ghcr.io/powehi/api:1.2.3")
}

test_has_explicit_tag_false_for_bare_registry_port_no_tag if {
	not has_explicit_tag("registry:5000/repo")
}

test_has_explicit_tag_true_for_registry_port_and_tag if {
	has_explicit_tag("registry:5000/repo:1.0")
}

test_deny_fires_for_latest_tag if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api", "namespace": "default"},
		"spec": {"template": {"metadata": {"labels": {}}, "spec": {
			"containers": [{"name": "app", "image": "repo/app:latest"}],
		}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "must not use the ':latest' tag")
}

test_deny_fires_for_untagged_image if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api", "namespace": "default"},
		"spec": {"template": {"metadata": {"labels": {}}, "spec": {
			"containers": [{"name": "app", "image": "repo/app"}],
		}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "must not use the ':latest' tag")
}
