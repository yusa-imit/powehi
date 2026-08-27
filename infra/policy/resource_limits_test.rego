# Regression tests for resource_limits.rego (check a).
package main

import rego.v1

test_has_resource_limits_true_when_all_four_set if {
	has_resource_limits({"resources": {
		"limits": {"cpu": "500m", "memory": "256Mi"},
		"requests": {"cpu": "250m", "memory": "128Mi"},
	}})
}

test_has_resource_limits_false_when_limits_missing if {
	not has_resource_limits({"resources": {"requests": {"cpu": "250m", "memory": "128Mi"}}})
}

test_has_resource_limits_false_when_resources_absent if {
	not has_resource_limits({"name": "app"})
}

test_has_resource_limits_false_when_value_is_empty_string if {
	not has_resource_limits({"resources": {
		"limits": {"cpu": "", "memory": "256Mi"},
		"requests": {"cpu": "250m", "memory": "128Mi"},
	}})
}

test_deny_fires_for_container_missing_limits if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api", "namespace": "default"},
		"spec": {"template": {"metadata": {"labels": {"app": "api"}}, "spec": {
			"containers": [{"name": "app", "image": "repo/app:1.0"}],
		}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "must set resources.limits")
}

# The gap cycle 379 closed: a CronJob's containers live one level deeper
# than a Deployment's — confirm the deny rule actually inspects them rather
# than silently resolving to an empty container list (which would make this
# check vacuously pass, the exact bug the fix addressed).
test_deny_fires_for_cronjob_container_missing_limits if {
	resource := {
		"kind": "CronJob",
		"metadata": {"name": "cleanup", "namespace": "default"},
		"spec": {"jobTemplate": {"spec": {"template": {
			"metadata": {"labels": {"app": "cleanup"}},
			"spec": {"containers": [{"name": "job", "image": "repo/cleanup:1.0"}]},
		}}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "must set resources.limits")
}
