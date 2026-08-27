# Regression tests for helpers.rego's kind-dispatch logic — in particular
# the CronJob deep-nesting path (.spec.jobTemplate.spec.template.*), which
# is exactly the shape cycle 379 (fix da1aa63) got right after cycle
# 378/379's audit found Job/CronJob/bare-Pod silently unhandled. These tests
# exist so a future refactor of pod_spec/workload_pod_labels/containers_of
# can't reintroduce that gap without a red `conftest verify`.
package main

import rego.v1

test_pod_spec_deployment if {
	resource := {"kind": "Deployment", "spec": {"template": {"spec": {"containers": [{"name": "c"}]}}}}
	pod_spec(resource) == {"containers": [{"name": "c"}]}
}

test_pod_spec_bare_pod if {
	resource := {"kind": "Pod", "spec": {"containers": [{"name": "c"}]}}
	pod_spec(resource) == {"containers": [{"name": "c"}]}
}

test_pod_spec_cronjob_deep_nesting if {
	resource := {
		"kind": "CronJob",
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c"}]}}}}},
	}
	pod_spec(resource) == {"containers": [{"name": "c"}]}
}

test_workload_pod_labels_cronjob_deep_nesting if {
	resource := {
		"kind": "CronJob",
		"spec": {"jobTemplate": {"spec": {"template": {
			"metadata": {"labels": {"app": "cron"}},
			"spec": {},
		}}}},
	}
	workload_pod_labels(resource) == {"app": "cron"}
}

test_workload_pod_labels_bare_pod_is_metadata_labels if {
	resource := {"kind": "Pod", "metadata": {"labels": {"app": "standalone"}}, "spec": {}}
	workload_pod_labels(resource) == {"app": "standalone"}
}

test_containers_of_cronjob_resolves_regular_and_init_containers if {
	resource := {
		"kind": "CronJob",
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {
			"containers": [{"name": "c"}],
			"initContainers": [{"name": "init"}],
		}}}}},
	}
	containers := containers_of(resource)
	count(containers) == 2
}

test_containers_of_job_resolves_via_shallow_template if {
	resource := {
		"kind": "Job",
		"spec": {"template": {"spec": {"containers": [{"name": "c"}]}}},
	}
	count(containers_of(resource)) == 1
}

test_is_workload_like_covers_job_cronjob_pod if {
	is_workload_like({"kind": "Job"})
	is_workload_like({"kind": "CronJob"})
	is_workload_like({"kind": "Pod"})
}

test_is_workload_like_excludes_non_workload_kinds if {
	not is_workload_like({"kind": "ConfigMap"})
	not is_workload_like({"kind": "NetworkPolicy"})
	not is_workload_like({"kind": "Secret"})
}
