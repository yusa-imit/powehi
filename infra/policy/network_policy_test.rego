# Regression tests for network_policy.rego (check b).
package main

import rego.v1

test_is_deny_all_policy_true_for_no_rule_blocks if {
	is_deny_all_policy({"spec": {"policyTypes": ["Ingress", "Egress"]}})
}

test_is_deny_all_policy_false_with_ingress_rule_present if {
	not is_deny_all_policy({"spec": {"policyTypes": ["Ingress", "Egress"], "ingress": [{}]}})
}

test_is_deny_all_policy_false_when_missing_egress_type if {
	not is_deny_all_policy({"spec": {"policyTypes": ["Ingress"]}})
}

test_selector_matches_workload_true_for_label_subset if {
	resource := {"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {"app": "api", "tier": "backend"}}}}}
	np := {"spec": {"podSelector": {"matchLabels": {"app": "api"}}}}
	selector_matches_workload(np, resource)
}

# Documented (and intentional) Kubernetes semantics: an empty podSelector
# selects every pod in the namespace, so it counts as covering any workload.
test_selector_matches_workload_true_for_empty_selector if {
	resource := {"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {"app": "api"}}}}}
	np := {"spec": {"podSelector": {}}}
	selector_matches_workload(np, resource)
}

test_selector_matches_workload_false_for_mismatched_label if {
	resource := {"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {"app": "api"}}}}}
	np := {"spec": {"podSelector": {"matchLabels": {"app": "other"}}}}
	not selector_matches_workload(np, resource)
}

test_deny_fires_when_no_networkpolicy_present if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api", "namespace": "default"},
		"spec": {"template": {"metadata": {"labels": {"app": "api"}}, "spec": {"containers": []}}},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "no deny-all baseline NetworkPolicy")
}

test_has_deny_all_baseline_true_when_matching_policy_present if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api", "namespace": "default"},
		"spec": {"template": {"metadata": {"labels": {"app": "api"}}, "spec": {"containers": []}}},
	}
	np := {
		"kind": "NetworkPolicy",
		"metadata": {"name": "deny-all", "namespace": "default"},
		"spec": {"podSelector": {"matchLabels": {"app": "api"}}, "policyTypes": ["Ingress", "Egress"]},
	}
	has_deny_all_baseline(resource) with input as [{"contents": resource}, {"contents": np}]
}

test_has_deny_all_baseline_false_when_policy_in_other_namespace if {
	resource := {
		"kind": "Deployment",
		"metadata": {"name": "api", "namespace": "default"},
		"spec": {"template": {"metadata": {"labels": {"app": "api"}}, "spec": {"containers": []}}},
	}
	np := {
		"kind": "NetworkPolicy",
		"metadata": {"name": "deny-all", "namespace": "other-ns"},
		"spec": {"podSelector": {"matchLabels": {"app": "api"}}, "policyTypes": ["Ingress", "Egress"]},
	}
	not has_deny_all_baseline(resource) with input as [{"contents": resource}, {"contents": np}]
}
