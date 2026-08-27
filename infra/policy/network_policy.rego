# Check (b): a deny-all baseline NetworkPolicy exists per workload.
#
# This does NOT require every NetworkPolicy to be deny-all — a chart may
# (and this one does) layer explicit numbered allow-rules on top of a single
# deny-all baseline. It only requires that, for each workload, at least one
# NetworkPolicy in the same namespace whose podSelector matches that
# workload's pod labels has policyTypes == [Ingress, Egress] with NO
# ingress/egress rule blocks at all (their absence, with the type listed in
# policyTypes, is what makes a NetworkPolicy deny-all under Kubernetes
# NetworkPolicy semantics).
package main

import rego.v1

deny contains msg if {
	some resource in all_resources
	is_workload_like(resource)
	not has_deny_all_baseline(resource)
	msg := sprintf(
		"%s/%s: no deny-all baseline NetworkPolicy found — a NetworkPolicy matching this workload's pod labels must set policyTypes [Ingress, Egress] with no ingress/egress rule blocks",
		[resource.kind, resource.metadata.name],
	)
}

has_deny_all_baseline(resource) if {
	some np in all_resources
	np.kind == "NetworkPolicy"
	np.metadata.namespace == resource.metadata.namespace
	is_deny_all_policy(np)
	selector_matches_workload(np, resource)
}

is_deny_all_policy(np) if {
	policy_types := {t | some t in np.spec.policyTypes}
	policy_types == {"Ingress", "Egress"}
	not np.spec.ingress
	not np.spec.egress
}

# The NetworkPolicy's podSelector.matchLabels must be a subset of (i.e.
# actually select) the workload's pod-template labels — this rejects a
# deny-all NetworkPolicy that happens to exist for some unrelated workload.
# Note: an empty podSelector ({}) is vacuously a subset of any label set, so
# it DOES count as "covering" this workload here — that's correct Kubernetes
# NetworkPolicy semantics (an empty podSelector selects all pods in the
# namespace), not a gap.
selector_matches_workload(np, resource) if {
	pod_labels := workload_pod_labels(resource)
	sel := object.get(np.spec, ["podSelector", "matchLabels"], {})
	every k, v in sel {
		pod_labels[k] == v
	}
}
