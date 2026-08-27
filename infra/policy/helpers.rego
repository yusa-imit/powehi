# Shared helpers for the infra/policy conftest gate.
#
# IMPORTANT: every rule in this package assumes conftest is invoked with
# `--combine`, e.g.:
#
#   helm template infra/helm/powehi | conftest test - -p infra/policy --combine
#
# --combine is required (not optional) because the NetworkPolicy deny-all
# check (network_policy.rego) is a set-level check: it must see every
# rendered resource together to confirm a deny-all NetworkPolicy exists
# alongside each workload, not just validate one document in isolation.
# Without --combine, conftest evaluates each YAML document in a multi-doc
# manifest as an independent, isolated `input` and cross-document existence
# checks are structurally impossible to express.
package main

import rego.v1

# All rendered Kubernetes resources, unwrapped from conftest's --combine
# envelope (`{"contents": <resource>, "path": <file>}`) into a flat list of
# the raw resource objects.
all_resources := [r.contents | some r in input]

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}

is_workload(resource) if {
	workload_kinds[resource.kind]
}

# The PodSpec-bearing part of a resource: `.spec.template.spec` for
# Deployment/StatefulSet/DaemonSet/ReplicaSet, `.spec` for a bare Pod.
pod_spec(resource) := resource.spec.template.spec if {
	is_workload(resource)
}

pod_spec(resource) := resource.spec if {
	resource.kind == "Pod"
}

# The pod-template labels a NetworkPolicy's podSelector would need to match
# to select this workload's pods.
workload_pod_labels(resource) := resource.spec.template.metadata.labels if {
	is_workload(resource)
}

workload_pod_labels(resource) := resource.metadata.labels if {
	resource.kind == "Pod"
}

# All containers (regular + init) for a workload or bare Pod.
containers_of(resource) := array.concat(
	object.get(pod_spec(resource), "containers", []),
	object.get(pod_spec(resource), "initContainers", []),
) if {
	is_workload(resource)
}

containers_of(resource) := array.concat(
	object.get(pod_spec(resource), "containers", []),
	object.get(pod_spec(resource), "initContainers", []),
) if {
	resource.kind == "Pod"
}
