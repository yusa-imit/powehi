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

# Job's PodTemplateSpec lives at `.spec.template.{spec,metadata.labels}` —
# structurally identical to Deployment/StatefulSet/DaemonSet/ReplicaSet — so
# it's safe to fold into workload_kinds directly. CronJob is NOT included
# here: its PodTemplateSpec is nested one level deeper, at
# `.spec.jobTemplate.spec.template.{spec,metadata.labels}` (a CronJob wraps a
# JobSpec, which is where the usual `.template.spec` shows up). Naively
# adding "CronJob" here would make pod_spec/workload_pod_labels look in the
# wrong place. CronJob gets its own rule bodies below instead, and is
# covered via is_workload_like, not is_workload.
workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

is_workload(resource) if {
	workload_kinds[resource.kind]
}

# Canonical "does this policy set need to inspect a PodSpec here" gate. Every
# check in this package should gate on is_workload_like rather than
# duplicating an ad hoc `is_workload(resource)` OR `resource.kind == "Pod"`
# (or worse, silently omitting CronJob/Pod) locally.
is_workload_like(resource) if {
	is_workload(resource)
}

is_workload_like(resource) if {
	resource.kind == "CronJob"
}

is_workload_like(resource) if {
	resource.kind == "Pod"
}

# The PodSpec-bearing part of a resource: `.spec.template.spec` for
# Deployment/StatefulSet/DaemonSet/ReplicaSet/Job, `.spec` for a bare Pod,
# and `.spec.jobTemplate.spec.template.spec` for a CronJob (one level
# deeper — see the workload_kinds comment above).
pod_spec(resource) := resource.spec.template.spec if {
	is_workload(resource)
}

pod_spec(resource) := resource.spec if {
	resource.kind == "Pod"
}

pod_spec(resource) := resource.spec.jobTemplate.spec.template.spec if {
	resource.kind == "CronJob"
}

# The pod-template labels a NetworkPolicy's podSelector would need to match
# to select this workload's pods.
workload_pod_labels(resource) := resource.spec.template.metadata.labels if {
	is_workload(resource)
}

workload_pod_labels(resource) := resource.metadata.labels if {
	resource.kind == "Pod"
}

workload_pod_labels(resource) := resource.spec.jobTemplate.spec.template.metadata.labels if {
	resource.kind == "CronJob"
}

# All containers (regular + init) for anything is_workload_like covers.
# pod_spec(resource) already resolves to the correct nesting depth for every
# kind is_workload_like accepts, so a single rule body suffices here.
containers_of(resource) := array.concat(
	object.get(pod_spec(resource), "containers", []),
	object.get(pod_spec(resource), "initContainers", []),
) if {
	is_workload_like(resource)
}
