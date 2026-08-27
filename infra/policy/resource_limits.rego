# Check (a): resource limits present.
#
# Every container (regular + init) in every Deployment/StatefulSet/
# DaemonSet/ReplicaSet/Job/CronJob/Pod must declare all four of
# resources.limits.{cpu,memory} and resources.requests.{cpu,memory}.
# No unbounded pods (helm-conventions.md: "Resource limits required for
# every container").
package main

import rego.v1

deny contains msg if {
	some resource in all_resources
	is_workload_like(resource)
	some container in containers_of(resource)
	not has_resource_limits(container)
	msg := sprintf(
		"%s/%s: container %q must set resources.limits.{cpu,memory} and resources.requests.{cpu,memory}",
		[resource.kind, resource.metadata.name, container.name],
	)
}

has_resource_limits(container) if {
	is_set_value(object.get(container, ["resources", "limits", "cpu"], null))
	is_set_value(object.get(container, ["resources", "limits", "memory"], null))
	is_set_value(object.get(container, ["resources", "requests", "cpu"], null))
	is_set_value(object.get(container, ["resources", "requests", "memory"], null))
}

is_set_value(v) if {
	v != null
	v != ""
}
