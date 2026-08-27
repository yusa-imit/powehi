# Check (e): runAsNonRoot: true is set, at the pod level and/or every
# container level. A container-level setting is sufficient on its own even
# if no pod-level setting is present (and vice versa for containers that
# don't override it), though this chart currently sets both.
package main

import rego.v1

deny contains msg if {
	some resource in all_resources
	is_workload_like(resource)
	not run_as_nonroot_satisfied(resource)
	msg := sprintf(
		"%s/%s: securityContext.runAsNonRoot must be true at the pod level and/or on every container",
		[resource.kind, resource.metadata.name],
	)
}

run_as_nonroot_satisfied(resource) if {
	pod_spec(resource).securityContext.runAsNonRoot == true
}

run_as_nonroot_satisfied(resource) if {
	containers := containers_of(resource)
	count(containers) > 0
	every container in containers {
		container.securityContext.runAsNonRoot == true
	}
}
