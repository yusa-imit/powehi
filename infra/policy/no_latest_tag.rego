# Check (d): no container image tag is literally `latest`, and no image
# reference is left without an explicit tag at all (Kubernetes implicitly
# pulls `:latest` in that case, which is equally unacceptable).
#
# This inspects the exploded/rendered `image:` string on every container,
# not the values file, so a bad `Chart.AppVersion` or a future overlay
# pinning `latest` gets caught. Scope note: this CI gate only renders the
# in-repo chart + overlays — it cannot see (and does not attempt to block)
# an operator passing `--set image.tag=latest` at actual deploy time; that
# threat needs an in-cluster admission policy (e.g. Kyverno/Gatekeeper), not
# a static render-time check like this one.
package main

import rego.v1

deny contains msg if {
	some resource in all_resources
	is_workload_like(resource)
	some container in containers_of(resource)
	is_latest_or_untagged(container.image)
	msg := sprintf(
		"%s/%s: container %q image %q must not use the ':latest' tag (or no tag at all, which Kubernetes implicitly treats as latest) — pin an explicit version",
		[resource.kind, resource.metadata.name, container.name, container.image],
	)
}

is_latest_or_untagged(image) if {
	endswith(image, ":latest")
}

is_latest_or_untagged(image) if {
	not has_explicit_tag(image)
}

# An image has an explicit tag if the final "/"-delimited path segment
# contains a ":" (a bare registry host:port with no trailing tag, e.g.
# "registry:5000/repo", does not count as tagged).
has_explicit_tag(image) if {
	segments := split(image, "/")
	last_segment := segments[count(segments) - 1]
	contains(last_segment, ":")
}
