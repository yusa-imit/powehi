#!/usr/bin/env bash
# Offline test for taskdef-with-image.jq (run by ci-infra.yml).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
old=ghcr.io/yusa-imit/powehi-server@sha256:$(printf 'a%.0s' {1..64})
new=ghcr.io/yusa-imit/powehi-server@sha256:$(printf 'b%.0s' {1..64})
fixture=$(jq -n --arg old "$old" '{taskDefinition: {
  taskDefinitionArn: "arn:aws:ecs:ap-northeast-2:1:task-definition/powehi-staging-service:3",
  family: "powehi-staging-service", revision: 3, status: "ACTIVE", cpu: "512",
  taskRoleArn: "r1", executionRoleArn: "r2", requiresAttributes: [{name: "x"}], compatibilities: ["FARGATE"],
  registeredAt: 1, registeredBy: "me",
  containerDefinitions: [{name: "powehi-server", image: $old}, {name: "cloudflared", image: "cf@sha256:c"}]},
  tags: [{key: "Environment", value: "staging"}]}')
out=$(printf '%s' "$fixture" | jq --arg image "$new" --arg env staging -f "$here/taskdef-with-image.jq")
check() { printf '%s' "$out" | jq -e "$1" > /dev/null || { echo "FAIL: $1" >&2; exit 1; }; }
check ".containerDefinitions[0].image == \"$new\""
check '.containerDefinitions[1].image == "cf@sha256:c"'
check '.tags == [{key: "Environment", value: "staging"}]'
check '.family == "powehi-staging-service" and .taskRoleArn == "r1"'
check 'has("revision") or has("taskDefinitionArn") or has("registeredAt") | not'
for bad in "ghcr.io/yusa-imit/powehi-server:latest" "evil.io/x@sha256:$(printf 'b%.0s' {1..64})"; do
  if printf '%s' "$fixture" | jq --arg image "$bad" --arg env staging -f "$here/taskdef-with-image.jq" > /dev/null 2>&1; then
    echo "FAIL: accepted $bad" >&2; exit 1
  fi
done
bad=$'ghcr.io/yusa-imit/powehi-server@sha256:'$(printf 'b%.0s' {1..64})$'\n'
if printf '%s' "$fixture" | jq --arg image "$bad" --arg env staging -f "$here/taskdef-with-image.jq" > /dev/null 2>&1; then
  echo "FAIL: accepted trailing newline" >&2; exit 1
fi
# A base revision tagged for another environment, or untagged, or without the server container.
for f in '.tags[0].value = "prod"' 'del(.tags)' '.taskDefinition.containerDefinitions |= map(select(.name != "powehi-server"))'; do
  if printf '%s' "$fixture" | jq "$f" | jq --arg image "$new" --arg env staging -f "$here/taskdef-with-image.jq" > /dev/null 2>&1; then
    echo "FAIL: accepted base with $f" >&2; exit 1
  fi
done
echo "taskdef-with-image: ok"
