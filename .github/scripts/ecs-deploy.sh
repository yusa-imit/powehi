#!/usr/bin/env bash
# Phase 9.8. Point an ECS service at a new powehi-server image digest and wait until it is stable.
# Usage: ecs-deploy.sh <cluster> <service> <image@sha256:digest> <staging|prod>
# Rollback is the same call with the previous digest (docs/runbooks/server-deploy.md).
# AWS credentials come from the caller's environment (OIDC role of the GitHub Environment).
set -euo pipefail

cluster=${1:?cluster}
service=${2:?service}
image=${3:?image}
env_name=${4:?environment}
here=$(cd "$(dirname "$0")" && pwd)

current=$(aws ecs describe-services --cluster "$cluster" --services "$service" \
  --query 'services[0].taskDefinition' --output text)
[[ "$current" == arn:aws:ecs:* ]] || { echo "service $service not found in $cluster" >&2; exit 1; }
echo "current task definition: $current"

# The family name (no revision) resolves to the latest ACTIVE revision, so a task definition
# change applied by tofu (env, secrets) is carried into the next deploy.
family=${current##*/}; family=${family%:*}
aws ecs describe-task-definition --task-definition "$family" --include TAGS --output json \
  | jq --arg image "$image" --arg env "$env_name" -f "$here/taskdef-with-image.jq" > "${RUNNER_TEMP:-/tmp}/taskdef.json"

new=$(aws ecs register-task-definition --cli-input-json "file://${RUNNER_TEMP:-/tmp}/taskdef.json" \
  --query 'taskDefinition.taskDefinitionArn' --output text)
echo "registered: $new"
previous_image=$(aws ecs describe-task-definition --task-definition "$current" \
  --query "taskDefinition.containerDefinitions[?name=='powehi-server'].image | [0]" --output text)
echo "previous image: $previous_image"

aws ecs update-service --cluster "$cluster" --service "$service" --task-definition "$new" \
  --output text --query 'service.serviceArn' > /dev/null
# The deployment circuit breaker rolls a task that never turns healthy back. The waiter may
# succeed on the rollback or time out (10 minutes) while it is still running; the check below
# fails the job either way.
aws ecs wait services-stable --cluster "$cluster" --services "$service"

running=$(aws ecs describe-services --cluster "$cluster" --services "$service" \
  --query 'services[0].taskDefinition' --output text)
[[ "$running" == "$new" ]] || { echo "service settled on $running, not $new (rolled back)" >&2; exit 1; }
echo "deployed $image as $new (previous image: $previous_image)"
