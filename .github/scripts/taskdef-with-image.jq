# Phase 9.8. Input: `aws ecs describe-task-definition --include TAGS` output. Output: the
# register-task-definition input with the powehi-server image swapped to $image. The base revision must carry the tag
# Environment=$env (a stray revision in the family is refused). Everything
# else (sidecar, roles, secrets ARNs, health check) is carried over unchanged.
# The Environment tag must survive: the deploy role's RegisterTaskDefinition requires it.
if ($image | test("^ghcr\\.io/yusa-imit/powehi-server@sha256:[0-9a-f]{64}\\z") | not)
then error("image must be ghcr.io/yusa-imit/powehi-server@sha256:<64 hex>")
elif ((.tags // []) | any(.key == "Environment" and .value == $env) | not)
then error("base task definition is not tagged Environment=\($env)")
elif (.taskDefinition.family | test("^powehi-\($env)-[a-z0-9-]+\\z") | not)
then error("base task definition family is not a powehi-\($env) family")
else
  .taskDefinition as $td
  | ($td.containerDefinitions | map(select(.name == "powehi-server")) | length) as $n
  | if $n != 1 then error("expected exactly one powehi-server container, found \($n)") else . end
  | ($td | del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities,
               .registeredAt, .registeredBy, .deregisteredAt))
    + {tags: (.tags // [])}
  | .containerDefinitions |= map(if .name == "powehi-server" then .image = $image else . end)
end
