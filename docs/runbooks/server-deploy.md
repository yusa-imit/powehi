# Server deploy and rollback (Phase 9.8)

`deploy.yml` runs after `release.yml` succeeds on a `vX.Y.Z` tag whose commit is on `main`.

1. **resolve**: looks up the image digest for the tag, then `cosign verify`s it against the
   `release.yml` identity on a release tag. Nothing else is deployed, whatever the tag says.
2. **staging**: registers a new task definition (only the `powehi-server` image changes, pinned by
   digest), updates the ECS service, waits for it to be stable, then runs the CLI smoke test
   against `https://api-staging.<domain>`.
3. **production**: only if repository variable `PROD_DEPLOY_ENABLED` is `true`; waits for the
   `production` Environment approval, then repeats step 2 against `https://api.<domain>`.

ECS's deployment circuit breaker rolls back a task that never turns healthy. The workflow then
fails because the service did not settle on the new task definition. With one task, three failed
starts can outlast the 10-minute waiter: the job then fails while the rollback is still running;
check the service before re-running.

Signing is bound to a commit on `main` (the certificate's workflow SHA), so a tag pushed from a
side branch cannot be deployed. Add a `v*` tag ruleset restricting who can create tags.

## Rollback

Run **Deploy — server to ECS** from `main` (Actions, Run workflow) with the previous image digest
(`sha256:...`; find it in the log line `previous image: ...` of the deploy step, or the GitHub
Packages page). It is verified with cosign, then goes staging -> approval -> prod like any
deploy. Rollback never touches the database: migrations run forward at startup, so roll back only
to a release whose schema expectations are compatible with the current schema.

## Task definition drift

`modules/service` ignores `task_definition` changes, so `tofu apply` never reverts a deploy. A
`tofu apply` that changes the task definition (new env var, secret) registers a new revision that
the service does not run until the next deploy. `deploy.yml` starts from the family's latest
revision, so that deploy picks the change up and swaps only the server image.
