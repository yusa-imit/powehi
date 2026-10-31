# modules/

Reusable OpenTofu modules shared by `envs/staging` and `envs/prod`. Holds `network` and `data` (9.3), `edge` (9.4, Cloudflare) and `service` (9.5, ECS Fargate with the cloudflared sidecar). Every module
takes the region and the environment name as inputs (ADR-0007 decision 4) and uses the
`powehi-<env>-` resource name prefix that the deploy roles in `../bootstrap` are scoped to.

Module rules: no service that processes ciphertext content; log groups and metrics carry no
payload and no plaintext user IDs; R2 buckets accept only ciphertext objects.

`edge` (Cloudflare provider ~> 5): zone TLS (min 1.3, TLS 1.3 on, always-HTTPS, strict), a
remotely managed Tunnel plus proxied CNAME for the env's API hostname (origin
`http://localhost:8080`, 404 otherwise), and, only in the zone-owning stack (`manage_zone = true`, staging), the zone TLS settings, a
managed WAF ruleset and one path-only per-IP rate-limit rule on the OPAQUE register/login paths; plus the private
`<prefix>-media` R2 bucket (apac) and, when `create_r2_token` is true, a token scoped to it. Needs
`CLOUDFLARE_API_TOKEN` in the environment. The tunnel token is never in state; the owner fetches it out of band. `r2_secret_access_key`
(only with `create_r2_token`) is sensitive and reaches the task via Secrets Manager.

`service` (9.5): one ECS cluster and service, one task with `powehi-server` and a `cloudflared`
sidecar (both images pinned by digest; the tunnel starts only after the server is healthy). The task
security group has no ingress; the public IP is for outbound only. Credentials (database URL, Valkey
URL, R2 keys, VAPID key, handle-oracle token, tunnel token) are Secrets Manager ARNs under
`powehi/<env>/` that the owner creates out of band; the module takes ARNs, never values, and the
execution role can read exactly those. Roles are `powehi-<env>-svc-exec` / `-svc-task` with the env
permissions boundary; the task role has no policy. Logs go to `/powehi/<env>/service` (14 days). The
database URL must carry `sslmode=verify-full&sslrootcert=/etc/powehi/rds-global-bundle.pem` (RDS forces TLS). Concurrent task starts do not race the
startup migrations: sqlx takes a Postgres advisory lock around them. The service ignores
`task_definition` changes, since the deploy workflow (9.8) owns revisions. `cpu_architecture` defaults to
`X86_64` because `release.yml` builds `linux/amd64` only; ADR-0007's ARM64 needs a multi-arch image (9.8).
