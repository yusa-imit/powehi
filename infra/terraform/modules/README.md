# modules/

Reusable OpenTofu modules shared by `envs/staging` and `envs/prod`. Holds `network` and `data` (9.3), `edge` (9.4, Cloudflare) and, in 9.5, ECS Fargate with the cloudflared sidecar. Every module
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
