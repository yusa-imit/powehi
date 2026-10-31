# modules/

Reusable OpenTofu modules shared by `envs/staging` and `envs/prod`. Empty until 9.3
(network and data), 9.4 (Cloudflare edge) and 9.5 (ECS Fargate + Tunnel). Every module
takes the region and the environment name as inputs (ADR-0007 decision 4) and uses the
`powehi-<env>-` resource name prefix that the deploy roles in `../bootstrap` are scoped to.

Module rules: no service that processes ciphertext content; log groups and metrics carry no
payload and no plaintext user IDs; R2 buckets accept only ciphertext objects.
