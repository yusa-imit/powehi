# GitHub Actions OIDC. No long-lived AWS keys exist anywhere (ADR-0007 decision 5).
#
# Trust policies match `sub` and `aud` with exact StringEquals: no StringLike, no wildcard.
#   deploy  : repo:<owner>/<name>:environment:<GitHub Environment>   (one role per env)
#   plan    : repo:<owner>/<name>:pull_request                       (read-only role)
# A `sub` of ...:environment:production is only issued to a job that passed that
# Environment's protection rules, so the owner's approval gate is enforced by AWS too.

locals {
  oidc_host = "token.actions.githubusercontent.com"

  # Always required: pins the numeric repository ID so a re-registered owner/name fails.
  repo_id_condition = {
    "${local.oidc_host}:repository_id" = var.github_repository_id
  }

  deploy_subjects = {
    for env, gh_env in var.github_environments :
    env => "repo:${var.github_repository}:environment:${gh_env}"
  }

  plan_subject = "repo:${var.github_repository}:pull_request"
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  # AWS validates the GitHub certificate chain against its trusted CA library; no thumbprint.
}

locals {
  trust_policies = merge(
    {
      for env, sub in local.deploy_subjects : "deploy-${env}" => jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Effect    = "Allow"
          Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
          Action    = "sts:AssumeRoleWithWebIdentity"
          Condition = {
            StringEquals = merge(local.repo_id_condition, {
              "${local.oidc_host}:aud" = "sts.amazonaws.com"
              "${local.oidc_host}:sub" = sub
            })
          }
        }]
      })
    },
    {
      plan = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Effect    = "Allow"
          Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
          Action    = "sts:AssumeRoleWithWebIdentity"
          Condition = {
            StringEquals = merge(local.repo_id_condition, {
              "${local.oidc_host}:aud" = "sts.amazonaws.com"
              "${local.oidc_host}:sub" = local.plan_subject
            })
          }
        }]
      })
    },
  )
}
