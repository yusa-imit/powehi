# Offline tests: mocked AWS provider, nothing is created. `apply` is used because computed
# attributes (role ARNs, OIDC provider ARN) only exist after the mock apply.

mock_provider "aws" {
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = {
      arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    }
  }

  # Generic ARN: the mock cannot return per-instance values. Boundary ARNs that matter are
  # derived deterministically in iam.tf (local.boundary_arn), so envs stay distinguishable.
  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::123456789012:policy/mock"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
}

variables {
  owner_email          = "owner@example.com"
  github_repository_id = "123456"
  allowed_account_ids  = ["123456789012"]
}

run "deploy_roles_trust_only_their_environment" {
  command = apply

  assert {
    condition = (
      jsondecode(aws_iam_role.deploy["staging"].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]
      == "repo:yusa-imit/powehi:environment:staging"
    )
    error_message = "staging deploy role must trust exactly repo:yusa-imit/powehi:environment:staging"
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.deploy["prod"].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]
      == "repo:yusa-imit/powehi:environment:production"
    )
    error_message = "prod deploy role must trust exactly the production GitHub Environment"
  }

  assert {
    condition = alltrue([
      for r in values(aws_iam_role.deploy) :
      jsondecode(r.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    ])
    error_message = "every deploy role must pin aud to sts.amazonaws.com"
  }

  assert {
    condition = alltrue([
      for r in values(aws_iam_role.deploy) :
      length(keys(jsondecode(r.assume_role_policy).Statement[0].Condition)) == 1 &&
      keys(jsondecode(r.assume_role_policy).Statement[0].Condition)[0] == "StringEquals" &&
      length(jsondecode(r.assume_role_policy).Statement) == 1
    ])
    error_message = "trust policies must use only StringEquals (no StringLike, no extra statements)"
  }

  assert {
    condition = alltrue([
      for r in values(aws_iam_role.deploy) :
      jsondecode(r.assume_role_policy).Statement[0].Action == "sts:AssumeRoleWithWebIdentity"
    ])
    error_message = "trust policies must only allow sts:AssumeRoleWithWebIdentity"
  }
}

run "plan_role_trusts_pull_request_only" {
  command = apply

  assert {
    condition = (
      jsondecode(aws_iam_role.plan.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]
      == "repo:yusa-imit/powehi:pull_request"
    )
    error_message = "plan role must trust exactly repo:yusa-imit/powehi:pull_request"
  }

  assert {
    condition = (
      !strcontains(aws_iam_role_policy.plan_state.policy, "prod") &&
      strcontains(aws_iam_role_policy.plan_state.policy, "/staging/*") &&
      jsondecode(aws_iam_role_policy.plan_state.policy).Statement[1].Resource == ["${aws_s3_bucket.state.arn}/staging/*"] &&
      jsondecode(aws_iam_role_policy.plan_state.policy).Statement[0].Condition.StringLike["s3:prefix"] == ["staging/*"]
    )
    error_message = "PR plan role may read only staging/* state, never prod/*"
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.plan_state.policy).Statement[2].Condition.StringEquals["kms:ViaService"] == "s3.ap-northeast-2.amazonaws.com"
    )
    error_message = "plan role KMS access must be limited to calls made through S3"
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.plan_state.policy, "s3:PutObject") && !strcontains(aws_iam_role_policy.plan_state.policy, "s3:DeleteObject")
    error_message = "plan role must not be able to write state or the lock file"
  }
}

run "repository_id_claim_is_enforced" {
  command = apply

  assert {
    condition = (
      jsondecode(aws_iam_role.deploy["staging"].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:repository_id"]
      == "123456"
    )
    error_message = "repository_id claim must always be enforced"
  }
}

run "state_bucket_is_locked_down" {
  command = apply

  assert {
    condition = (
      aws_s3_bucket_public_access_block.state.block_public_acls &&
      aws_s3_bucket_public_access_block.state.block_public_policy &&
      aws_s3_bucket_public_access_block.state.ignore_public_acls &&
      aws_s3_bucket_public_access_block.state.restrict_public_buckets
    )
    error_message = "state bucket must block all public access"
  }

  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "state bucket must be versioned"
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "state bucket must use SSE-KMS"
  }

  assert {
    condition     = aws_kms_key.state.enable_key_rotation
    error_message = "state KMS key must rotate"
  }
}

run "bad_repository_rejected" {
  command = plan

  variables {
    github_repository = "yusa-imit/*"
  }

  expect_failures = [var.github_repository]
}

run "budget_alerts_80_and_100" {
  command = apply

  assert {
    condition     = aws_budgets_budget.monthly.limit_amount == "150" && aws_budgets_budget.monthly.limit_unit == "USD"
    error_message = "budget must be $150/month"
  }

  assert {
    condition = (
      contains([for n in aws_budgets_budget.monthly.notification : n.threshold], 80) &&
      contains([for n in aws_budgets_budget.monthly.notification : n.threshold], 100)
    )
    error_message = "budget must alert at 80% and 100%"
  }
}

run "non_numeric_repository_id_rejected" {
  command = plan

  variables {
    github_repository_id = "abc"
  }

  expect_failures = [var.github_repository_id]
}

run "bad_account_id_rejected" {
  command = plan

  variables {
    allowed_account_ids = ["12345"]
  }

  expect_failures = [var.allowed_account_ids]
}

# --- Privilege-escalation guards on the deploy roles -----------------------------------------
run "deploy_policies_cannot_touch_own_role_or_boundary" {
  command = apply

  # Allow statements that carry an iam: action (except SLR creation) must only target svc
  # roles/policies; and no allowed Resource glob may match a protected ARN.
  assert {
    condition = alltrue(flatten([
      for k, p in aws_iam_policy.deploy : [
        for s in jsondecode(p.policy).Statement : alltrue([
          for r in flatten([s.Resource]) : strcontains(r, "-svc-")
        ])
        if s.Effect == "Allow" && anytrue([for a in flatten([s.Action]) : startswith(a, "iam:") && a != "iam:CreateServiceLinkedRole"])
      ]
    ]))
    error_message = "every iam allow on a deploy role must target the powehi-<env>-svc-* prefix only"
  }

  assert {
    condition = !anytrue(flatten([
      for k, p in aws_iam_policy.deploy : [
        for s in jsondecode(p.policy).Statement : [
          for r in flatten([s.Resource]) : anytrue([
            for protected in [
              "arn:aws:iam::123456789012:role/powehi-${split("-", k)[0]}-deploy",
              "arn:aws:iam::123456789012:role/powehi-plan-readonly",
              "arn:aws:iam::123456789012:policy/powehi-boundary-${split("-", k)[0]}",
              "arn:aws:iam::123456789012:policy/powehi-guardrail-${split("-", k)[0]}",
              "arn:aws:iam::123456789012:policy/powehi-deploy-${k}",
            ] : can(regex("^\\Q${replace(r, "*", "\\E.*\\Q")}\\E$", protected))
          ])
        ] if s.Effect == "Allow" && anytrue([for a in flatten([s.Action]) : startswith(a, "iam:")])
      ]
    ]))
    error_message = "no allowed Resource pattern may match the deploy role, plan role, boundary, guardrail or deploy policies"
  }

  assert {
    condition     = !anytrue([for k, p in aws_iam_policy.deploy : strcontains(p.policy, "AdministratorAccess")])
    error_message = "AdministratorAccess must never be attachable"
  }

  assert {
    condition = alltrue([
      for k, p in aws_iam_policy.deploy : alltrue([
        for s in jsondecode(p.policy).Statement :
        contains(keys(try(s.Condition, {})), "ArnLike") && contains(keys(s.Condition.ArnLike), "iam:PolicyARN")
        if contains(flatten([s.Action]), "iam:AttachRolePolicy")
      ])
    ])
    error_message = "iam:AttachRolePolicy must be limited by an iam:PolicyARN allow-list"
  }

  assert {
    condition     = !anytrue([for k, p in aws_iam_policy.deploy : strcontains(p.policy, "iam:UpdateAssumeRolePolicy")])
    error_message = "deploy roles must not be able to change a role's trust policy"
  }

  assert {
    condition = alltrue([
      for k, p in aws_iam_policy.deploy : alltrue([
        for s in jsondecode(p.policy).Statement : !contains(flatten([s.Action]), "ec2:*") && !anytrue([for a in flatten([s.Action]) : endswith(a, ":*")])
      ])
    ])
    error_message = "service-wide wildcard actions (svc:*) are not allowed on deploy roles"
  }

  assert {
    condition = alltrue([
      for k, p in aws_iam_policy.deploy : alltrue([
        for s in jsondecode(p.policy).Statement :
        anytrue([for a in flatten([s.Action]) : can(regex("^(ec2|ecs|rds|elasticache):(Create|Delete|Modify|Update|Register|Allocate|Release|Attach|Detach|Authorize|Revoke|Associate|Disassociate|Replace|Tag|Untag|Add|Remove|Put|Reset|Reboot|Start|Stop)", a))])
        ? (contains(keys(try(s.Condition, {})), "StringEquals") || s.Sid == "RdsSnapshotsOwnPrefix" || s.Sid == "EcsDeregisterOwnTaskDefinitions")
        : true
      ])
    ])
    error_message = "ec2/ecs/rds/elasticache writes must carry an env tag condition (except name-scoped snapshots/task definitions)"
  }
}

run "ec2_child_creates_require_env_tagged_parent" {
  command = apply

  # Every allow of a child-create action must be either RequestTag-gated on NEW-resource ARNs or
  # ResourceTag-gated on PARENT ARNs; nothing may allow child creates with RequestTag on vpc/*.
  assert {
    condition = alltrue([
      for k, p in aws_iam_policy.deploy : alltrue([
        for s in jsondecode(p.policy).Statement :
        (
          contains(keys(s.Condition.StringEquals), "aws:ResourceTag/Environment") &&
          alltrue([for r in flatten([s.Resource]) : anytrue([for t in ["vpc", "subnet", "route-table", "security-group", "elastic-ip"] : endswith(r, ":${t}/*")])])
          ) || (
          contains(keys(s.Condition.StringEquals), "aws:RequestTag/Environment") &&
          alltrue([for r in flatten([s.Resource]) : !anytrue([for t in ["vpc", "elastic-ip"] : endswith(r, ":${t}/*")])])
        )
        if s.Effect == "Allow" && contains(flatten([s.Action]), "ec2:CreateSecurityGroup")
      ])
    ])
    error_message = "ec2 child creates: RequestTag only on new-resource ARNs, parent ARNs need ResourceTag"
  }

  assert {
    condition = alltrue([
      for env in ["staging", "prod"] :
      strcontains(aws_iam_policy.guardrail[env].policy, "ec2:Create*")
    ])
    error_message = "guardrail must deny ec2:Create* against other-env-tagged parents"
  }
}

run "ecs_task_definition_and_tagging_constraints" {
  command = apply

  assert {
    condition = alltrue(flatten([
      for k, p in aws_iam_policy.deploy : [
        for s in jsondecode(p.policy).Statement :
        try(s.Condition.ArnLike["ecs:task-definition"] == "arn:aws:ecs:ap-northeast-2:123456789012:task-definition/powehi-${split("-", k)[0]}-*:*", false)
        if s.Effect == "Allow" && (contains(flatten([s.Action]), "ecs:CreateService") || (contains(flatten([s.Action]), "ecs:UpdateService") && !contains(keys(s.Condition), "Null")))
      ]
    ]))
    error_message = "CreateService/UpdateService must constrain ecs:task-definition to the env family prefix"
  }

  assert {
    condition = alltrue(flatten([
      for k, p in aws_iam_policy.deploy : [
        for s in jsondecode(p.policy).Statement :
        contains(keys(s.Condition.StringEquals), "aws:RequestTag/Environment") || contains(keys(s.Condition.StringEquals), "ecs:CreateAction")
        if s.Effect == "Allow" && anytrue([for a in flatten([s.Action]) : contains(["ecs:TagResource", "rds:AddTagsToResource", "elasticache:AddTagsToResource", "ec2:CreateTags"], a)])
      ]
    ]))
    error_message = "every Tag/AddTags allow must carry aws:RequestTag/Environment"
  }

  assert {
    condition = alltrue(flatten([
      for k, p in aws_iam_policy.deploy : [
        for s in jsondecode(p.policy).Statement :
        contains(keys(s.Condition.StringEquals), "ecs:CreateAction")
        if s.Effect == "Allow" && s.Sid == "EcsTagOnCreate"
      ]
    ]))
    error_message = "ecs:TagResource on create must be gated by ecs:CreateAction"
  }
}

run "iam_paths_denied_and_env_keys_strict" {
  command = apply

  assert {
    condition = alltrue([
      for env in ["staging", "prod"] :
      strcontains(aws_iam_policy.guardrail[env].policy, "role/*/*") && strcontains(aws_iam_policy.guardrail[env].policy, "policy/*/*")
    ])
    error_message = "guardrail must deny role/*/* and policy/*/* (IAM path tricks)"
  }

  assert {
    condition = (
      jsondecode(aws_iam_policy.deploy["staging-iam"].policy).Statement[0].Condition.StringEquals["iam:PermissionsBoundary"] == "arn:aws:iam::123456789012:policy/powehi-boundary-staging" &&
      jsondecode(aws_iam_policy.deploy["prod-iam"].policy).Statement[0].Condition.StringEquals["iam:PermissionsBoundary"] == "arn:aws:iam::123456789012:policy/powehi-boundary-prod" &&
      strcontains(aws_iam_policy.guardrail["prod"].policy, "policy/powehi-boundary-prod") &&
      !strcontains(aws_iam_policy.guardrail["prod"].policy, "policy/powehi-boundary-staging")
    )
    error_message = "each env's CreateRole must require its own distinct boundary ARN"
  }
}

run "hyphenated_env_key_rejected" {
  command = plan

  variables {
    github_environments = { "stag-ing" = "staging" }
  }

  expect_failures = [var.github_environments]
}

run "guardrail_denies_are_a_separate_policy" {
  command = apply

  assert {
    condition = alltrue([
      for env in ["staging", "prod"] :
      strcontains(aws_iam_policy.guardrail[env].policy, "iam:CreatePolicyVersion") &&
      strcontains(aws_iam_policy.guardrail[env].policy, "iam:UpdateAssumeRolePolicy") &&
      strcontains(aws_iam_policy.guardrail[env].policy, "iam:DeleteOpenIDConnectProvider") &&
      strcontains(aws_iam_policy.guardrail[env].policy, "iam:CreateAccessKey") &&
      strcontains(aws_iam_policy.guardrail[env].policy, "NotResource")
    ])
    error_message = "guardrail must deny policy-version, trust, OIDC and credential mutations"
  }

  assert {
    condition = alltrue([
      for env in ["staging", "prod"] :
      !strcontains(aws_iam_policy.guardrail[env].name, "-svc-") &&
      !strcontains(aws_iam_policy.workload_boundary[env].name, "-svc-") &&
      !strcontains(aws_iam_role.deploy[env].name, "-svc-")
    ])
    error_message = "protected names must not fall inside the writable svc prefix"
  }

  assert {
    condition = alltrue([
      for env in ["staging", "prod"] : contains(
        [for a in aws_iam_role_policy_attachment.guardrail : a.role], aws_iam_role.deploy[env].name
      )
    ])
    error_message = "guardrail must be attached to each deploy role"
  }
}

# The mocked provider does not enforce the 6144-character managed-policy quota; check it here.
run "deploy_policies_fit_the_iam_size_quota" {
  command = apply

  assert {
    condition     = alltrue([for k, p in aws_iam_policy.deploy : length(p.policy) <= 6144])
    error_message = "a managed policy exceeds the 6144-character IAM quota; split it"
  }
}

run "deploy_trust_is_pinned_to_main" {
  command = apply

  assert {
    condition = alltrue([for e in ["staging", "prod"] :
      jsondecode(aws_iam_role.deploy[e].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:ref"] == "refs/heads/main"
    ])
    error_message = "deploy roles must require ref = refs/heads/main"
  }
}
