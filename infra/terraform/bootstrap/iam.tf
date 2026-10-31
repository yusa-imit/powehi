# Roles and permissions. Region-locked and tag/name-locked per env.
#
# Naming contract (what makes the privilege-escalation guard sound):
#   deploy roles        powehi-<env>-deploy              (never writable by any deploy role)
#   plan role           powehi-plan-readonly             (never writable)
#   boundary policies   powehi-boundary-<env>            (never writable)
#   guardrail policies  powehi-guardrail-<env>           (never writable, attached to deploy)
#   deploy policies     powehi-deploy-<env>-<part>       (never writable)
#   workload roles      powehi-<env>-svc-*               (the ONLY roles a deploy role may touch)
#   workload policies   powehi-<env>-svc-*               (the ONLY policies a deploy role may touch)
# No writable pattern can match a protected name, and the guardrail policy additionally
# denies every role/policy mutation whose target is NOT the env's svc pattern (NotResource).

locals {
  region = var.aws_region
  acct   = local.account_id

  # Tag every resource carries (providers' default_tags in envs/*). Mutations are only
  # allowed on resources whose tag equals the deploy role's own env.
  env_tag = "Environment"

  ec2_arn = "arn:aws:ec2:${var.aws_region}:${local.account_id}:*"

  # EC2 creates come in two kinds. Top-level resources (a VPC, an IGW, an EIP) have no parent;
  # the new resource's RequestTag is the only possible gate. Child resources are created INSIDE
  # a parent (SG/subnet/route table/NACL/flow log/EOIGW/endpoint in a VPC, a NAT gateway in a
  # subnet with an EIP, an endpoint with route tables/subnets/SGs). For those the parent ARN is
  # also an authorised resource of the call, so it must carry aws:ResourceTag/Environment=<env>;
  # otherwise staging could plant resources in the prod VPC by tagging the NEW resource "staging".
  # Deterministic (policy name is fixed), so each env's conditions are checkable offline.
  boundary_arn = {
    for env, _ in var.github_environments :
    env => "arn:aws:iam::${local.account_id}:policy/powehi-boundary-${env}"
  }

  ecs_taskdef_arn = {
    for env, _ in var.github_environments :
    env => "arn:aws:ecs:${var.aws_region}:${local.account_id}:task-definition/powehi-${env}-*:*"
  }

  ec2_pre = "arn:aws:ec2:${var.aws_region}:${local.account_id}"

  ec2_toplevel_create_actions = ["ec2:CreateVpc", "ec2:CreateInternetGateway", "ec2:AllocateAddress"]
  ec2_toplevel_new_arns = [
    "${local.ec2_pre}:vpc/*", "${local.ec2_pre}:internet-gateway/*", "${local.ec2_pre}:elastic-ip/*",
  ]

  ec2_child_create_actions = [
    "ec2:CreateSubnet", "ec2:CreateSecurityGroup", "ec2:CreateRouteTable",
    "ec2:CreateNatGateway", "ec2:CreateVpcEndpoint", "ec2:CreateNetworkAcl",
    "ec2:CreateFlowLogs", "ec2:CreateEgressOnlyInternetGateway",
  ]
  ec2_child_new_arns = [
    for t in [
      "subnet", "security-group", "route-table", "natgateway", "vpc-endpoint", "network-acl",
      "vpc-flow-log", "egress-only-internet-gateway",
    ] : "${local.ec2_pre}:${t}/*"
  ]
  # Everything a child create may reference as parent / attachment.
  ec2_parent_arns = [
    for t in ["vpc", "subnet", "route-table", "security-group", "elastic-ip"] :
    "${local.ec2_pre}:${t}/*"
  ]

  ec2_create_action_names = [
    for a in concat(local.ec2_toplevel_create_actions, local.ec2_child_create_actions) :
    trimprefix(a, "ec2:")
  ]
}

# --- Per-env permissions boundary for roles that workloads (ECS tasks) will run as -------
# Name is deliberately outside every writable pattern (not powehi-<env>-svc-*).
resource "aws_iam_policy" "workload_boundary" {
  for_each = var.github_environments

  name        = "powehi-boundary-${each.key}"
  description = "Upper bound for every IAM role created by the ${each.key} deploy role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${local.region}:${local.acct}:log-group:/powehi/${each.key}/*:*"
      },
      {
        Sid      = "ReadOwnSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:${local.region}:${local.acct}:secret:powehi/${each.key}/*"
      },
      {
        Sid       = "Metrics"
        Effect    = "Allow"
        Action    = ["cloudwatch:PutMetricData"]
        Resource  = "*"
        Condition = { StringEquals = { "cloudwatch:namespace" = "Powehi/${each.key}" } }
      },
    ]
  })
}

# --- Deploy roles (one per env) ------------------------------------------------------------
resource "aws_iam_role" "deploy" {
  for_each = var.github_environments

  name                 = "powehi-${each.key}-deploy"
  description          = "GitHub Actions deploy role for ${each.key}"
  assume_role_policy   = local.trust_policies["deploy-${each.key}"]
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "deploy_state" {
  for_each = var.github_environments

  name = "state-${each.key}"
  role = aws_iam_role.deploy[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ListOwnStatePrefix"
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.state.arn
        Condition = { StringLike = { "s3:prefix" = ["${each.key}/*"] } }
      },
      {
        # DeleteObject is for the use_lockfile `.tflock` object.
        Sid      = "ReadWriteOwnState"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.state.arn}/${each.key}/*"
      },
      {
        Sid      = "StateKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = aws_kms_key.state.arn
      },
    ]
  })
}

# Deploy permissions are split into managed policies (inline role policies share a 10 KiB
# aggregate cap). Each is resource-scoped by name prefix and/or by the env tag:
#   create  -> aws:RequestTag/Environment == env
#   mutate  -> aws:ResourceTag/Environment == env
locals {
  deploy_policy_docs = {
    for env, _ in var.github_environments : env => {
      ec2 = {
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "CreateTopLevelTagged"
            Effect   = "Allow"
            Action   = local.ec2_toplevel_create_actions
            Resource = local.ec2_toplevel_new_arns
            Condition = { StringEquals = {
              "aws:RequestedRegion"             = local.region
              "aws:RequestTag/${local.env_tag}" = env
            } }
          },
          {
            Sid      = "CreateChildNewResourceTagged"
            Effect   = "Allow"
            Action   = local.ec2_child_create_actions
            Resource = local.ec2_child_new_arns
            Condition = { StringEquals = {
              "aws:RequestedRegion"             = local.region
              "aws:RequestTag/${local.env_tag}" = env
            } }
          },
          {
            # The parent (VPC/subnet/route table/SG/EIP) must already belong to this env.
            Sid      = "CreateChildInOwnEnvParentOnly"
            Effect   = "Allow"
            Action   = local.ec2_child_create_actions
            Resource = local.ec2_parent_arns
            Condition = { StringEquals = {
              "aws:RequestedRegion"              = local.region
              "aws:ResourceTag/${local.env_tag}" = env
            } }
          },
          {
            Sid      = "TagOnCreate"
            Effect   = "Allow"
            Action   = "ec2:CreateTags"
            Resource = local.ec2_arn
            Condition = { StringEquals = {
              "aws:RequestedRegion"             = local.region
              "ec2:CreateAction"                = local.ec2_create_action_names
              "aws:RequestTag/${local.env_tag}" = env
            } }
          },
          {
            Sid      = "RetagOwnEnvOnly"
            Effect   = "Allow"
            Action   = "ec2:CreateTags"
            Resource = local.ec2_arn
            Condition = { StringEquals = {
              "aws:ResourceTag/${local.env_tag}" = env
              "aws:RequestTag/${local.env_tag}"  = env
            } }
          },
          {
            Sid    = "MutateOwnEnvOnly"
            Effect = "Allow"
            Action = [
              "ec2:DeleteVpc", "ec2:DeleteSubnet", "ec2:DeleteSecurityGroup",
              "ec2:DeleteRouteTable", "ec2:DeleteInternetGateway", "ec2:DeleteNatGateway",
              "ec2:ReleaseAddress", "ec2:DeleteVpcEndpoints", "ec2:DeleteNetworkAcl",
              "ec2:DeleteFlowLogs", "ec2:DeleteEgressOnlyInternetGateway", "ec2:DeleteTags",
              "ec2:ModifyVpcAttribute", "ec2:ModifySubnetAttribute", "ec2:ModifyVpcEndpoint",
              "ec2:ModifySecurityGroupRules", "ec2:AttachInternetGateway",
              "ec2:DetachInternetGateway", "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
              "ec2:AssociateAddress", "ec2:DisassociateAddress", "ec2:CreateRoute",
              "ec2:DeleteRoute", "ec2:ReplaceRoute", "ec2:AuthorizeSecurityGroupIngress",
              "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupIngress",
              "ec2:RevokeSecurityGroupEgress", "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
              "ec2:UpdateSecurityGroupRuleDescriptionsEgress", "ec2:CreateNetworkAclEntry",
              "ec2:DeleteNetworkAclEntry", "ec2:ReplaceNetworkAclEntry",
              "ec2:ReplaceNetworkAclAssociation",
            ]
            Resource = local.ec2_arn
            Condition = { StringEquals = {
              "aws:RequestedRegion"              = local.region
              "aws:ResourceTag/${local.env_tag}" = env
            } }
          },
        ]
      }

      compute = {
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "EcsCreateClusterAndCapacityProviderTagged"
            Effect = "Allow"
            Action = ["ecs:CreateCluster", "ecs:CreateCapacityProvider"]
            Resource = [
              "arn:aws:ecs:${local.region}:${local.acct}:cluster/powehi-${env}-*",
              "arn:aws:ecs:${local.region}:${local.acct}:capacity-provider/powehi-${env}-*",
            ]
            Condition = { StringEquals = { "aws:RequestTag/${local.env_tag}" = env } }
          },
          {
            # A service may only run a task definition from this env's family prefix.
            Sid      = "EcsCreateServiceTagged"
            Effect   = "Allow"
            Action   = ["ecs:CreateService"]
            Resource = "arn:aws:ecs:${local.region}:${local.acct}:service/powehi-${env}-*/*"
            Condition = {
              StringEquals = { "aws:RequestTag/${local.env_tag}" = env }
              ArnLike      = { "ecs:task-definition" = local.ecs_taskdef_arn[env] }
            }
          },
          {
            # Tagging while creating only (ecs:CreateAction); later retags are EcsRetag below.
            Sid    = "EcsTagOnCreate"
            Effect = "Allow"
            Action = ["ecs:TagResource"]
            Resource = concat(
              [
                "arn:aws:ecs:${local.region}:${local.acct}:cluster/powehi-${env}-*",
                "arn:aws:ecs:${local.region}:${local.acct}:service/powehi-${env}-*/*",
                "arn:aws:ecs:${local.region}:${local.acct}:capacity-provider/powehi-${env}-*",
              ],
              [local.ecs_taskdef_arn[env]],
            )
            Condition = { StringEquals = {
              "ecs:CreateAction"                = ["CreateCluster", "CreateService", "CreateCapacityProvider", "RegisterTaskDefinition"]
              "aws:RequestTag/${local.env_tag}" = env
            } }
          },
          {
            Sid    = "EcsRetagOwnEnvOnly"
            Effect = "Allow"
            Action = ["ecs:TagResource"]
            Resource = [
              "arn:aws:ecs:${local.region}:${local.acct}:cluster/powehi-${env}-*",
              "arn:aws:ecs:${local.region}:${local.acct}:service/powehi-${env}-*/*",
              "arn:aws:ecs:${local.region}:${local.acct}:capacity-provider/powehi-${env}-*",
            ]
            Condition = { StringEquals = {
              "aws:ResourceTag/${local.env_tag}" = env
              "aws:RequestTag/${local.env_tag}"  = env
            } }
          },
          {
            Sid    = "EcsMutateOwnEnvOnly"
            Effect = "Allow"
            Action = [
              "ecs:UpdateCluster", "ecs:UpdateClusterSettings", "ecs:DeleteCluster",
              "ecs:PutClusterCapacityProviders", "ecs:DeleteService",
              "ecs:UpdateCapacityProvider", "ecs:DeleteCapacityProvider", "ecs:UntagResource",
            ]
            Resource = [
              "arn:aws:ecs:${local.region}:${local.acct}:cluster/powehi-${env}-*",
              "arn:aws:ecs:${local.region}:${local.acct}:service/powehi-${env}-*/*",
              "arn:aws:ecs:${local.region}:${local.acct}:capacity-provider/powehi-${env}-*",
            ]
            Condition = { StringEquals = { "aws:ResourceTag/${local.env_tag}" = env } }
          },
          {
            # UpdateService that swaps the task definition must stay in this env's family prefix.
            Sid      = "EcsUpdateServiceNewTaskDefinition"
            Effect   = "Allow"
            Action   = ["ecs:UpdateService"]
            Resource = "arn:aws:ecs:${local.region}:${local.acct}:service/powehi-${env}-*/*"
            Condition = {
              StringEquals = { "aws:ResourceTag/${local.env_tag}" = env }
              ArnLike      = { "ecs:task-definition" = local.ecs_taskdef_arn[env] }
            }
          },
          {
            # UpdateService that does not change the task definition (scale, deployment config).
            Sid      = "EcsUpdateServiceKeepTaskDefinition"
            Effect   = "Allow"
            Action   = ["ecs:UpdateService"]
            Resource = "arn:aws:ecs:${local.region}:${local.acct}:service/powehi-${env}-*/*"
            Condition = {
              StringEquals = { "aws:ResourceTag/${local.env_tag}" = env }
              Null         = { "ecs:task-definition" = "true" }
            }
          },
          {
            # RegisterTaskDefinition does not support resource-level permissions (the family is
            # not an authorisable resource), so a family prefix cannot be enforced here. The
            # damage is bounded: a stray task definition can only be RUN through CreateService /
            # UpdateService (ArnLike on powehi-<env>-* above), and iam:PassRole only admits svc
            # roles. Residual: see README (recommend an account split for prod).
            Sid       = "EcsRegisterTaskDefinition"
            Effect    = "Allow"
            Action    = ["ecs:RegisterTaskDefinition"]
            Resource  = "*"
            Condition = { StringEquals = { "aws:RequestTag/${local.env_tag}" = env, "aws:RequestedRegion" = local.region } }
          },
          {
            Sid      = "EcsDeregisterOwnTaskDefinitions"
            Effect   = "Allow"
            Action   = ["ecs:DeregisterTaskDefinition", "ecs:DeleteTaskDefinitions"]
            Resource = "arn:aws:ecs:${local.region}:${local.acct}:task-definition/powehi-${env}-*:*"
          },
          {
            Sid    = "RdsCreateTagged"
            Effect = "Allow"
            Action = [
              "rds:CreateDBInstance", "rds:CreateDBCluster", "rds:CreateDBSubnetGroup",
              "rds:CreateDBParameterGroup", "rds:CreateDBClusterParameterGroup",
            ]
            Resource = [
              for t in ["db", "cluster", "subgrp", "pg", "cluster-pg"] :
              "arn:aws:rds:${local.region}:${local.acct}:${t}:powehi-${env}-*"
            ]
            Condition = { StringEquals = { "aws:RequestTag/${local.env_tag}" = env } }
          },
          {
            Sid    = "RdsMutateOwnEnvOnly"
            Effect = "Allow"
            Action = [
              "rds:ModifyDBInstance", "rds:ModifyDBCluster", "rds:ModifyDBSubnetGroup",
              "rds:ModifyDBParameterGroup", "rds:ModifyDBClusterParameterGroup",
              "rds:ResetDBParameterGroup", "rds:DeleteDBInstance", "rds:DeleteDBCluster",
              "rds:DeleteDBSubnetGroup", "rds:DeleteDBParameterGroup",
              "rds:DeleteDBClusterParameterGroup", "rds:RebootDBInstance",
              "rds:StartDBInstance", "rds:StopDBInstance", "rds:RemoveTagsFromResource",
            ]
            Resource = [
              for t in ["db", "cluster", "subgrp", "pg", "cluster-pg"] :
              "arn:aws:rds:${local.region}:${local.acct}:${t}:powehi-${env}-*"
            ]
            Condition = { StringEquals = { "aws:ResourceTag/${local.env_tag}" = env } }
          },
          {
            Sid    = "RdsRetagOwnEnvOnly"
            Effect = "Allow"
            Action = ["rds:AddTagsToResource"]
            Resource = [
              for t in ["db", "cluster", "subgrp", "pg", "cluster-pg"] :
              "arn:aws:rds:${local.region}:${local.acct}:${t}:powehi-${env}-*"
            ]
            Condition = { StringEquals = {
              "aws:ResourceTag/${local.env_tag}" = env
              "aws:RequestTag/${local.env_tag}"  = env
            } }
          },
          {
            Sid    = "RdsSnapshotsOwnPrefix"
            Effect = "Allow"
            Action = ["rds:CreateDBSnapshot", "rds:DeleteDBSnapshot", "rds:CreateDBClusterSnapshot", "rds:DeleteDBClusterSnapshot"]
            Resource = [
              for t in ["snapshot", "cluster-snapshot", "db", "cluster"] :
              "arn:aws:rds:${local.region}:${local.acct}:${t}:powehi-${env}-*"
            ]
          },
          {
            Sid    = "ElastiCacheCreateTagged"
            Effect = "Allow"
            Action = [
              "elasticache:CreateReplicationGroup", "elasticache:CreateCacheCluster",
              "elasticache:CreateCacheSubnetGroup", "elasticache:CreateCacheParameterGroup",
            ]
            Resource = [
              for t in ["replicationgroup", "cluster", "subnetgroup", "parametergroup"] :
              "arn:aws:elasticache:${local.region}:${local.acct}:${t}:powehi-${env}-*"
            ]
            Condition = { StringEquals = { "aws:RequestTag/${local.env_tag}" = env } }
          },
          {
            Sid    = "ElastiCacheMutateOwnEnvOnly"
            Effect = "Allow"
            Action = [
              "elasticache:ModifyReplicationGroup", "elasticache:ModifyCacheCluster",
              "elasticache:ModifyCacheSubnetGroup", "elasticache:ModifyCacheParameterGroup",
              "elasticache:ResetCacheParameterGroup", "elasticache:DeleteReplicationGroup",
              "elasticache:DeleteCacheCluster", "elasticache:DeleteCacheSubnetGroup",
              "elasticache:DeleteCacheParameterGroup", "elasticache:RemoveTagsFromResource",
            ]
            Resource = [
              for t in ["replicationgroup", "cluster", "subnetgroup", "parametergroup"] :
              "arn:aws:elasticache:${local.region}:${local.acct}:${t}:powehi-${env}-*"
            ]
            Condition = { StringEquals = { "aws:ResourceTag/${local.env_tag}" = env } }
          },
          {
            Sid    = "ElastiCacheRetagOwnEnvOnly"
            Effect = "Allow"
            Action = ["elasticache:AddTagsToResource"]
            Resource = [
              for t in ["replicationgroup", "cluster", "subnetgroup", "parametergroup"] :
              "arn:aws:elasticache:${local.region}:${local.acct}:${t}:powehi-${env}-*"
            ]
            Condition = { StringEquals = {
              "aws:ResourceTag/${local.env_tag}" = env
              "aws:RequestTag/${local.env_tag}"  = env
            } }
          },
        ]
      }

      observability = {
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "OwnLogGroups"
            Effect = "Allow"
            Action = [
              "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy",
              "logs:DeleteRetentionPolicy", "logs:TagResource", "logs:UntagResource",
              "logs:TagLogGroup", "logs:UntagLogGroup", "logs:ListTagsForResource",
              "logs:ListTagsLogGroup", "logs:AssociateKmsKey", "logs:DisassociateKmsKey",
              "logs:PutMetricFilter", "logs:DeleteMetricFilter",
            ]
            Resource = [
              "arn:aws:logs:${local.region}:${local.acct}:log-group:/powehi/${env}/*",
              "arn:aws:logs:${local.region}:${local.acct}:log-group:/powehi/${env}/*:*",
            ]
          },
          {
            Sid    = "OwnAlarmsAndDashboards"
            Effect = "Allow"
            Action = [
              "cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:TagResource",
              "cloudwatch:UntagResource", "cloudwatch:ListTagsForResource",
              "cloudwatch:PutDashboard", "cloudwatch:DeleteDashboards",
            ]
            Resource = [
              "arn:aws:cloudwatch:${local.region}:${local.acct}:alarm:powehi-${env}-*",
              "arn:aws:cloudwatch::${local.acct}:dashboard/powehi-${env}-*",
            ]
          },
          {
            Sid    = "OwnSecrets"
            Effect = "Allow"
            Action = [
              "secretsmanager:CreateSecret", "secretsmanager:PutSecretValue",
              "secretsmanager:UpdateSecret", "secretsmanager:DeleteSecret",
              "secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue",
              "secretsmanager:GetResourcePolicy", "secretsmanager:TagResource",
              "secretsmanager:UntagResource", "secretsmanager:RestoreSecret",
            ]
            Resource = "arn:aws:secretsmanager:${local.region}:${local.acct}:secret:powehi/${env}/*"
          },
        ]
      }

      iam = {
        Version = "2012-10-17"
        Statement = [
          {
            Sid    = "CreateBoundedSvcRoles"
            Effect = "Allow"
            Action = ["iam:CreateRole", "iam:PutRolePermissionsBoundary"]
            Resource = [
              "arn:aws:iam::${local.acct}:role/powehi-${env}-svc-*",
            ]
            Condition = {
              StringEquals = {
                "iam:PermissionsBoundary" = local.boundary_arn[env]
              }
            }
          },
          {
            # No UpdateAssumeRolePolicy: a role's trust is fixed at creation; changing it
            # means replacing the role. No AttachRolePolicy here (see the allow-list below).
            Sid    = "ManageSvcRoles"
            Effect = "Allow"
            Action = [
              "iam:GetRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateRoleDescription",
              "iam:TagRole", "iam:UntagRole", "iam:PutRolePolicy", "iam:GetRolePolicy",
              "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:ListRolePolicies",
              "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole",
            ]
            Resource = "arn:aws:iam::${local.acct}:role/powehi-${env}-svc-*"
          },
          {
            Sid      = "AttachAllowListedPoliciesOnly"
            Effect   = "Allow"
            Action   = "iam:AttachRolePolicy"
            Resource = "arn:aws:iam::${local.acct}:role/powehi-${env}-svc-*"
            Condition = {
              ArnLike = {
                "iam:PolicyARN" = [
                  "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
                  "arn:aws:iam::${local.acct}:policy/powehi-${env}-svc-*",
                ]
              }
            }
          },
          {
            Sid    = "ManageSvcPolicies"
            Effect = "Allow"
            Action = [
              "iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:GetPolicyVersion",
              "iam:ListPolicyVersions", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion",
              "iam:TagPolicy", "iam:UntagPolicy",
            ]
            Resource = "arn:aws:iam::${local.acct}:policy/powehi-${env}-svc-*"
          },
          {
            Sid       = "PassSvcRolesToEcsTasksOnly"
            Effect    = "Allow"
            Action    = "iam:PassRole"
            Resource  = "arn:aws:iam::${local.acct}:role/powehi-${env}-svc-*"
            Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
          },
          {
            Sid      = "ServiceLinkedRoles"
            Effect   = "Allow"
            Action   = "iam:CreateServiceLinkedRole"
            Resource = "arn:aws:iam::${local.acct}:role/aws-service-role/*"
            Condition = {
              StringEquals = {
                "iam:AWSServiceName" = [
                  "ecs.amazonaws.com",
                  "rds.amazonaws.com",
                  "elasticache.amazonaws.com",
                ]
              }
            }
          },
        ]
      }
    }
  }

  deploy_policies = merge([
    for env, parts in local.deploy_policy_docs : {
      for part, doc in parts : "${env}-${part}" => { env = env, part = part, doc = doc }
    }
  ]...)
}

resource "aws_iam_policy" "deploy" {
  for_each = local.deploy_policies

  name   = "powehi-deploy-${each.value.env}-${each.value.part}"
  policy = jsonencode(each.value.doc)
}

resource "aws_iam_role_policy_attachment" "deploy" {
  for_each = local.deploy_policies

  role       = aws_iam_role.deploy[each.value.env].name
  policy_arn = aws_iam_policy.deploy[each.key].arn
}

# Read-only discovery that AWS cannot scope to a resource (Describe*/List*, secret listing).
# No write action lives here.
#trivy:ignore:AVD-AWS-0057 Describe/List on Resource * is how refresh works; read-only, region-locked
resource "aws_iam_policy" "deploy_discovery" {
  name = "powehi-deploy-discovery"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DescribeRegional"
        Effect = "Allow"
        Action = [
          "ec2:Describe*", "ecs:Describe*", "ecs:List*", "rds:Describe*",
          "rds:ListTagsForResource", "elasticache:Describe*", "elasticache:ListTagsForResource",
          "logs:DescribeLogGroups", "cloudwatch:DescribeAlarms", "cloudwatch:ListDashboards",
          "cloudwatch:GetDashboard", "secretsmanager:ListSecrets",
          "secretsmanager:GetRandomPassword",
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = local.region } }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "deploy_discovery" {
  for_each = var.github_environments

  role       = aws_iam_role.deploy[each.key].name
  policy_arn = aws_iam_policy.deploy_discovery.arn
}

# --- Guardrail: explicit Deny, a SEPARATE managed policy the deploy role cannot edit --------
# Its name (powehi-guardrail-<env>) and the deploy/boundary/plan names match no allowed
# pattern, and the Deny below uses NotResource so everything but the svc pattern is covered.
resource "aws_iam_policy" "guardrail" {
  for_each = var.github_environments

  name        = "powehi-guardrail-${each.key}"
  description = "Explicit denies for the ${each.key} deploy role; not editable by it"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyRoleMutationOutsideSvcPrefix"
        Effect = "Deny"
        Action = [
          "iam:CreateRole", "iam:UpdateRole", "iam:UpdateRoleDescription", "iam:DeleteRole",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy",
          "iam:DetachRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:PutRolePermissionsBoundary",
          "iam:DeleteRolePermissionsBoundary", "iam:TagRole", "iam:UntagRole",
        ]
        NotResource = "arn:aws:iam::${local.acct}:role/powehi-${each.key}-svc-*"
      },
      {
        Sid    = "DenyPolicyMutationOutsideSvcPrefix"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
          "iam:DeletePolicyVersion", "iam:DeletePolicy", "iam:TagPolicy", "iam:UntagPolicy",
        ]
        NotResource = "arn:aws:iam::${local.acct}:policy/powehi-${each.key}-svc-*"
      },
      {
        # IAM paths would let a name like role/x/powehi-<env>-svc-y dodge name-prefix reasoning;
        # svc roles/policies live at the root path only.
        Sid      = "DenyIamPathTricks"
        Effect   = "Deny"
        Action   = ["iam:CreateRole", "iam:CreatePolicy"]
        Resource = ["arn:aws:iam::${local.acct}:role/*/*", "arn:aws:iam::${local.acct}:policy/*/*"]
      },
      {
        Sid      = "DenyTrustAndBoundaryRemovalEverywhere"
        Effect   = "Deny"
        Action   = ["iam:UpdateAssumeRolePolicy", "iam:DeleteRolePermissionsBoundary"]
        Resource = "*"
      },
      {
        Sid      = "DenyRoleWithoutBoundary"
        Effect   = "Deny"
        Action   = ["iam:CreateRole", "iam:PutRolePermissionsBoundary"]
        Resource = "*"
        Condition = {
          StringNotEquals = { "iam:PermissionsBoundary" = local.boundary_arn[each.key] }
        }
      },
      {
        Sid    = "DenyIdentityAndFederation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser", "iam:DeleteUser", "iam:CreateAccessKey", "iam:UpdateAccessKey",
          "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:CreateGroup",
          "iam:AddUserToGroup", "iam:PutUserPolicy", "iam:AttachUserPolicy",
          "iam:PutGroupPolicy", "iam:AttachGroupPolicy", "iam:PutUserPermissionsBoundary",
          "iam:DeleteUserPermissionsBoundary", "iam:CreateOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider", "iam:AddClientIDToOpenIDConnectProvider",
          "iam:RemoveClientIDFromOpenIDConnectProvider",
          "iam:UpdateOpenIDConnectProviderThumbprint", "iam:CreateSAMLProvider",
          "iam:UpdateSAMLProvider", "iam:DeleteSAMLProvider", "iam:UploadServerCertificate",
          "iam:UpdateAccountPasswordPolicy", "iam:CreateServiceSpecificCredential",
        ]
        Resource = "*"
      },
      {
        # ec2:Create* covers children created inside another env's tagged parent (SG/subnet/
        # route table/NACL/endpoint/NAT/flow log) in addition to the allow-side parent check.
        # A brand-new resource has no ResourceTag yet, so top-level creates are unaffected.
        Sid    = "DenyMutatingAnotherEnvsResources"
        Effect = "Deny"
        Action = [
          "ec2:Delete*", "ec2:Modify*", "ec2:Terminate*", "ec2:Attach*", "ec2:Detach*",
          "ec2:Associate*", "ec2:Disassociate*", "ec2:Authorize*", "ec2:Revoke*",
          "ec2:Replace*", "ec2:Release*", "ec2:Create*",
          "ecs:Update*", "ecs:Delete*", "ecs:TagResource", "ecs:UntagResource",
          "ecs:PutClusterCapacityProviders", "rds:Modify*", "rds:Delete*", "rds:Reboot*",
          "rds:Stop*", "rds:AddTagsToResource", "rds:RemoveTagsFromResource",
          "elasticache:Modify*", "elasticache:Delete*", "elasticache:AddTagsToResource",
          "elasticache:RemoveTagsFromResource",
        ]
        Resource = "*"
        Condition = {
          Null            = { "aws:ResourceTag/${local.env_tag}" = "false" }
          StringNotEquals = { "aws:ResourceTag/${local.env_tag}" = each.key }
        }
      },
      {
        Sid    = "DenyRemovingTheEnvTag"
        Effect = "Deny"
        Action = [
          "ec2:DeleteTags", "ecs:UntagResource", "rds:RemoveTagsFromResource",
          "elasticache:RemoveTagsFromResource", "logs:UntagResource", "logs:UntagLogGroup",
          "secretsmanager:UntagResource", "cloudwatch:UntagResource",
        ]
        Resource  = "*"
        Condition = { "ForAnyValue:StringEquals" = { "aws:TagKeys" = [local.env_tag] } }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "guardrail" {
  for_each = var.github_environments

  role       = aws_iam_role.deploy[each.key].name
  policy_arn = aws_iam_policy.guardrail[each.key].arn
}

# --- Read-only plan role for pull requests ---------------------------------------------------
# Its trust (`sub = repo:...:pull_request`) is issued to a workflow run from ANY same-repo
# branch PR, including one that edits the workflow file itself. CODEOWNERS does not stop that:
# it gates merging, not running. So this role is treated as reachable by any branch author and
# is limited to what that author may see anyway:
#   - state: only `staging/*` objects (state holds secrets, so NOT prod); no writes, no lock
#     file (CI must run `tofu plan -lock=false`)
#   - KMS decrypt only when called through S3 (kms:ViaService)
#   - no secret values. Prod plans run only in the Environment-gated job under the prod
#     deploy role, which already has read/write on prod/*.
locals {
  plan_readable_state_envs = ["staging"]
}

resource "aws_iam_role" "plan" {
  name                 = "powehi-plan-readonly"
  description          = "GitHub Actions read-only tofu plan for pull requests (staging state only)"
  assume_role_policy   = local.trust_policies["plan"]
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "plan_state" {
  name = "state-read"
  role = aws_iam_role.plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ListStagingStateOnly"
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.state.arn
        Condition = { StringLike = { "s3:prefix" = [for e in local.plan_readable_state_envs : "${e}/*"] } }
      },
      {
        Sid      = "ReadStagingStateOnly"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = [for e in local.plan_readable_state_envs : "${aws_s3_bucket.state.arn}/${e}/*"]
      },
      {
        Sid      = "DecryptStateViaS3Only"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = aws_kms_key.state.arn
        Condition = { StringEquals = {
          "kms:ViaService" = "s3.${local.region}.amazonaws.com"
        } }
      },
      {
        Sid         = "DenyNonStagingStateRead"
        Effect      = "Deny"
        Action      = "s3:GetObject*"
        NotResource = [for e in local.plan_readable_state_envs : "${aws_s3_bucket.state.arn}/${e}/*"]
      },
    ]
  })
}

#trivy:ignore:AVD-AWS-0057 Describe/List/Get on Resource * is how read-only refresh works
resource "aws_iam_role_policy" "plan_refresh" {
  name = "refresh-readonly"
  role = aws_iam_role.plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DescribeRegional"
        Effect = "Allow"
        Action = [
          "ec2:Describe*", "ecs:Describe*", "ecs:List*", "rds:Describe*", "rds:List*",
          "elasticache:Describe*", "elasticache:List*", "logs:Describe*", "logs:List*",
          "logs:ListTagsForResource", "cloudwatch:Describe*", "cloudwatch:List*", "cloudwatch:Get*",
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = local.region } }
      },
      {
        Sid    = "SecretsMetadataOnly"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets",
          "secretsmanager:GetResourcePolicy",
        ]
        Resource = "*"
      },
      {
        Sid    = "IamRead"
        Effect = "Allow"
        Action = [
          "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
          "iam:ListPolicyVersions", "iam:ListInstanceProfilesForRole",
        ]
        Resource = [
          "arn:aws:iam::${local.acct}:role/powehi-*",
          "arn:aws:iam::${local.acct}:policy/powehi-*",
        ]
      },
      {
        Sid      = "DenySecretValues"
        Effect   = "Deny"
        Action   = ["secretsmanager:GetSecretValue", "ssm:GetParameter*"]
        Resource = "*"
      },
    ]
  })
}
