# Exercise 3 — ABAC by Project Tag
#
# AUTHORIZED USE ONLY.  Deploy this Terraform stack only into a test AWS
# account you personally own.  `terraform apply` against a real account
# provisions real resources that cost real money.  Tear down with
# `terraform destroy` when the exercise is complete.
#
# This file is a complete, runnable Terraform stack that demonstrates the
# canonical ABAC pattern described in Lecture 1 and elaborated in
# Lecture 2:
#
#   - Two principals (a Role per environment).
#   - Two resources (an S3 bucket per project).
#   - A SINGLE ABAC policy that grants access only when the principal's
#     Project tag equals the resource's Project tag.
#
# The pattern scales: adding a new project means tagging the new role
# and the new bucket; no policy changes are required.
#
# Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_attribute-based-access-control.html
#
# To work through this exercise:
#   1. Read the file top-to-bottom; predict what each resource will do.
#   2. `terraform init && terraform plan` — read the plan output.
#   3. `terraform apply` — confirm the resources land.
#   4. Assume the apollo_role; verify you can list/read the apollo bucket.
#   5. Assume the apollo_role; verify you CANNOT touch the beacon bucket.
#   6. Repeat with beacon_role.
#   7. `terraform destroy` — tear down.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Course      = "C6-Week11"
      Exercise    = "03-abac-by-project-tag"
      Environment = "test"
    }
  }
}

# ---------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------

variable "principal_account_id" {
  type        = string
  description = "The AWS account ID that will assume the per-project roles. For a single-account lab, set this to the same account as the resources."
}

variable "project_names" {
  type        = list(string)
  description = "The list of project names that will receive ABAC-scoped buckets and roles."
  default     = ["apollo", "beacon"]
}

# ---------------------------------------------------------------------
# One S3 bucket per project, tagged with the project name
# ---------------------------------------------------------------------

resource "aws_s3_bucket" "project_buckets" {
  for_each = toset(var.project_names)
  bucket   = "c6-week11-abac-${each.key}-${random_id.suffix.hex}"

  tags = {
    Project = each.key
  }
}

resource "aws_s3_bucket_versioning" "project_buckets" {
  for_each = aws_s3_bucket.project_buckets
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "project_buckets" {
  for_each = aws_s3_bucket.project_buckets
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "project_buckets" {
  for_each                = aws_s3_bucket.project_buckets
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "random_id" "suffix" {
  byte_length = 4
}

# ---------------------------------------------------------------------
# One IAM role per project, tagged with the project name
# ---------------------------------------------------------------------

resource "aws_iam_role" "project_roles" {
  for_each = toset(var.project_names)
  name     = "c6-week11-abac-${each.key}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.principal_account_id}:root"
      }
      Action = "sts:AssumeRole"
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      }
    }]
  })

  tags = {
    Project = each.key
  }
}

# ---------------------------------------------------------------------
# The SINGLE ABAC policy that authorises access on tag match
# ---------------------------------------------------------------------

resource "aws_iam_policy" "abac_project_match" {
  name        = "c6-week11-abac-project-match"
  description = "Grants S3 access to project buckets when the principal's Project tag equals the resource's Project tag."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RequireTLS"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "ListBucketsOnTagMatch"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning"
        ]
        Resource = "arn:aws:s3:::c6-week11-abac-*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = "$${aws:PrincipalTag/Project}"
          }
        }
      },
      {
        Sid    = "ReadWriteObjectsOnTagMatch"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObjectVersion",
          "s3:DeleteObjectVersion"
        ]
        Resource = "arn:aws:s3:::c6-week11-abac-*/*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = "$${aws:PrincipalTag/Project}"
          }
        }
      },
      {
        Sid    = "TaggingDiscipline"
        Effect = "Deny"
        Action = [
          "s3:PutBucketTagging",
          "s3:DeleteBucketTagging",
          "s3:PutObjectTagging",
          "s3:DeleteObjectTagging"
        ]
        Resource = "*"
        Condition = {
          "ForAnyValue:StringEquals" = {
            "aws:TagKeys" = ["Project"]
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------
# Attach the single ABAC policy to every project role
# ---------------------------------------------------------------------

resource "aws_iam_role_policy_attachment" "project_role_abac" {
  for_each   = aws_iam_role.project_roles
  role       = each.value.name
  policy_arn = aws_iam_policy.abac_project_match.arn
}

# ---------------------------------------------------------------------
# Outputs — the verification handles you will use to test the policy
# ---------------------------------------------------------------------

output "bucket_arns_by_project" {
  description = "Map of project name to the bucket ARN for that project."
  value = {
    for proj, bucket in aws_s3_bucket.project_buckets :
    proj => bucket.arn
  }
}

output "role_arns_by_project" {
  description = "Map of project name to the role ARN for that project."
  value = {
    for proj, role in aws_iam_role.project_roles :
    proj => role.arn
  }
}

output "verification_commands" {
  description = "Suggested verification calls after `terraform apply` succeeds."
  value = {
    apollo_ok = "aws s3 ls s3://${aws_s3_bucket.project_buckets["apollo"].id} --profile apollo-session"
    apollo_denied_on_beacon = "aws s3 ls s3://${aws_s3_bucket.project_buckets["beacon"].id} --profile apollo-session    # expect AccessDenied"
    beacon_ok = "aws s3 ls s3://${aws_s3_bucket.project_buckets["beacon"].id} --profile beacon-session"
    beacon_denied_on_apollo = "aws s3 ls s3://${aws_s3_bucket.project_buckets["apollo"].id} --profile beacon-session    # expect AccessDenied"
  }
}
