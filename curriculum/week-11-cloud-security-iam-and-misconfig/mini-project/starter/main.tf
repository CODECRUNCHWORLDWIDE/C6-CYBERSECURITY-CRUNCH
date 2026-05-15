# ====================================================================
# Mini-Project Starter — DELIBERATELY MISCONFIGURED Terraform stack.
#
# AUTHORIZED USE ONLY.  Apply only to an AWS account you personally
# own.  Set a billing alarm at $5 before applying.  Run `terraform
# destroy` immediately after the rescan confirms remediation.
#
# This file contains FIFTEEN deliberate misconfigurations enumerated
# in Lecture 3 section 5.  The student's mini-project job is to scan,
# identify, and remediate each.  Do NOT use this stack as a template
# for any real workload.
# ====================================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Course      = "C6-Week11"
      Stack       = "mini-project-starter"
      Environment = "test"
      DoNotUse    = "deliberately-misconfigured"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

# --------------------------------------------------------------------
# FINDING 1 & 2 & 3 & 4 — An S3 bucket that is:
#   1. publicly ACLed (`acl = "public-read"`),
#   2. without BlockPublicAccess settings,
#   3. without default server-side encryption,
#   4. without versioning.
# Detection: Prowler s3_bucket_public_access; Checkov CKV_AWS_20,
# CKV_AWS_53-56, CKV_AWS_19, CKV_AWS_21.
# --------------------------------------------------------------------

resource "aws_s3_bucket" "public_reports" {
  bucket = "c6-week11-public-reports-${random_id.suffix.hex}"
}

# DEFECT: public ACL.  Remediation: remove this block entirely;
# rely on the bucket's default private ACL.
resource "aws_s3_bucket_acl" "public_reports" {
  bucket = aws_s3_bucket.public_reports.id
  acl    = "public-read"
}

# DEFECT: no aws_s3_bucket_public_access_block resource.
# Remediation: add one with all four flags = true.

# DEFECT: no aws_s3_bucket_server_side_encryption_configuration.
# Remediation: add one with SSE-S3 or SSE-KMS.

# DEFECT: no aws_s3_bucket_versioning.
# Remediation: add one with status = "Enabled".

# --------------------------------------------------------------------
# FINDING 5 — An IAM user with an access key and console login but
# without MFA.
# Detection: Prowler iam_user_mfa_enabled_console_access,
# iam_user_no_access_keys.  Checkov CKV_AWS_148.
# --------------------------------------------------------------------

resource "aws_iam_user" "legacy_ci" {
  name = "c6-week11-legacy-ci"
}

resource "aws_iam_access_key" "legacy_ci" {
  user = aws_iam_user.legacy_ci.name
}

resource "aws_iam_user_login_profile" "legacy_ci" {
  user                    = aws_iam_user.legacy_ci.name
  password_reset_required = false
  password_length         = 16
}

# DEFECT: no aws_iam_user_policy_attachment with MFA enforcement.
# Remediation: deprecate this user entirely.  Replace with an IAM
# Identity Center permission-set assignment.

# --------------------------------------------------------------------
# FINDING 6 — An IAM role with a trust policy that permits any AWS
# principal (`Principal: {AWS: "*"}`) to assume it.
# Detection: Prowler iam_role_cross_account_unrestricted.
# Checkov CKV_AWS_60.
# --------------------------------------------------------------------

resource "aws_iam_role" "open_trust" {
  name = "c6-week11-open-trust"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "*"   # DEFECT: scope to a specific account or service.
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# --------------------------------------------------------------------
# FINDING 7 — An IAM policy with `Action: "*"` and `Resource: "*"`,
# attached to a non-administrator role.
# Detection: Prowler iam_policy_no_administrative_privileges,
# iam_policy_avoid_full_access.  Checkov CKV_AWS_40.
# --------------------------------------------------------------------

resource "aws_iam_policy" "full_access" {
  name        = "c6-week11-full-access"
  description = "Attaches admin-equivalent permissions to a worker role."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "*"           # DEFECT: scope to specific actions.
      Resource = "*"         # DEFECT: scope to specific resources.
    }]
  })
}

resource "aws_iam_role" "worker" {
  name = "c6-week11-worker"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker_full" {
  role       = aws_iam_role.worker.name
  policy_arn = aws_iam_policy.full_access.arn
}

# --------------------------------------------------------------------
# FINDING 8 & 9 & 12 — Security groups that:
#   8. permit 0.0.0.0/0 on port 22 (SSH),
#   9. permit 0.0.0.0/0 on port 3389 (RDP),
#  12. the default VPC security group is unrestricted (we DO NOT
#      manage the default SG here; the finding fires because the
#      default exists and is unmanaged).
# Detection: Prowler ec2_securitygroup_allow_ingress_from_internet_to_any_port,
# ec2_securitygroup_default_restrict_traffic.  Checkov CKV_AWS_24,
# CKV_AWS_25, CKV_AWS_44.
# --------------------------------------------------------------------

resource "aws_vpc" "lab" {
  cidr_block           = "10.99.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "c6-week11-lab"
  }
}

resource "aws_security_group" "wide_open" {
  name        = "c6-week11-wide-open"
  description = "Deliberately misconfigured for the mini-project."
  vpc_id      = aws_vpc.lab.id

  # DEFECT: SSH from anywhere.
  ingress {
    description = "SSH from anywhere (intentional defect)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # DEFECT: RDP from anywhere.
  ingress {
    description = "RDP from anywhere (intentional defect)"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# DEFECT: we do not import or manage the default security group.
# Prowler / Checkov fire because the default SG's default rule is
# unrestricted.  Remediation: add an aws_default_security_group
# resource that revokes all ingress and egress on the default SG.

# --------------------------------------------------------------------
# FINDING 10 — CloudTrail disabled (we do not create one).
# Detection: Prowler cloudtrail_multi_region_enabled,
# cloudtrail_log_file_validation_enabled.  Checkov CKV_AWS_35,
# CKV_AWS_36 (applied conditionally — if no trail exists, these are
# missing-resource findings).
# Remediation: create a multi-region trail with log-file validation,
# write to a dedicated logs bucket with KMS encryption.
# --------------------------------------------------------------------

# DEFECT: intentional omission.  No aws_cloudtrail resource here.

# --------------------------------------------------------------------
# FINDING 11 — An EBS volume without encryption.
# Detection: Prowler ec2_ebs_volume_encryption.  Checkov CKV_AWS_3.
# --------------------------------------------------------------------

resource "aws_ebs_volume" "unencrypted" {
  count             = var.create_ebs_volume ? 1 : 0
  availability_zone = "${var.region}a"
  size              = 1
  encrypted         = false        # DEFECT: should be true.
  tags = {
    Name = "c6-week11-unencrypted"
  }
}

# --------------------------------------------------------------------
# FINDING 13 & 14 — An RDS instance that is publicly accessible and
# unencrypted.
# Detection: Prowler rds_instance_no_public_access,
# rds_instance_storage_encrypted.  Checkov CKV_AWS_17, CKV_AWS_16.
# --------------------------------------------------------------------

resource "aws_db_subnet_group" "lab" {
  count      = var.create_rds ? 1 : 0
  name       = "c6-week11-rds-subnet-group"
  subnet_ids = aws_subnet.lab[*].id
}

resource "aws_subnet" "lab" {
  count             = var.create_rds ? 2 : 0
  vpc_id            = aws_vpc.lab.id
  cidr_block        = cidrsubnet(aws_vpc.lab.cidr_block, 8, count.index)
  availability_zone = element(["${var.region}a", "${var.region}b"], count.index)
  tags = {
    Name = "c6-week11-subnet-${count.index}"
  }
}

resource "aws_db_instance" "public_rds" {
  count                  = var.create_rds ? 1 : 0
  identifier             = "c6-week11-public-rds"
  engine                 = "postgres"
  engine_version         = "16.3"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "postgres"
  password               = "DeliberatelyWeakPassword123"
  publicly_accessible    = true    # DEFECT: should be false.
  storage_encrypted      = false   # DEFECT: should be true.
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.lab[0].name
  vpc_security_group_ids = [aws_security_group.wide_open.id]
}

# --------------------------------------------------------------------
# FINDING 15 — A KMS key without rotation enabled.
# Detection: Prowler kms_cmk_rotation_enabled.  Checkov CKV_AWS_7.
# --------------------------------------------------------------------

resource "aws_kms_key" "app_key" {
  description             = "c6-week11 application key (deliberately defective)"
  deletion_window_in_days = 7
  enable_key_rotation     = false   # DEFECT: should be true.
}

resource "aws_kms_alias" "app_key" {
  name          = "alias/c6-week11-app"
  target_key_id = aws_kms_key.app_key.key_id
}
