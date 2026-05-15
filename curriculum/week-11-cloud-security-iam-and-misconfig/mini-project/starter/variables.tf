# Inputs to the mini-project starter stack.
#
# Every variable has a safe default that keeps the stack within the AWS
# free tier when applied.  Override only after reading the stack's
# defects (see main.tf comments) and after setting a billing alarm.

variable "region" {
  type        = string
  description = "AWS region to apply into.  Default: us-east-1 (free-tier eligible)."
  default     = "us-east-1"
  validation {
    condition     = contains(["us-east-1", "us-west-2", "eu-west-1"], var.region)
    error_message = "Use us-east-1, us-west-2, or eu-west-1 for the lab.  Other regions may incur higher costs."
  }
}

variable "create_ebs_volume" {
  type        = bool
  description = "Provision the deliberately-unencrypted EBS volume.  Default off; flip on only if you want the live finding."
  default     = false
}

variable "create_rds" {
  type        = bool
  description = "Provision the deliberately-public, deliberately-unencrypted RDS instance.  Default off; an RDS micro instance costs ~$15/month outside the free tier."
  default     = false
}

variable "apply_destructive" {
  type        = bool
  description = "Master switch to acknowledge that you have read every defect in main.tf and accept the consequences of `terraform apply`.  Required by the optional pre-apply check below."
  default     = false
}

# Optional: emit a friendly error if apply_destructive is false but the
# user runs `terraform apply`.  Implemented as a precondition on a
# null_resource that runs at apply time.
resource "null_resource" "apply_destructive_check" {
  count = var.apply_destructive ? 1 : 0
  triggers = {
    acknowledged = tostring(var.apply_destructive)
  }
}

# The minimal IAM role to allow Prowler scanning — provisioned only
# when the user opts in.
variable "create_prowler_audit_role" {
  type        = bool
  description = "Provision the c6-week11-prowler-audit role.  Default off; flip on to enable Prowler against this account."
  default     = false
}

variable "prowler_principal_arn" {
  type        = string
  description = "The IAM user or role ARN that will assume the Prowler audit role.  Required when create_prowler_audit_role is true."
  default     = ""
}

resource "aws_iam_role" "prowler_audit" {
  count = var.create_prowler_audit_role ? 1 : 0
  name  = "c6-week11-prowler-audit"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.prowler_principal_arn
      }
      Action = "sts:AssumeRole"
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "prowler_security_audit" {
  count      = var.create_prowler_audit_role ? 1 : 0
  role       = aws_iam_role.prowler_audit[0].name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "prowler_view_only" {
  count      = var.create_prowler_audit_role ? 1 : 0
  role       = aws_iam_role.prowler_audit[0].name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}
