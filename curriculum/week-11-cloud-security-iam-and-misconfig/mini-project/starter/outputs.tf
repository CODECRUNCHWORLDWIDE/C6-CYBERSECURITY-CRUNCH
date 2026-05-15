# Outputs from the mini-project starter stack.
#
# These outputs surface the misconfigurations for inspection.  Each is
# verbose by design: a real production stack would not echo
# bucket-public state and access-key IDs, but the mini-project does so
# the student can verify scanner findings against the actual state.

output "public_bucket_name" {
  description = "The name of the deliberately-public reports bucket."
  value       = aws_s3_bucket.public_reports.id
}

output "public_bucket_arn" {
  description = "The ARN of the deliberately-public reports bucket."
  value       = aws_s3_bucket.public_reports.arn
}

output "legacy_ci_user_arn" {
  description = "The ARN of the deliberately-MFA-less IAM user."
  value       = aws_iam_user.legacy_ci.arn
}

output "legacy_ci_access_key_id" {
  description = "The deliberately-unrotated access key ID.  Do NOT commit this to a public repo (the secret is sensitive; AWS would auto-disable a publicly-discovered key)."
  value       = aws_iam_access_key.legacy_ci.id
  sensitive   = true
}

output "open_trust_role_arn" {
  description = "The ARN of the role whose trust policy permits any AWS principal to assume it."
  value       = aws_iam_role.open_trust.arn
}

output "worker_role_arn" {
  description = "The ARN of the worker role attached to the full-access policy."
  value       = aws_iam_role.worker.arn
}

output "full_access_policy_arn" {
  description = "The ARN of the deliberately-administrative-equivalent policy."
  value       = aws_iam_policy.full_access.arn
}

output "wide_open_security_group_id" {
  description = "The security group ID that permits 0.0.0.0/0 on SSH and RDP."
  value       = aws_security_group.wide_open.id
}

output "lab_vpc_id" {
  description = "The lab VPC ID."
  value       = aws_vpc.lab.id
}

output "kms_key_id" {
  description = "The KMS key ID for the deliberately-non-rotating key."
  value       = aws_kms_key.app_key.key_id
}

output "kms_key_arn" {
  description = "The KMS key ARN for the deliberately-non-rotating key."
  value       = aws_kms_key.app_key.arn
}

output "ebs_volume_id" {
  description = "The deliberately-unencrypted EBS volume ID, if provisioned."
  value       = var.create_ebs_volume ? aws_ebs_volume.unencrypted[0].id : ""
}

output "rds_instance_endpoint" {
  description = "The deliberately-public RDS endpoint, if provisioned."
  value       = var.create_rds ? aws_db_instance.public_rds[0].endpoint : ""
  sensitive   = true
}

output "missing_resources_checklist" {
  description = "Resources the starter stack does NOT create — each absence is itself a finding the student remediates by adding the resource."
  value = {
    bucket_public_access_block       = "MISSING — add aws_s3_bucket_public_access_block.public_reports"
    bucket_versioning                = "MISSING — add aws_s3_bucket_versioning.public_reports"
    bucket_default_encryption        = "MISSING — add aws_s3_bucket_server_side_encryption_configuration.public_reports"
    cloudtrail_trail                 = "MISSING — add aws_cloudtrail.main (multi-region, log-file validation, KMS-encrypted)"
    cloudtrail_logs_bucket           = "MISSING — dedicated bucket for the trail with object-lock and versioning"
    default_security_group_restrict  = "MISSING — add aws_default_security_group with no ingress/egress rules"
    iam_account_password_policy      = "MISSING — add aws_iam_account_password_policy with strong requirements"
    aws_iam_account_alias            = "MISSING — add aws_iam_account_alias to make the account human-recognisable"
  }
}
