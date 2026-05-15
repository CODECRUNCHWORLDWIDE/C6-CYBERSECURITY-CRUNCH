# Remediation Log Template

Curriculum starter template for the Week 11 mini-project. Students copy this file to `remediation.md` in their working directory and append one row per remediation as it is applied. The log is the audit trail; an auditor reads this log to confirm that every scanner detection was addressed in code with a traceable commit.

---

## Format

Each remediation row contains:

- **Check ID** — the scanner check identifier (Prowler check name or Checkov check ID).
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL as recorded in the baseline scan log.
- **Resource** — the Terraform resource address that was changed (e.g., `aws_s3_bucket.public_reports`).
- **File** — the path to the Terraform file changed.
- **Lines changed** — the line range or one-sentence description of the change.
- **Commit SHA** — the short SHA of the commit that applied the change.
- **Date (UTC)** — the date the change landed in your branch.
- **Verified by** — which scanner re-run verified the fix and the new finding count for that check.
- **Justification** — one sentence stating why this change resolves the detection.

---

## Remediation table

| # | Check ID                                  | Severity | Resource                                | File         | Lines changed                              | Commit  | Date       | Verified by | Justification                                                     |
|--:|-------------------------------------------|----------|-----------------------------------------|--------------|--------------------------------------------|---------|------------|-------------|-------------------------------------------------------------------|
| 1 | `s3_bucket_public_access` / `CKV_AWS_20`  | CRITICAL | `aws_s3_bucket.public_reports`          | `main.tf`    | Removed the `aws_s3_bucket_acl` block.     |         |            | Checkov     | Public ACL removed; bucket reverts to private default.            |
| 2 | `CKV_AWS_53`-`56`                          | MEDIUM   | `aws_s3_bucket.public_reports`          | `main.tf`    | Added `aws_s3_bucket_public_access_block` with all four flags = true. |         |            | Checkov     | BlockPublicAccess settings prevent any future public exposure.    |
| 3 | `CKV_AWS_19`                               | MEDIUM   | `aws_s3_bucket.public_reports`          | `main.tf`    | Added `aws_s3_bucket_server_side_encryption_configuration` with AES256. |         |            | Checkov     | Default encryption enabled at rest.                               |
| 4 | `CKV_AWS_21`                               | MEDIUM   | `aws_s3_bucket.public_reports`          | `main.tf`    | Added `aws_s3_bucket_versioning` with status "Enabled".            |         |            | Checkov     | Versioning protects against accidental and malicious deletes.     |
| 5 | `iam_user_mfa_enabled_console_access`     | MEDIUM   | `aws_iam_user.legacy_ci`                | `main.tf`    | Removed the user, access key, and login profile entirely.          |         |            | Prowler     | The IAM user is replaced by an SSO permission-set assignment.     |
| 6 | `iam_role_cross_account_unrestricted`     | CRITICAL | `aws_iam_role.open_trust`               | `main.tf`    | Narrowed `Principal` from `{AWS: "*"}` to a specific account ARN; added MFA condition. |         |            | Prowler     | Trust is now scoped to one named account and MFA-conditioned.     |
| 7 | `CKV_AWS_40` / `iam_policy_avoid_full_access` | HIGH | `aws_iam_policy.full_access`            | `main.tf`    | Replaced `Action: "*"` and `Resource: "*"` with a service-scoped allow-list. |         |            | Both        | Worker role's permissions are now scoped to its actual workload.  |
| 8 | `CKV_AWS_24`                               | HIGH     | `aws_security_group.wide_open`          | `main.tf`    | Narrowed SSH `cidr_blocks` from `["0.0.0.0/0"]` to the lab's bastion CIDR. |         |            | Checkov     | SSH is no longer reachable from the public internet.              |
| 9 | `CKV_AWS_25`                               | HIGH     | `aws_security_group.wide_open`          | `main.tf`    | Removed the RDP ingress rule entirely.     |         |            | Checkov     | RDP is not used in this lab; the rule was a defect.               |
|10 | `cloudtrail_multi_region_enabled`         | HIGH     | (new) `aws_cloudtrail.main`             | `main.tf`    | Added a multi-region CloudTrail trail with log-file validation and KMS encryption. |         |            | Prowler     | Account is now auditable end-to-end.                              |
|11 | `CKV_AWS_3` / `ec2_ebs_volume_encryption` | HIGH     | `aws_ebs_volume.unencrypted`            | `main.tf`    | Set `encrypted = true` and added a KMS-key ARN.                      |         |            | Both        | EBS encryption protects against snapshot-extraction attacks.      |
|12 | `CKV_AWS_44` / `ec2_securitygroup_default_restrict_traffic` | MEDIUM | (new) `aws_default_security_group.lab`  | `main.tf`    | Added the resource with no ingress and no egress rules.            |         |            | Both        | Default SG is no longer permissive.                               |
|13 | `CKV_AWS_17` / `rds_instance_no_public_access` | HIGH | `aws_db_instance.public_rds`            | `main.tf`    | Set `publicly_accessible = false` and confirmed subnet group is private. |         |            | Both        | RDS endpoint is no longer publicly reachable.                     |
|14 | `CKV_AWS_16` / `rds_instance_storage_encrypted` | HIGH | `aws_db_instance.public_rds`            | `main.tf`    | Set `storage_encrypted = true` and `kms_key_id` to the app key.       |         |            | Both        | Database storage is encrypted at rest.                            |
|15 | `CKV_AWS_7` / `kms_cmk_rotation_enabled`  | MEDIUM   | `aws_kms_key.app_key`                   | `main.tf`    | Set `enable_key_rotation = true`.          |         |            | Both        | KMS key rotation aligns with CIS 3.8.                             |

---

## Per-row commit-message format

The mini-project asks that each remediation be a separate commit with the check identifier in the subject. Suggested format:

```
fix(<scope>): <one-liner> [<check-id>]

<two-to-four sentence body explaining the change>

Verified-by: <Prowler | Checkov | both>
Refs: <CIS-Benchmark-control or NIST-control or AWS-doc-URL>
```

Example:

```
fix(s3): enable default encryption on the reports bucket [CKV_AWS_19]

The starter bucket shipped without a server-side encryption block, which
Checkov CKV_AWS_19 and CIS AWS Foundations control 2.1.1 flag as a
HIGH-severity defect. Add an aws_s3_bucket_server_side_encryption
_configuration resource with SSE-S3 (AES256) as the default algorithm.

Verified-by: Checkov 3.x
Refs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
```

---

## Final rescan summary

After all rows are completed, run the three scanners again and record the final counts here.

| Scanner   | Baseline failing | Final failing | Delta (resolved) |
|-----------|-----------------:|--------------:|------------------:|
| Prowler   |                  |               |                   |
| Checkov   |                  |               |                   |
| ScoutSuite|                  |               |                   |

A passing mini-project has zero HIGH-and-CRITICAL findings remaining across all three scanners, with every baseline-detected check accounted for in the table above.
