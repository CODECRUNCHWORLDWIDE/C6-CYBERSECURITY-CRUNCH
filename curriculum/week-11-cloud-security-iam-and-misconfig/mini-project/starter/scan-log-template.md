# Scan Log Template

Curriculum starter template for the Week 11 mini-project. Students copy this file to `scan-log.md` in their working directory and fill in one row per scanner detection from the baseline runs. Sort by severity descending; within the same severity, by scanner check identifier.

---

## Account context

| Field             | Value                                    |
|-------------------|------------------------------------------|
| Account ID        | `redacted-XXXXXX` (do not commit the real ID) |
| Region            | (e.g., `us-east-1`)                      |
| Scan date (UTC)   | (YYYY-MM-DD)                             |
| Prowler version   | (`prowler --version` output)             |
| Checkov version   | (`checkov --version` output)             |
| ScoutSuite version| (`scout --version` output)               |
| Student handle    |                                          |

---

## Detection table

| # | Severity | Scanner   | Check ID                                          | Resource                                 | One-line summary                                       |
|--:|----------|-----------|---------------------------------------------------|------------------------------------------|--------------------------------------------------------|
| 1 | CRITICAL | Prowler   | `s3_bucket_public_access`                         | `c6-week11-public-reports-XXXXX`         | Bucket has a public ACL.                               |
| 2 | CRITICAL | Prowler   | `iam_role_cross_account_unrestricted`             | `c6-week11-open-trust`                   | Role trust policy permits any AWS principal.           |
| 3 | HIGH     | Checkov   | `CKV_AWS_40`                                      | `aws_iam_policy.full_access`             | Policy has `Action: "*"` and `Resource: "*"`.          |
| 4 | HIGH     | Checkov   | `CKV_AWS_24`                                      | `aws_security_group.wide_open`           | Security group permits `0.0.0.0/0` on port 22.         |
| 5 | HIGH     | Checkov   | `CKV_AWS_25`                                      | `aws_security_group.wide_open`           | Security group permits `0.0.0.0/0` on port 3389.       |
| 6 | HIGH     | Prowler   | `cloudtrail_multi_region_enabled`                 | (account-level)                          | No multi-region CloudTrail trail exists.               |
| 7 | HIGH     | Checkov   | `CKV_AWS_3`                                       | `aws_ebs_volume.unencrypted`             | EBS volume is unencrypted.                             |
| 8 | HIGH     | Checkov   | `CKV_AWS_17`                                      | `aws_db_instance.public_rds`             | RDS instance is publicly accessible.                   |
| 9 | HIGH     | Checkov   | `CKV_AWS_16`                                      | `aws_db_instance.public_rds`             | RDS instance is unencrypted.                           |
|10 | MEDIUM   | Checkov   | `CKV_AWS_148`                                     | `aws_iam_user.legacy_ci`                 | IAM user has access key and no MFA enforcement.        |
|11 | MEDIUM   | Checkov   | `CKV_AWS_19`                                      | `aws_s3_bucket.public_reports`           | Bucket has no default server-side encryption.          |
|12 | MEDIUM   | Checkov   | `CKV_AWS_21`                                      | `aws_s3_bucket.public_reports`           | Bucket has no versioning.                              |
|13 | MEDIUM   | Checkov   | `CKV_AWS_53` `_54` `_55` `_56`                    | `aws_s3_bucket.public_reports`           | Bucket has no `BlockPublicAccess` configuration.       |
|14 | MEDIUM   | Prowler   | `ec2_securitygroup_default_restrict_traffic`      | (default VPC SG)                         | Default security group is not restricted.              |
|15 | MEDIUM   | Checkov   | `CKV_AWS_7`                                       | `aws_kms_key.app_key`                    | KMS key has rotation disabled.                         |

Add additional rows for any detections unique to one scanner. The starter rows above are the fifteen the file deliberately produces; expect a small number of additional rows from scanner-specific checks.

---

## Cross-scanner reconciliation

| Detection theme            | Prowler | Checkov | ScoutSuite |
|----------------------------|:-------:|:-------:|:----------:|
| Public S3 bucket           | yes     | yes     | yes        |
| Bucket encryption missing  | yes     | yes     | yes        |
| Bucket versioning missing  | yes     | yes     | partial    |
| Open IAM role trust        | yes     | yes     | yes        |
| Admin-equivalent policy    | yes     | yes     | yes        |
| 0.0.0.0/0 on SSH           | yes     | yes     | yes        |
| 0.0.0.0/0 on RDP           | yes     | yes     | yes        |
| CloudTrail missing         | yes     | partial | yes        |
| EBS unencrypted            | yes     | yes     | yes        |
| Public RDS                 | yes     | yes     | yes        |
| Unencrypted RDS            | yes     | yes     | yes        |
| KMS rotation off           | yes     | yes     | yes        |
| MFA-less IAM user          | yes     | yes     | yes        |
| Default SG unrestricted    | yes     | partial | yes        |

The "partial" cells reflect that some checks only fire when a particular resource exists or only fire at runtime (Prowler) vs at IaC time (Checkov).

---

## Suppression and acceptance notes

If a detection is intentionally suppressed (because it does not apply to this codebase) or accepted (because the risk has been weighed and accepted), note it here with a one-paragraph justification. Every suppression or acceptance has a name attached and an expiry date.

| Check ID   | Reason for suppression / acceptance | Owner | Expiry |
|------------|-------------------------------------|-------|--------|
| (none yet) |                                     |       |        |
