# Lecture 3 — Misconfiguration Scanning with Prowler, Checkov, and ScoutSuite

> *Lectures 1 and 2 taught the policy language a defender writes. Lecture 3 introduces the policy language a defender reads — automatically, repeatedly, on every commit and every account — to find the gaps the hand-written policies left behind. Three free open-source tools cover the surface: Prowler for the running cloud account, Checkov for the IaC text *before* it is deployed, ScoutSuite for the multi-cloud audit report.*

---

## 1. The misconfiguration problem

Verizon's annual Data Breach Investigations Report has, every year from 2019 onward, identified misconfiguration as the single largest category of root cause for cloud-related breaches. The Capital One disclosure of 2019 (an SSRF chained into an over-permissive EC2 instance profile, ~100 million records exposed); the Twitch source-code repository leak of 2021 (a poorly-segmented EC2 instance with broad S3 access); the Pegasus Airlines passenger-data exposure of 2022 (~6.5 terabytes of unsecured AWS S3 content); the Toyota customer-data exposure of 2023 (a misconfigured cloud environment exposed for ten years); the dozens of smaller incidents that appear in the Have I Been Pwned timeline every month — they are, with strikingly few exceptions, the same misconfiguration in the same kind of S3 bucket policy or the same kind of IAM role trust.

The pattern is not exotic. The pattern is *humans writing JSON*. The fix is not a smarter human; the fix is automated machinery that reads the JSON and flags the patterns we know to be dangerous before they reach production. The machinery exists, is free, is open-source, and is the subject of this lecture.

Three tools cover the practical surface:

- **Prowler** — scans a live cloud account through the provider SDK. Read-only API calls; produces findings ranked by severity. AWS coverage is deepest; Azure and GCP coverage is growing rapidly.
- **Checkov** — scans the IaC text *before* the resources are ever provisioned. Static analysis on Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM, Serverless, OpenAPI, GitHub Actions. The earliest, cheapest layer of defence.
- **ScoutSuite** — scans a live cloud account across multiple providers and produces a single navigable HTML report. AWS, Azure, GCP, OCI, Aliyun. Less granular than Prowler on AWS specifically, but the multi-cloud report is operationally useful.

The three are complementary. The mini-project runs all three; the real-world deployment runs all three plus their commercial successors as the budget allows. The free open-source tools are sufficient for the work of this week and for the work of most small-to-medium cloud accounts in the real world.

---

## 2. Prowler

**Prowler** began life in 2016 as a single Bash script by Toni de la Fuente at NCC Group. The original script automated the CIS AWS Foundations Benchmark's audit procedures — for each of the 100-odd controls in the benchmark, the script ran the AWS CLI command that proved or disproved the control's compliance, and emitted a one-line verdict. The script became popular, the project moved to GitHub, the maintainer founded ProwlerPro to monetise a hosted offering, and the open-source core was rewritten in Python in 2022 (version 3) and again in 2023 (version 4, with Azure and GCP support). As of May 2026, Prowler 5.x is the current line.

### Installing Prowler

The recommended path is `pipx`:

```bash
pipx install prowler
prowler --version
```

`pipx` installs Prowler into its own isolated virtual environment and exposes the `prowler` command on the PATH. This avoids polluting the system Python. If `pipx` is not available, a virtualenv works too:

```bash
python3 -m venv ~/.venvs/prowler
source ~/.venvs/prowler/bin/activate
pip install prowler
```

The first run downloads the check catalogue and validates the AWS credentials:

```bash
aws sts get-caller-identity --profile c6-week11
prowler aws --profile c6-week11
```

The default scan runs every AWS check Prowler has against every region your credentials can reach. On a small account this takes 2–5 minutes; on a real account it can take 30. The check catalogue as of Prowler 5.x is over 400 checks.

### Prowler output

Prowler emits to multiple destinations simultaneously. The default outputs:

- **stdout** — colour-coded `PASS` / `FAIL` / `WARN` / `MUTED` lines as the scan runs.
- **CSV** — `output/prowler-output-<account>-<timestamp>.csv`. One row per check result. Spreadsheet-friendly.
- **JSON-ASFF** — `output/prowler-output-<account>-<timestamp>.asff.json`. The AWS Security Finding Format. Stable schema; the integration target for AWS Security Hub. Exercise 5 parses this file.
- **HTML** — `output/prowler-output-<account>-<timestamp>.html`. A standalone HTML report with filtering by service, severity, and compliance framework.

A representative finding from the JSON-ASFF output:

```json
{
  "SchemaVersion": "2018-10-08",
  "Id": "prowler-iam_no_root_access_key-123456789012-us-east-1-...",
  "ProductArn": "arn:aws:securityhub:us-east-1::product/prowler/prowler",
  "GeneratorId": "prowler-iam_no_root_access_key",
  "Title": "Ensure no root account access key exists.",
  "Severity": {"Label": "CRITICAL"},
  "Resources": [
    {
      "Type": "AwsIamUser",
      "Id": "arn:aws:iam::123456789012:root",
      "Region": "us-east-1"
    }
  ],
  "Compliance": {
    "Status": "FAILED",
    "RelatedRequirements": [
      "CIS-AWS-Foundations-1.4",
      "NIST-800-53-AC-2(1)",
      "PCI-DSS-7.1.1"
    ]
  },
  "Description": "The root account has an active access key. Root account access keys provide unrestricted access and are an audit and security risk.",
  "Remediation": {
    "Recommendation": {
      "Text": "Delete the access key for the root account; rotate any credentials that referenced it.",
      "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
    }
  }
}
```

Read this carefully. The `Id` is a stable identifier; the `GeneratorId` is the check name (you can look up the check's source in Prowler's repository by this name). The `Severity.Label` is one of `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. The `Compliance.RelatedRequirements` maps the finding to specific controls in named frameworks; in this case CIS AWS Foundations control 1.4, NIST 800-53 AC-2(1), and PCI-DSS 7.1.1. A regulator who asks "do you comply with CIS 1.4?" gets a yes/no answer from this finding's `Compliance.Status`.

### Triage workflow

Prowler will produce more findings than you can address in one sitting. The triage workflow:

1. **Filter by severity.** Address `CRITICAL` first, then `HIGH`, then `MEDIUM`. `LOW` and `INFORMATIONAL` can wait for a baseline rescan.
2. **Filter by service area.** Pick one service per session: today is IAM, tomorrow is S3, the day after is CloudTrail. Context-switching between services makes the work harder.
3. **Read the remediation note.** Prowler's remediations are usually correct and link to the canonical AWS documentation page. Do not improvise; use the documented fix.
4. **Write the fix as code.** Terraform diff, CloudFormation diff, or Pulumi diff. Commit with the Prowler check ID in the commit message.
5. **Rescan.** Run Prowler again, filtered to the specific check; verify the finding has cleared.
6. **Document the change.** The remediation log records the finding ID, the date, the commit SHA, and a one-sentence justification.

### Read-only credentials for Prowler

Prowler is read-only by design. The IAM permissions it needs are `SecurityAudit` (an AWS-managed policy) plus `ViewOnlyAccess` (another AWS-managed policy) plus a small set of explicit extras for newer services not covered by either. The Prowler docs publish the canonical least-privilege policy at https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/authentication/.

Create a dedicated role for Prowler:

```hcl
resource "aws_iam_role" "prowler_audit" {
  name = "c6-week11-prowler-audit"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.security_account_id}:root" }
      Action = "sts:AssumeRole"
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "prowler_security_audit" {
  role       = aws_iam_role.prowler_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "prowler_view_only" {
  role       = aws_iam_role.prowler_audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}
```

The role's trust policy requires MFA on the session that assumes it, restricts assumption to the security account, and grants only the two read-only managed policies. Prowler runs against this role via `aws sts assume-role --role-arn arn:aws:iam::<target-account>:role/c6-week11-prowler-audit --role-session-name prowler-scan`.

---

## 3. Checkov

**Checkov** was built by Bridgecrew in 2019 specifically to find misconfigurations in Terraform before `apply`. Bridgecrew was acquired by Palo Alto Networks in 2021; the project remained open-source under Apache 2.0. Checkov has expanded its scope steadily: as of 2026, it scans Terraform, CloudFormation, Kubernetes manifests, Helm charts, Dockerfiles, ARM templates, Serverless Framework, OpenAPI specs, GitHub Actions workflows, GitLab CI workflows, and BitBucket Pipelines.

The structural advantage of Checkov over Prowler: Checkov reads *text*, not API state. The scan needs no cloud credentials. The scan runs in milliseconds-to-seconds. The scan runs *before* the resource is ever provisioned, so misconfigurations cost nothing to discover and nothing to fix.

### Installing Checkov

`pipx` again:

```bash
pipx install checkov
checkov --version
```

The first scan against a Terraform directory:

```bash
checkov --directory ./terraform
```

Output is colour-coded text, with each finding identified by a check ID (e.g., `CKV_AWS_18` for "S3 bucket should have access logging configured"):

```
Check: CKV_AWS_18: "Ensure the S3 bucket has access logging enabled"
        FAILED for resource: aws_s3_bucket.my_bucket
        File: /terraform/main.tf:14-22
        Guide: https://docs.bridgecrew.io/docs/s3_13-enable-logging
```

### Configuring Checkov

A `.checkov.yaml` at the directory root configures the scan:

```yaml
framework:
  - terraform
  - kubernetes
output:
  - cli
  - json
output-file-path: ./checkov-output
hard-fail-on:
  - HIGH
  - CRITICAL
soft-fail-on:
  - MEDIUM
  - LOW
skip-check:
  - CKV_AWS_50   # legitimately disabled — Lambda needs broader perms
download-external-modules: true
quiet: true
compact: true
```

The `hard-fail-on` / `soft-fail-on` settings drive CI behaviour: `hard-fail` makes the CI job fail (non-zero exit); `soft-fail` records the finding without failing the build. Exercise 6 builds this workflow.

### Checkov in CI

A representative GitHub Actions workflow:

```yaml
name: IaC Security
on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'kubernetes/**'

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Checkov
        run: pipx install checkov
      - name: Run Checkov
        run: checkov --config-file .checkov.yaml --directory .
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: checkov-report
          path: checkov-output/
```

The CI job runs on every pull request that touches IaC. A HIGH or CRITICAL finding fails the job; the pull request cannot merge until the finding is fixed or explicitly suppressed.

### Suppression discipline

Checkov supports two suppression mechanisms:

- **Global suppression** — `skip-check` in the config file. Skips the check for every resource. Use sparingly; only when the check is genuinely inappropriate for the codebase.
- **Per-resource suppression** — a comment on the resource:

```hcl
resource "aws_s3_bucket" "logs" {
  # checkov:skip=CKV_AWS_18:Access logging is the purpose of this bucket; cannot recurse
  bucket = "my-org-access-logs"
}
```

The comment includes the check ID and a justification. Every suppression has a justification in the comment; the grader reads them.

The discipline matters because suppression is silent — a suppressed finding does not appear in the scan output. Real codebases accumulate suppressions until the scan is meaningless. The hygiene: every suppression has an expiry date in the comment; once a quarter, an engineer reviews every suppression and removes the expired ones; the comment justification must convince an auditor.

### Custom Checkov policies

Checkov supports custom checks written either as YAML or as Python. A YAML custom check for "every S3 bucket must be tagged with `Project`":

```yaml
metadata:
  name: "Ensure every S3 bucket has a Project tag"
  id: "CKV2_CUSTOM_1"
  category: "GENERAL_SECURITY"
  severity: "HIGH"
scope:
  provider: "aws"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "tags.Project"
  operator: "exists"
```

A Python custom check has access to the full Terraform resource graph and can express arbitrary logic. The Checkov docs at https://www.checkov.io/3.Custom%20Policies/Custom%20Policies%20Overview.html document both syntaxes.

---

## 4. ScoutSuite

**ScoutSuite** is NCC Group's multi-cloud auditor. It began as a Python rewrite of Scout2 in 2018; it now covers AWS, Azure, GCP, OCI, and Aliyun. GPL-2.0 licensed. Maintained by NCC's security consultancy practice.

ScoutSuite's distinguishing feature is the HTML report. Where Prowler emits a flat finding list and Checkov emits a text-line-per-finding, ScoutSuite emits a navigable single-page HTML application: every service has a tab, every resource is a clickable card, every finding is a coloured indicator with a click-through to the resource's configuration. For an audit conversation in which a non-engineer needs to walk through the findings with you, the ScoutSuite report is the better artefact.

### Installing ScoutSuite

`pipx`:

```bash
pipx install scoutsuite
scout --version
```

The AWS scan:

```bash
scout aws --profile c6-week11
```

Output is written to `scoutsuite-report/<account-id>/`. Open `scoutsuite-report/<account-id>/scoutsuite-report-<account>.html` in a browser. The report is a self-contained HTML file — no server, no external resources, no telemetry. You can email the file to an auditor.

### ScoutSuite finding model

Each ScoutSuite finding is keyed by a *dotted-key path* into the cloud's configuration state. A finding's JSON definition:

```json
{
  "description": "Ensure that all S3 buckets have versioning enabled",
  "rationale": "Versioning protects against accidental and malicious deletes...",
  "remediation": "Enable versioning on every S3 bucket via the API or console.",
  "compliance": [
    {"name": "CIS-AWS-Foundations", "version": "v1.4.0", "reference": "2.1.3"}
  ],
  "level": "warning",
  "dashboard_name": "Buckets",
  "display_path": "s3.buckets.id",
  "path": "s3.buckets.id",
  "conditions": [
    "and",
    [
      "s3.buckets.id.versioning.Status",
      "notEqual",
      "Enabled"
    ]
  ]
}
```

The `path` is the dotted-key into ScoutSuite's representation of the cloud state; the `conditions` is the predicate. Extending ScoutSuite means writing one JSON file with the rule definition plus, if the rule needs new state, a Python module that fetches and structures it.

### Where ScoutSuite fits

ScoutSuite's strengths:

- **Multi-cloud in one tool**. One install, five providers.
- **Navigable HTML report**. Better for audit conversations than a flat list.
- **Service-organised view**. The report is naturally organised by service; you can answer "how is our S3 footprint?" without grepping.

ScoutSuite's weaknesses:

- **AWS coverage is shallower than Prowler's.** Prowler has ~400 AWS checks; ScoutSuite has ~150. For a deep AWS audit, run Prowler too.
- **The HTML report is a snapshot**. ScoutSuite produces a point-in-time report; it does not run continuously or alert on changes. Pair with CloudTrail-driven alerting for change detection.
- **Performance is slower than Prowler**. ScoutSuite tends to call more APIs per service; expect a small account to take 10-15 minutes.

The practical pattern: run ScoutSuite quarterly to produce a snapshot for governance review; run Prowler weekly (or in CI) for fast feedback; run Checkov on every commit for the fastest possible feedback.

---

## 5. The deliberate-misconfig stack

The mini-project ships a Terraform stack at `mini-project/starter/main.tf` that contains, by deliberate design, the following findings. The student's job is to spot them, scan-detect them, and remediate them.

1. **An S3 bucket with a public ACL.** `acl = "public-read"`. Prowler check `s3_bucket_public_access`. Checkov check `CKV_AWS_20`. CIS AWS Foundations 2.1.5.
2. **An S3 bucket with no `BlockPublicAccess` settings.** Allows the bucket policy to drift to public. Prowler check `s3_account_level_public_access_blocks`. Checkov check `CKV_AWS_53` through `CKV_AWS_56`.
3. **An S3 bucket with no encryption at rest.** Prowler check `s3_bucket_default_encryption`. Checkov check `CKV_AWS_19`.
4. **An S3 bucket with no versioning.** Prowler check `s3_bucket_object_versioning`. Checkov check `CKV_AWS_21`.
5. **An IAM user with an access key but no MFA.** Prowler checks `iam_user_mfa_enabled_console_access` and `iam_user_no_access_keys`. Checkov check `CKV_AWS_148`.
6. **An IAM role with a trust policy permitting any AWS principal.** `"Principal": {"AWS": "*"}` on `sts:AssumeRole`. Prowler check `iam_role_cross_account_unrestricted`. Checkov check `CKV_AWS_60`.
7. **An IAM policy with `Action: "*"` and `Resource: "*"`.** Attached to a non-administrator role. Prowler checks `iam_policy_no_administrative_privileges` and `iam_policy_avoid_full_access`. Checkov check `CKV_AWS_40`.
8. **A security group permitting `0.0.0.0/0` on port 22 (SSH).** Prowler check `ec2_securitygroup_allow_ingress_from_internet_to_any_port`. Checkov check `CKV_AWS_24`.
9. **A security group permitting `0.0.0.0/0` on port 3389 (RDP).** Prowler check `ec2_securitygroup_allow_ingress_from_internet_to_any_port`. Checkov check `CKV_AWS_25`.
10. **CloudTrail disabled.** Or scoped to one region only. Prowler checks `cloudtrail_multi_region_enabled` and `cloudtrail_log_file_validation_enabled`. Checkov checks `CKV_AWS_35` and `CKV_AWS_36`.
11. **An EBS volume without encryption.** Prowler check `ec2_ebs_volume_encryption`. Checkov check `CKV_AWS_3`.
12. **A VPC default security group permitting any traffic.** The default security group's existence with a default rule is a CIS finding regardless of whether anything uses it. Prowler check `ec2_securitygroup_default_restrict_traffic`. Checkov check `CKV_AWS_44`.
13. **An RDS instance with `publicly_accessible = true`.** Prowler check `rds_instance_no_public_access`. Checkov check `CKV_AWS_17`.
14. **An RDS instance with no encryption at rest.** Prowler check `rds_instance_storage_encrypted`. Checkov check `CKV_AWS_16`.
15. **A KMS key without rotation enabled.** Prowler check `kms_cmk_rotation_enabled`. Checkov check `CKV_AWS_7`.

Fifteen findings, all detectable by all three scanners (with some variance in finding granularity), all remediable with a small Terraform diff per finding. The mini-project allocates ~6 hours to the work, expecting the student to produce a clean rescan and a per-finding remediation log.

---

## 6. The remediation workflow

The repeatable pattern for each finding:

1. **Read the finding's description and remediation note.** Trust the scanner here; it links to the canonical documentation. Do not improvise.
2. **Identify the smallest Terraform change.** For an unencrypted S3 bucket, the change is adding a `server_side_encryption_configuration` block — three lines. For a wide-open security group, the change is narrowing the `cidr_blocks` from `["0.0.0.0/0"]` to a specific allow-list — one line. For a public bucket ACL, the change is removing the `acl = "public-read"` line entirely.
3. **`terraform plan` and read the output.** The plan should show *only* the expected change. If the plan shows additional drift (because the previous `apply` left manual modifications in the account), reconcile the drift first.
4. **`terraform apply` in the test account.** Run the apply; verify the change took.
5. **Rescan with the relevant scanner.** Prowler for a live-account finding; Checkov for an IaC finding. Confirm the finding cleared.
6. **Commit.** Commit message format: `fix(<scope>): <one-line> [<finding-id>]`. Example: `fix(s3): enable default encryption on the reports bucket [CKV_AWS_19]`.
7. **Log it.** Append a row to the remediation log: finding ID, severity, file changed, commit SHA, date, scanner used to verify.

By the time fifteen findings are cleared, the student has fifteen commits, fifteen log entries, a clean Prowler / Checkov / ScoutSuite rescan, and a design document that explains the resulting architecture.

---

## 7. What this lecture does not cover

Three things are out of scope for Week 11 but worth knowing exist:

- **AWS Security Hub** is AWS's hosted aggregation of findings from Prowler (via JSON-ASFF), GuardDuty, Inspector, Macie, and Config. Security Hub is *paid* per finding ingested, costs grow with the number of accounts, and produces a centralised dashboard. The free open-source workflow this week covers the same findings without the dashboard.

- **GuardDuty** is AWS's hosted threat-detection service. It detects *runtime* anomalies (a known-malicious IP making API calls, an EC2 instance contacting a Tor exit node, an IAM principal exhibiting credential-stuffing patterns). Not a misconfiguration scanner; complementary to one. Paid per GB of CloudTrail and DNS data analysed.

- **Continuous compliance dashboards.** Wiz, Orca, Lacework, Datadog Cloud Security, Palo Alto Prisma Cloud — the commercial successors to the open-source tooling. Aggregate findings across cloud providers and across the SDLC; pay per workload or per node or per scan. Out of scope for the curriculum.

The open-source path is sufficient for the mini-project and for most small-to-medium real cloud environments. The commercial path becomes attractive at scale and when the audit posture has to integrate with the rest of an enterprise security programme.

---

## 8. Where this leaves you

You now have a model of why misconfigurations are the dominant cloud-breach root cause, three free tools that find them, the remediation workflow that closes them, and the awareness of the broader tooling landscape that you do not need for this week. The mini-project is the assembly: a misconfigured stack you scan and remediate end-to-end, with the design document an auditor would accept.

The thread that connects all three lectures: cloud security is *policy work*. The kernel does not enforce your policy; the cloud control plane does. The policies are written in JSON. The JSON has known dangerous shapes. The shapes are detectable by free tools. The discipline is to scan continuously, remediate methodically, and document the result.

Next: the exercises. Start with `exercises/exercise-01-policy-anatomy.json` and the SOLUTIONS walk-through.
