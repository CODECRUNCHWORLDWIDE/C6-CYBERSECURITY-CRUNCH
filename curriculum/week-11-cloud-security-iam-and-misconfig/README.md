# Week 11 — Cloud Security: IAM and Misconfiguration

> *Week 10 put a stateful firewall and an IDS sensor on a network the student owns. Week 11 walks across the wire into a shared-tenancy public cloud, where the perimeter is not a chain in the kernel but a JSON policy in a control-plane API. The deliverable this week is a defensible IAM design for a small AWS account plus a misconfiguration-scanning workflow that catches the most common shapes of cloud-security failure before they reach production. The mini-project is a deliberately misconfigured Terraform stack the student inherits, scans with three free tools — **Prowler**, **Checkov**, **ScoutSuite** — and remediates finding-by-finding into an audit-ready state.*

Welcome to Week 11 of **C6 · Cybersecurity Crunch**. The first ten weeks built defences for environments where the student writes the kernel rules. Week 11 is the first week in which the student does *not* write the kernel rules — Amazon, Google, and Microsoft do, and the student writes JSON that asks them politely to enforce a policy. The mental shift is real. A firewall rule that fires denies a packet; an IAM policy that fires denies an *API call*. The unit of access is no longer a TCP flow but a `(principal, action, resource, condition)` tuple. This week is about taking that shift seriously, learning the policy language that expresses it, and adopting the free open-source tooling that finds the gaps left behind by every cloud account that grew faster than its governance.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  Every command, Terraform plan, Prowler / Checkov / ScoutSuite run, |
|  IAM policy, and cloud-API call in this module is run against:      |
|                                                                     |
|  - a cloud account you personally own and pay for (your own AWS,    |
|    GCP, or Azure free-tier account), OR                             |
|  - a cloud account on which you hold a current, written, signed     |
|    authorisation from the account owner (your employer's cloud      |
|    governance team's standing engagement letter, a customer's       |
|    signed scope-of-work, a school IT department's signed            |
|    authorisation, or equivalent).                                   |
|                                                                     |
|  Running a misconfiguration scanner against a cloud account you do  |
|  not own is, in the United States, a violation of the Computer      |
|  Fraud and Abuse Act (18 U.S.C. § 1030) regardless of the           |
|  scanner's intent — the CFAA criminalises unauthorised access,      |
|  not malicious access. Prowler, Checkov, and ScoutSuite all use     |
|  read-only cloud-API calls; "read-only" still means "calls" and     |
|  every API call is logged. In the European Union the NIS2           |
|  directive treats unauthorised access to information systems as a   |
|  criminal offence; in the United Kingdom the Computer Misuse Act    |
|  1990 governs; Florida residents are additionally subject to        |
|  Fla. Stat. § 815.06.                                               |
|                                                                     |
|  IAM policy changes are explosive. A wildcard in the wrong place    |
|  can grant `s3:DeleteBucket` on every bucket in the account, or     |
|  `iam:*` to every principal in the directory. Every policy in this  |
|  week's exercises is written against a *test* account whose only    |
|  contents are the resources you provisioned for the exercise. Do    |
|  not paste these policies into a production account "to see what    |
|  happens". The blast radius of a single misplaced `Resource: "*"`   |
|  in an admin-adjacent policy is the entire account.                 |
|                                                                     |
|  Terraform `apply` against a real cloud account creates real        |
|  resources that cost real money. The deliberate-misconfig stack     |
|  in the mini-project is parameterised to stay within the AWS free   |
|  tier and to tear down cleanly with `terraform destroy`. Set a      |
|  billing alert before you run it. The grader has no obligation to   |
|  reimburse anyone who forgot.                                       |
|                                                                     |
|  If you cannot point at a document or an ownership claim that       |
|  authorises the work, you do not run the work. The same rule that   |
|  governed every previous week of C6 governs this one.               |
+---------------------------------------------------------------------+
```

Read the banner once carefully now; thereafter treat it as a contract. The mini-project explicitly scopes a *test AWS account you own*. If the only access the student has is to an employer's account, the deliverable is still valid — but the implementation portion stays in `terraform plan` and the scanner reports are generated against a local mocked state, not a real account. The grade is on the design and the remediation, not on whether bits ever touched real AWS resources.

---

## Learning objectives

By the end of this week, you will be able to:

- **Explain** the four conceptual ingredients of every IAM policy decision — **subject** (the principal making the request), **resource** (the thing being acted on), **action** (the API the principal is calling), and **condition** (the context in which the call is made) — and walk through how a cloud control plane evaluates a request against the set of policies attached to each. Use AWS terminology as the worked example because AWS's policy language is the most concrete and the most documented; treat GCP and Azure as variations on the same theme.
- **Articulate** the **principle of least privilege** as it applies to cloud IAM: every principal receives the *minimum* permissions needed to perform its job, scoped to the *minimum* set of resources, gated by the *minimum* set of conditions. Distinguish least privilege from "deny by default" (a policy mechanic) and from "zero trust" (an architectural posture). Cite NIST SP 800-207 for the architectural framing and the AWS IAM User Guide for the policy-evaluation logic.
- **Distinguish** **identity-based policies** (attached to a user, group, or role; "what can this principal do?"), **resource-based policies** (attached to a resource; "who can do what on this thing?"), and **attribute-based access control / ABAC** (decisions made on tags or attributes at request time, rather than fixed identity bindings) — and write at least one of each in the AWS policy language. Articulate when each is the right tool.
- **Read** an AWS IAM policy document and trace, line by line, what it permits and denies. Identify the four required JSON keys (`Version`, `Statement`, `Effect`, `Action`) and the optional keys (`Principal`, `Resource`, `Condition`, `Sid`, `NotAction`, `NotResource`). Understand the resolution order: explicit deny wins; then permission boundaries; then session policies; then identity- or resource-based allows. Cite the AWS policy-evaluation-logic page.
- **Write** **Service Control Policies (SCPs)** that act as organisation-wide guardrails: the maximum permissions a member account *can* have, regardless of what its own IAM policies say. Understand that SCPs do not *grant* permissions — they *limit* them. Apply SCPs to enforce non-negotiable invariants (no public S3 buckets, no IAM users outside a designated OU, no provisioning in unapproved regions). Cite the AWS Organisations user guide.
- **Translate** an AWS IAM pattern into its GCP and Azure equivalents. GCP IAM uses **roles** (collections of permissions) bound to **principals** (Google accounts, service accounts, Workspace groups) on **resources** organised in a hierarchy (Organisation > Folder > Project > Resource). Azure RBAC uses **role assignments** (a role definition + a security principal + a scope) and adds **Azure Policy** for guardrails. Articulate the structural similarities and the meaningful differences.
- **Identify** the canonical cloud misconfigurations that scanners flag: public S3 buckets, IAM users with console passwords but no MFA, IAM roles trusted by every principal in the account, unencrypted EBS volumes, security groups open to `0.0.0.0/0` on administrative ports, CloudTrail disabled or scoped to one region, root-account access keys, default VPC use for production workloads. Map each to the AWS Foundations CIS Benchmark control that flags it.
- **Run** **Prowler** against an AWS account, read its CSV / JSON / HTML reports, and triage the findings by severity. Understand that Prowler executes a long list of `Get`/`List`/`Describe` API calls; that its only credentials are the credentials you give it; and that the read-only role pattern (an IAM role with `SecurityAudit` plus `ViewOnlyAccess` plus a small set of explicit extras) is the recommended deployment model.
- **Run** **Checkov** against Terraform, CloudFormation, and Kubernetes manifests, *before* the resources are ever provisioned. Understand that Checkov operates on static text and therefore catches misconfigurations earlier and cheaper than any runtime scanner. Configure Checkov in a CI workflow that fails the build on HIGH-severity findings.
- **Run** **ScoutSuite** against AWS, GCP, and Azure. Read its HTML report and understand the rule-pack model (`providers/aws/rules/findings/`, etc.) that makes ScoutSuite extensible. Compare ScoutSuite's coverage to Prowler's for AWS; understand why operators run both.
- **Remediate** scanner findings methodically. The remediation workflow: triage by severity and exploitability, identify the smallest change that fixes the finding without breaking unrelated workloads, write the fix as code (Terraform diff or CloudFormation diff, never click-ops), rescan to confirm the finding is gone, document the change with a finding ID and the commit SHA.
- **Document** the IAM design for a small account such that an auditor can follow it: an account topology (root, member accounts, OUs if applicable), an identity inventory (humans, services, automation), a permissions matrix (which role can do what to which resource class), an SCP inventory, an exception log (every deviation from least privilege with a justification and an expiry), and a change log.

---

## Prerequisites

- **Weeks 1 through 10 completed.** Week 10 introduced the discipline of writing rule files as code under version control; the same discipline applies to IAM policies. Week 4 (threat modelling) and Week 9 (forensics) inform how the student thinks about which controls matter most.
- **An AWS account you own, ideally one provisioned with the AWS free tier.** The mini-project's Terraform stack is sized to stay within free-tier limits (`t3.micro` for any EC2, a single S3 bucket below 5 GB, a single CloudTrail trail in the home region). Sign up at https://aws.amazon.com/free/ if you do not already have one. Set a budget alarm at $5 before doing anything in this week. AWS retains the right to charge for resources outside the free tier; the grader does not.
- **A GCP account, even at the always-free tier, is helpful but not required.** The GCP IAM sidebar in Lecture 1 can be read without ever opening the Cloud Console; the ScoutSuite GCP run in Exercise 6 is optional. Sign up at https://cloud.google.com/free/ if you want to follow the optional steps.
- **An Azure account is optional in the same sense.** Sign up at https://azure.microsoft.com/free/ if you want to compare the three providers' RBAC models hands-on.
- **Python 3.11 or later.** Verify with `python3 --version`. Prowler is a Python tool; Checkov is a Python tool; ScoutSuite is a Python tool. Every `.py` exercise is type-hinted.
- **Terraform 1.6 or later.** Install from https://developer.hashicorp.com/terraform/install. Terraform is BSL-licensed since August 2023; the OpenTofu fork (https://opentofu.org) is a drop-in compatible alternative and is permitted as a substitute throughout the week. The starter Terraform stack works with either.
- **The AWS CLI v2 on the path.** Verify with `aws --version`. Configure with `aws configure --profile c6-week11` and a dedicated IAM user (or an SSO short-lived credential) that has the `SecurityAudit` and `ReadOnlyAccess` managed policies plus a small `Allow ec2:Describe*` extra. The exercises explicitly walk through this least-privileged setup.
- **`prowler`, `checkov`, `scoutsuite` installed via `pipx` or a virtual environment.** The exercises pin versions. Prowler 5.x, Checkov 3.x, ScoutSuite 5.x are the assumed lines as of May 2026.
- **Comfort with the assumption that the first IAM policy you write will be wrong.** Every cloud engineer's first hand-written policy has a typo, a missing comma, or a wildcard in the wrong place. The exercises walk through the canonical recovery pattern: every policy change goes through a `terraform plan` (or its equivalent) review before `apply`; every policy attaches in a *dry-run* mode (`PermissionsBoundary` only, no live attachment) for the first iteration; every account has a *break-glass* identity that can recover from a lockout.
- **A cloud account you own, or a willingness to confine the lab to plan-only and mocked state.** Re-read the banner.

---

## Topics covered

- **The four conceptual ingredients of an IAM decision.** Subject (the principal asking — a human user, a service account, a role-session, an automated agent). Resource (the thing being acted on — an S3 bucket, a Pub/Sub topic, a Key Vault secret). Action (the API call — `s3:GetObject`, `compute.instances.delete`, `Microsoft.Storage/storageAccounts/read`). Condition (the context — source IP, time of day, the requesting principal's tag set, whether MFA was used).
- **AWS IAM policy structure.** The `Version` field (always `"2012-10-17"` for new policies). The `Statement` array (each element is a permission rule). The `Effect` (`Allow` or `Deny`). The `Action` (a string or array; supports wildcards). The `Resource` (an ARN or array; supports wildcards). The `Condition` block (zero or more condition operators applied to request context keys). The `Principal` field on resource-based policies. The `NotAction` / `NotResource` keys and why they are footguns.
- **Policy evaluation logic.** AWS's evaluation order: an explicit `Deny` anywhere in the request's applicable policies wins. Otherwise, permission boundaries set the ceiling. Otherwise, session policies set a further ceiling. Otherwise, an identity-based or resource-based `Allow` permits the action. Otherwise (no applicable allow), the action is denied. Cite https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html.
- **Identity-based policies.** Attached to an IAM user, an IAM group, or an IAM role. Answer the question "what can *this principal* do?" The single most-attached managed policy in the AWS catalogue is `AdministratorAccess` (`{Effect: Allow, Action: "*", Resource: "*"}`) — the policy this week is explicitly designed to replace in any account that still uses it casually.
- **Resource-based policies.** Attached to a resource (an S3 bucket policy, a KMS key policy, an SQS queue policy, a Lambda function policy, a Secrets Manager secret policy). Answer the question "who can do what on *this thing*?" Includes a `Principal` field that identity-based policies do not have. The S3 bucket policy is the most-misconfigured resource-based policy in the cloud, by a wide margin.
- **Attribute-based access control (ABAC).** Decisions made on request-context attributes (typically resource tags or principal tags) rather than fixed identity bindings. The canonical AWS ABAC pattern: a single role per environment (`dev`, `staging`, `prod`), each with a policy that grants access only when the principal's `aws:PrincipalTag/Project` equals the resource's `aws:ResourceTag/Project`. Scales to thousands of resources without N-by-M policy growth. Cite the AWS ABAC tutorial.
- **Service Control Policies (SCPs).** Apply to an AWS account or an Organisational Unit (OU) inside AWS Organisations. Define the *maximum* permissions any principal in the targeted accounts can have. Never grant permissions; only constrain them. Canonical SCP patterns: deny all actions outside a list of approved regions; deny the creation of public S3 buckets; deny disabling CloudTrail; deny IAM user creation in accounts that use SSO.
- **The IAM trust policy.** A subset of the resource-based policy mechanism specific to IAM roles. The trust policy says "who is allowed to assume this role". The single most-misconfigured trust policy in the cloud: `{Principal: {AWS: "*"}}` on a role with administrative permissions, which means *any AWS account in the world* can assume the role. Always scope `Principal` to a specific account, OU, or service.
- **GCP IAM sidebar.** Resource hierarchy: Organisation > Folder > Project > Resource. Roles: predefined (`roles/storage.objectViewer`) or custom. Principals: Google accounts, Workspace groups, service accounts, Google groups, allUsers, allAuthenticatedUsers. Bindings: a role plus a principal applied at a hierarchy node. Inheritance: child resources inherit bindings from parents (additive). Conditions: similar role-binding-with-condition mechanism as AWS conditions. Organisation Policies: the GCP equivalent of SCPs (constraint-based: `iam.disableServiceAccountKeyCreation`, `compute.requireOsLogin`, `storage.uniformBucketLevelAccess`). Cite https://cloud.google.com/iam/docs.
- **Azure RBAC sidebar.** Role assignments = role definition + principal + scope. Scope is a resource ID prefix (subscription > resource group > resource). Built-in roles: `Reader`, `Contributor`, `Owner`, `User Access Administrator`, and hundreds of service-specific roles. Custom role definitions: JSON document with `actions`, `notActions`, `dataActions`, `notDataActions`, `assignableScopes`. Azure Policy (separate from RBAC): the guardrail mechanism. Management Groups: the organisational hierarchy that scopes policies above the subscription level. Cite https://learn.microsoft.com/en-us/azure/role-based-access-control/.
- **Misconfiguration as the dominant cloud-security failure mode.** Verizon's annual DBIR has, every year since 2019, identified misconfiguration as the single largest category of root cause for cloud-related breaches. The Capital One breach (2019), the Twitch source-code leak (2021), and the Pegasus Airlines passenger-data exposure (2022) were all S3 misconfigurations. The pattern is repetitive: a bucket with a permissive resource policy or a `BlockPublicAccess` setting flipped off.
- **Prowler.** Free, open-source AWS security-best-practice assessment tool. Originally a single Bash script by Toni de la Fuente; Python-based since v3; covers AWS, Azure, and GCP since v4 (with AWS still the deepest coverage). Hundreds of checks across the CIS AWS Foundations Benchmark, GDPR, HIPAA, PCI-DSS, ISO 27001, the AWS Well-Architected Framework's Security Pillar, and the AWS Foundational Security Best Practices. Output formats: stdout, CSV, JSON, JSON-ASFF (compatible with AWS Security Hub), HTML. https://github.com/prowler-cloud/prowler.
- **Checkov.** Free, open-source static-analysis scanner from Bridgecrew (acquired by Palo Alto Networks in 2021, kept open-source). Scans Terraform, CloudFormation, Kubernetes manifests, Helm charts, Dockerfiles, ARM templates, Serverless Framework, OpenAPI specs, GitHub Actions workflows. Operates on the text — no cloud credentials required. Catches misconfigurations before provisioning. Configurable through `.checkov.yaml`, `--skip-check`, `--check`. https://github.com/bridgecrewio/checkov.
- **ScoutSuite.** Free, open-source multi-cloud security-auditing tool from NCC Group. Supports AWS, Azure, GCP, OCI, Aliyun. Reads cloud account configuration through the provider SDK (read-only) and produces an interactive HTML report keyed by service. Rule packs are JSON; extending ScoutSuite means writing a JSON finding definition plus the Python dotted-key it inspects. https://github.com/nccgroup/ScoutSuite.
- **The CIS Benchmarks.** The Center for Internet Security publishes free PDF benchmarks for AWS, Azure, GCP, OCI, Kubernetes, Docker, every major Linux distribution, Windows, and dozens of application stacks. Each control is numbered (e.g., "1.4 — Ensure no root user account access key exists") and includes a description, rationale, audit procedure, and remediation. https://www.cisecurity.org/cis-benchmarks/. The AWS Foundations Benchmark is the single most-cited cloud-security reference; Prowler's default CIS profile maps directly to it.
- **NIST SP 800-207, Zero Trust Architecture.** The framing this week leans on. ZTA's seven tenets translate, in the cloud, to: identity-aware access control on every API call, continuous evaluation of policy at request time, conditions on environment context (network, device posture, MFA status, time of day), centralised logging of every authentication and authorisation decision (CloudTrail, GCP Cloud Audit Logs, Azure Activity Log). https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf.
- **Terraform as the policy-change vehicle.** Every IAM change in a serious cloud account flows through Terraform (or CloudFormation, or Pulumi, or the Cloud Deployment Manager). The audit trail is the git history. The review gate is the pull request. The dry-run is `terraform plan`. The mini-project's "fix the misconfigurations" deliverable is a series of small commits, each with a finding ID in the commit message.
- **Break-glass identities.** The one human account in the cloud organisation that is allowed to violate the SCPs. Stored offline (Yubikey + recovery codes + printout in a fire-resistant safe). Never used in normal operations; only invoked when the regular access path is broken. Audit log alerts on every break-glass login. The week does not require provisioning a break-glass account but explains the pattern; the homework prompts a written design.
- **Documentation discipline.** The auditor test, applied to IAM: if a colleague who has never seen this AWS account reads the documents in your repository, can they reconstruct the IAM design from scratch? The artefacts: account topology, identity inventory, permission matrix, SCP inventory, exception log, change log, scanner-baseline reports.

---

## Weekly schedule

The schedule below adds up to approximately **35 hours**. Treat it as a target.

| Day       | Focus                                                                | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|----------------------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | L1 — IAM fundamentals and AWS policy language                        |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Tuesday   | L2 — Identity-, resource-, attribute-based policies and SCPs         |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Wednesday | L3 — Misconfiguration scanning with Prowler, Checkov, ScoutSuite     |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0.5h     |    0.5h    |    6h       |
| Thursday  | Exercises polished; challenge launch                                 |    0h    |    2h     |     1.5h   |    0.5h   |   1h     |     1h       |    0.5h    |    6.5h     |
| Friday    | Mini-project: scan the deliberate-misconfig stack, triage findings   |    0h    |    1h     |     0.5h   |    0.5h   |   1h     |     2h       |    0.5h    |    5.5h     |
| Saturday  | Mini-project: write the remediations, rescan, write the design doc   |    0h    |    0h     |     0h     |    0h     |   1h     |     3h       |    0h      |    4h       |
| Sunday    | Quiz, review, polish, push                                           |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    1h      |    1.5h     |
| **Total** |                                                                      | **6h**   | **7.5h**  | **2h**     | **3h**    | **6h**   | **6.5h**     | **3.5h**   | **34.5h**   |

---

## File map

```
week-11-cloud-security-iam-and-misconfig/
├── README.md                              ← this file
├── resources.md                           ← annotated bibliography, every link free
├── quiz.md                                ← 25 short-answer questions
├── homework.md                            ← five graded exercises, deliverables defined
├── lecture-notes/
│   ├── 01-iam-fundamentals-and-aws-policy-language.md
│   ├── 02-identity-resource-abac-and-scps.md
│   └── 03-misconfig-scanning-prowler-checkov-scoutsuite.md
├── exercises/
│   ├── exercise-01-policy-anatomy.json            ← a policy to read, line by line
│   ├── exercise-02-least-priv-deployer.json       ← author a least-privilege policy
│   ├── exercise-03-abac-by-project-tag.tf         ← Terraform with ABAC pattern
│   ├── exercise-04-scp-guardrails.json            ← three SCPs for an OU
│   ├── exercise-05-prowler-triage.py              ← parse a Prowler JSON-ASFF report
│   ├── exercise-06-checkov-ci.py                  ← drive Checkov from CI, gate builds
│   └── SOLUTIONS.md                               ← walkthrough for all six
├── challenges/
│   ├── challenge-01-rotate-the-keys.md            ← scenario: an exposed access key
│   └── challenge-02-cross-account-role-trust.md   ← scenario: design cross-acct trust
└── mini-project/
    ├── README.md                                  ← the deliverable specification
    └── starter/
        ├── README.md                              ← inventory of starter files
        ├── main.tf                                ← deliberate-misconfig Terraform
        ├── variables.tf                           ← inputs, all default-safe values
        ├── outputs.tf                             ← outputs (intentionally noisy)
        ├── findings-template.md                   ← finding-tracking template
        ├── remediation-template.md                ← per-finding remediation template
        └── design-doc-template.md                 ← IAM design doc template
```

The starter directory ships a Terraform stack that *intentionally fails* every modern cloud-security best practice in a way the three scanners will catch. The student's job is to remediate each finding into a passing state.

---

## Submission

- A pull request against the `main` branch of your fork of this curriculum repository.
- Branch named `week-11-<your-handle>`.
- The PR description links to every deliverable inside the branch by relative path.
- The PR description includes the *before* and *after* Prowler / Checkov / ScoutSuite scan summaries (finding counts by severity), demonstrating that every HIGH and MEDIUM finding from the starter stack is resolved.
- **Do not commit AWS access keys, GCP service-account JSON files, Azure client secrets, Terraform `.tfstate` files, or scanner output files that contain account IDs.** The starter `.gitignore` excludes the obvious paths; the grader will fail any submission that contains a real AWS account number, an access-key ID, or a secret-key string anywhere in the diff. Use `redacted-XXXXXX` placeholders in documentation.

---

## Honesty about scope

This week designs IAM and runs misconfiguration scans for a single small AWS account with a worked Terraform mini-project. The same skills scale to enterprise environments with dozens of accounts and thousands of identities, but the operational concerns of an enterprise — multi-account governance with AWS Control Tower or Landing Zone, centralised identity providers via SCIM, continuous compliance dashboards in Security Hub or Wiz, the politics of negotiating exception requests with auditors — are owed to a later course. The lab is honest about what it is: one person, one account, one weekend. The plan you produce should be honest the same way.

---

## A note on naming

This week uses the names **AWS IAM**, **GCP IAM**, **Azure RBAC**, **Service Control Policies**, **Prowler**, **Checkov**, **ScoutSuite**, **Terraform**, and **CIS Benchmarks** to refer to the projects (capitalisations as the projects themselves use them on their landing pages). The acronym **IAM** is preferred over "identity and access management" in body text; the canonical expansion appears once in Lecture 1. The acronym **ABAC** is preferred over "attribute-based access control" after first use. AWS-specific terms (`ARN`, `STS`, `SCP`, `OU`, `KMS`, `ASFF`) are introduced inline at first use.

Read `resources.md` next, then move to `lecture-notes/01-iam-fundamentals-and-aws-policy-language.md`.
