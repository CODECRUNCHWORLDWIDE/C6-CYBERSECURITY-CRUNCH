# IAM Design Document Template

Curriculum starter template for the Week 11 mini-project. Students copy this file to `design-doc.md` in their working directory and fill in each section. The completed document is two-to-four pages.

The audience is an auditor or a peer engineer who has never seen this account before. The document is good if that reader can reconstruct the account's IAM design from the document alone.

---

## 1. Account topology

Describe the (notional or real) account structure. Even for a single-account lab, articulate the structure as if it were one piece of a multi-account organisation. The grader looks for:

- Whether the account is part of an AWS Organization, and if so, the OU it sits in.
- The role of the management account, and the standing recommendation that the management account host no workloads.
- The relationship between this account and any sibling accounts (security, prod, sandbox, log-archive, etc.).

Suggested length: half a page.

---

## 2. Identities

Inventory every identity in the account. Distinguish:

- **Humans.** Via SSO permission-set assignments (the modern recommendation) or via IAM users (the legacy pattern, with a deprecation timeline).
- **Services.** AWS service-linked roles, plus any custom roles assumed by AWS services (Lambda, ECS, EC2, etc.).
- **Automation.** OIDC-federated roles assumed by CI runners (GitHub Actions, GitLab CI, CircleCI, etc.); IAM Roles Anywhere for on-prem runners; cross-account roles assumed by tooling in adjacent accounts.

For each identity, record: name, type, purpose, and the principal that can authenticate as it.

Suggested length: half a page (longer if the inventory is large).

---

## 3. Permission matrix

A table whose rows are role names and whose columns are service classes. Each cell describes the action scope: read / read-write / admin / none.

| Role                              | S3    | EC2   | RDS   | IAM   | CloudTrail | KMS         |
|-----------------------------------|-------|-------|-------|-------|------------|-------------|
| `c6-week11-prowler-audit`         | read  | read  | read  | read  | read       | read        |
| `c6-week11-worker`                | none  | none  | none  | none  | none       | decrypt-one |
| `c6-week11-deployer`              | r/w-scoped | r/w-scoped | none | pass-role-scoped | none | decrypt-one |
| (etc.)                            |       |       |       |       |            |             |

A real permission matrix has 10-30 rows for a small account. For the mini-project, the matrix has at least the four roles the remediated stack produces.

The matrix is graded on *concreteness*. "Engineers can read everything" is not concrete; "Engineers can read S3 objects in buckets tagged `Team=Apollo`" is concrete. Where the access is scoped (by ABAC, by resource prefix, by condition), the cell says so.

Suggested length: half a page (the table plus a paragraph of explanation).

---

## 4. SCP inventory

List the Service Control Policies that apply to this account (or that would apply if the account were part of an Organization). For each SCP, state:

- The SCP's name.
- The OU level at which it is attached.
- Its purpose in one sentence.
- The full JSON, either inline or linked to its location in the repository.

The Week 11 starter SCPs from Exercise 4 (region lockdown, CloudTrail protection, public-S3 prevention plus IAM-user denial) are reasonable starting points. The grader expects at least three SCPs in the inventory.

For accounts that are not part of an Organization, articulate what the SCPs *would* deny and frame the deliverable as "this is the policy we would deploy when we adopt Organizations".

Suggested length: half a page.

---

## 5. Exception log

Every deviation from least privilege. If none, say so explicitly. If any, list each with:

- The exception (what permission is broader than least privilege would prescribe).
- The justification (why the broader permission is necessary).
- The owner (the named person responsible for re-evaluating).
- The expiry (the date by which the exception is re-reviewed).

An exception log with no exceptions is acceptable for a small lab account. An exception log that exists but is empty for a real account is suspicious; either the auditor missed something, or the exceptions are undocumented.

Suggested length: a paragraph if no exceptions; longer if any.

---

## 6. Scanner baseline

State the final scanner counts after remediation:

| Scanner    | Baseline failing | Final failing | Delta (resolved) |
|------------|-----------------:|--------------:|------------------:|
| Prowler    |                  |               |                   |
| Checkov    |                  |               |                   |
| ScoutSuite |                  |               |                   |

Reference the location of the final scanner output files in the repository.

For any HIGH or CRITICAL finding that remains after remediation, justify the residual finding in the exception log (Section 5).

Suggested length: a paragraph plus the table.

---

## 7. Change log

A condensed view of the remediation commits. The remediation log (`remediation.md`) already has the full table; the design doc's change log summarises by theme rather than by individual commit.

| Theme                         | Commits | Notes                                            |
|-------------------------------|--------:|--------------------------------------------------|
| S3 hardening (encryption, versioning, BlockPublicAccess) | 4      | Public ACL removed; defaults aligned with CIS 2.1.x. |
| IAM hardening (trust scope, policy narrowing, user removal) | 3 | Open-trust role scoped; admin-equivalent policy replaced; legacy CI user retired in favour of SSO. |
| Network hardening (SG narrowing, default SG)               | 3      | SSH ingress narrowed; RDP removed; default SG empty. |
| Audit and detection                                        | 1      | Multi-region CloudTrail added.                  |
| Data hardening (RDS, EBS, KMS)                             | 4      | RDS made private and encrypted; EBS encrypted; KMS key rotation enabled. |

Suggested length: a half page.

---

## 8. References

Cite, with URL or document name:

- The AWS IAM User Guide.
- The CIS AWS Foundations Benchmark version and the specific control numbers your remediations align to.
- NIST SP 800-207 for the architectural framing.
- Prowler / Checkov / ScoutSuite documentation for any tool-specific behaviour referenced.

Suggested length: half a page.

---

## Submission

The completed design document is committed alongside the remediated `main.tf`, the scan log, and the remediation log. The pull request description links to all four.

The grader reads the document end-to-end. The grading test is the "auditor reconstruction" test: does the document let an outside reader rebuild this account from scratch? A document that scores well on the scanner-count metric but fails the reconstruction test does not pass.
