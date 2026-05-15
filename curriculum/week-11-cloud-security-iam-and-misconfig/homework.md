# Week 11 — Homework

> Five graded exercises. Targeted at the daily 1-hour homework block in the weekly schedule. Each is independent; do them in any order.

---

## Authorized-use disclaimer

Every artefact in this homework is exercised against an AWS account you own, or against a notional account you describe in writing without touching real resources. Re-read the week README banner.

---

## H1 — Read three AWS-published policies and label every defect

Open the AWS-managed-policy catalogue at https://docs.aws.amazon.com/aws-managed-policy/latest/reference/about-managed-policy.html. Pick three policies from the list, biased toward older ones (the `arn:aws:iam::aws:policy/*` policies with the highest `CreateDate` are the most-frequent offenders): suggested candidates are `AmazonEC2FullAccess`, `IAMReadOnlyAccess`, and `AmazonS3FullAccess`.

For each:

1. Paste the policy JSON into your homework document.
2. Annotate every statement with one sentence describing what the statement permits.
3. Identify every wildcard in the policy (in `Action`, `Resource`, or `Condition`) and rate each wildcard on a three-point scale: *justified* (the wildcard cannot reasonably be narrower), *worth narrowing* (could be more specific but the breadth is not actively dangerous), *defect* (the wildcard introduces real risk).
4. Propose, in Terraform HCL, a *replacement* customer-managed policy that achieves the same business purpose with less blast radius. The replacement does not need to be a drop-in (it can require the calling code to be slightly more specific in its API calls) but it should be useful for the same role.

Deliverable: ~400 words per policy plus the Terraform HCL.

---

## H2 — Run Prowler against a test account and produce a baseline

Provision a small free-tier AWS account if you do not already have one. Configure the AWS CLI with the dedicated `c6-week11` profile (see the week prerequisites). Install Prowler via `pipx install prowler`.

1. Create a dedicated read-only role named `c6-week11-prowler-audit` using the Terraform pattern in Lecture 3. The role's trust policy permits assumption from your IAM user with MFA.
2. Assume the role with `aws sts assume-role`. Set the resulting credentials in environment variables.
3. Run `prowler aws --output-formats json-asff html csv`.
4. Open the HTML report. Identify the three highest-severity findings.
5. For each, write a one-paragraph remediation plan (do not actually remediate yet — that is the mini-project's job).
6. Commit the JSON-ASFF report to your homework branch as `homework/h2-prowler-baseline.asff.json`. Redact your account ID by replacing it with `redacted-XXXXXX`.

Deliverable: the redacted JSON file plus a ~500-word write-up.

---

## H3 — Author a break-glass identity design

The week introduces *break-glass identities* — the one human account in the organisation that is allowed to violate the SCPs. This homework asks you to design one for a notional small-org AWS Organization with three accounts (security, prod, sandbox).

The design must specify:

1. Where the break-glass identity lives (management account; nowhere else).
2. The credential format (IAM user with console password and a hardware MFA device; or IAM Identity Center permission-set with a hardware MFA enrollment; or — the canonical 2026 recommendation — an IAM Identity Center permission-set tied to an Entra ID account that is itself protected by a physical security key and is not used for any other purpose).
3. The storage protocol for the credentials. (Hardware MFA seed in a fire-resistant safe; password printed in a sealed envelope; recovery codes printed in a separate sealed envelope; the seal is signed by two officers; opening the seals triggers an alert.)
4. The procedure for invoking the break-glass identity. (Two-person authorisation; both officers physically present; CloudTrail alarms on every action.)
5. The procedure for *resealing* the break-glass identity after use. (Rotate the password; replace the printed credentials; recompose the seal; document the invocation in the security register.)
6. The CloudWatch / EventBridge alerting that fires when the break-glass identity authenticates. (Slack alert, page to the on-call security manager, email to the audit committee.)

Deliverable: ~1 000 words. The grader looks for completeness of the procedures and explicit naming of who is responsible for each step.

---

## H4 — Compare the three scanners on the same Terraform stack

Take the deliberate-misconfig starter stack from the mini-project (`mini-project/starter/main.tf`). Run all three scanners against it:

- **Checkov.** `checkov --directory mini-project/starter --output json --output-file-path ./homework/h4-checkov.json`. Static; no credentials needed.
- **Prowler.** First `terraform apply` the stack into a test account (with the billing alarm set; tear down immediately after the scan). `prowler aws --output-formats json-asff --output-directory ./homework`.
- **ScoutSuite.** `scout aws --profile c6-week11 --report-dir ./homework/scoutsuite-report`.

For each scanner, record:

1. The total number of findings.
2. The breakdown by severity.
3. The findings the scanner caught that the other two did not.
4. The findings the other two scanners caught that this one did not.

Then produce a one-page comparison table (markdown, side-by-side columns). The table is the deliverable; the per-scanner output files are committed alongside but are not separately graded.

Deliverable: the comparison table plus the three output directories (with account IDs redacted).

---

## H5 — Write a one-page architectural decision record (ADR)

The team is choosing between three patterns for cloud-account access for human engineers:

1. **Pattern A — IAM users with console passwords.** The traditional approach. Each engineer has an IAM user in each account they touch.
2. **Pattern B — IAM Identity Center (formerly AWS SSO) with per-account permission sets.** Engineers sign in via SSO; the SSO portal issues short-lived role-sessions in each account.
3. **Pattern C — External IdP (Okta, Entra ID, Google Workspace) federated to IAM Identity Center.** Engineers sign in via the corporate IdP, which federates into IAM Identity Center, which issues short-lived role-sessions in each account.

Write an Architectural Decision Record in the canonical Michael Nygard format (https://github.com/joelparkerhenderson/architecture-decision-record/blob/main/locales/en/templates/decision-record-template-by-michael-nygard/index.md):

- **Title.** "Cloud-account access for human engineers."
- **Status.** "Proposed."
- **Context.** ~300 words. What problem are we solving? What constraints apply? What is the cost of getting this wrong?
- **Decision.** ~300 words. Which pattern do we choose, and on what evidence?
- **Consequences.** ~300 words. What follows from this choice — the good, the bad, and the operational obligations the team incurs?

The grader is looking for a clear *choice* (a "we will not decide right now" ADR is a failure), a defensible *rationale* (the rationale must reference the threat model and the cost of the alternatives), and explicit *consequences* (the homework expects at least three obligations the team incurs by adopting the chosen pattern — e.g., "every engineer must complete an SSO enrolment", "the IdP becomes a single point of failure", "MFA enforcement now lives at the IdP layer").

Deliverable: the ADR.

---

## Grading

Each item is worth 20 points; the homework is graded out of 100. Partial credit is awarded for partial completion of an item but not for omitting an item entirely. Submit as one document under `homework/`, with each item in its own subsection.
