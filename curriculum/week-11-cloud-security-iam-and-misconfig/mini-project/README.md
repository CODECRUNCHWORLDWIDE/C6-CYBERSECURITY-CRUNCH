# Week 11 — Mini-Project: Scan, Triage, Remediate

> *Take a deliberately-misconfigured Terraform stack. Scan it with three free open-source tools. Triage the findings. Remediate each finding in code. Document the result so an auditor would accept it.*

---

## Authorized-use disclaimer

The Terraform stack in `starter/` provisions real AWS resources when applied with valid credentials. Apply only into an AWS account you personally own. The stack is sized for the AWS free tier; nevertheless, set a billing alarm at $5 before doing anything. Tear down with `terraform destroy` immediately after the rescan confirms remediation.

The stack is intentionally insecure. Do not deploy it into any account that hosts real workloads, contains real customer data, or shares a VPC with any production resources.

---

## The deliverable

By the end of the mini-project, the student produces:

1. **A clean baseline scan.** Three scanner outputs (Prowler, Checkov, ScoutSuite) against the starter stack as it ships, with all findings documented in the findings log.
2. **A remediated Terraform stack.** The same stack, but with each finding fixed in code. The fixes are small (one to ten lines per finding) and committed individually with the finding ID in the commit message.
3. **A clean rescan.** Three scanner outputs against the remediated stack, demonstrating that every HIGH-and-CRITICAL finding from the baseline is resolved.
4. **A per-finding remediation log.** One markdown table row per finding: finding ID, severity, scanner that detected it, file changed, commit SHA, date, one-sentence justification.
5. **An IAM design document.** Two-to-four pages describing the design choices: which accounts exist, which roles exist, which managed policies are attached where, which SCPs apply, where ABAC is used and why, and how the design satisfies least privilege.

All five deliverables live in the student's submission branch under `mini-project/<your-handle>/`.

---

## The starter stack

The Terraform stack in `starter/` contains the fifteen deliberate misconfigurations enumerated in Lecture 3 section 5. The stack is parameterised to stay in the AWS free tier when applied: one `t3.micro` EC2 (if applied — most exercises do not require an actual `apply`), a small S3 footprint, one CloudTrail in the home region only, no RDS unless the student opts in.

The relevant files:

- `main.tf` — the Terraform stack itself.
- `variables.tf` — inputs, all with safe default values.
- `outputs.tf` — outputs, intentionally verbose for diagnostic purposes.
- `findings-template.md` — empty findings log; the student copies and fills it.
- `remediation-template.md` — empty remediation log; the student copies and fills it.
- `design-doc-template.md` — empty design doc; the student copies and fills it.

---

## The workflow

### Day 1 (Friday afternoon) — set up and baseline scan

1. Copy `starter/` to your working directory.
2. `terraform init && terraform validate`. The stack should validate clean.
3. Run Checkov against the stack:
   ```bash
   checkov --directory ./starter --output json --output-file-path ./baseline-checkov
   ```
   Open the report. You should see at least fifteen failed checks across the categories enumerated in Lecture 3.
4. (Optional, costs money) `terraform apply`. If you apply, set a budget alarm first. The apply provisions the resources; the subsequent Prowler scan reads them.
5. Run Prowler against the live account (only if you applied):
   ```bash
   aws sts assume-role --role-arn <your-prowler-role-arn> --role-session-name baseline
   # set the resulting credentials in env vars
   prowler aws --output-formats json-asff html --output-directory ./baseline-prowler
   ```
6. Run ScoutSuite (only if you applied):
   ```bash
   scout aws --profile c6-week11 --report-dir ./baseline-scoutsuite
   ```
7. Open all three reports. Cross-reference. Note that:
   - Some findings appear in all three scanners.
   - Some findings appear only in Checkov (static-only checks like "missing `lifecycle.prevent_destroy`").
   - Some findings appear only in Prowler (live-state checks like "the bucket has been accessed publicly in the last 30 days").
   - Some findings appear only in ScoutSuite (the report's organisation-by-service surfaces things the flat lists do not).
8. Fill in `findings-template.md`. One row per finding. Sort by severity descending.

### Day 1 (Friday evening) — triage

1. Read the findings log. Number the findings 1-N.
2. For each, write the proposed remediation in one sentence: which file changes, what the change is, why the change fixes the finding.
3. Order the findings by remediation effort (small fixes first; complex fixes last). Within the same effort tier, order by severity.
4. Commit the findings log: `git add findings.md && git commit -m "baseline: log 15 starter-stack findings"`.

### Day 2 (Saturday morning) — remediate

For each finding, in the order from the triage:

1. Open the Terraform file. Make the change.
2. `terraform validate` — confirm the file still parses.
3. `terraform plan` — confirm the plan shows only the expected change. If extra drift appears (because the previous `apply` left manual modifications in place), reconcile the drift before continuing.
4. Run Checkov scoped to the changed file: `checkov --file ./starter/main.tf`. The previously-failing check should now pass.
5. (If you applied) `terraform apply`. Then rescan with Prowler scoped to the relevant check: `prowler aws --check <check-id>`. The previously-failing check should now pass.
6. Append a row to the remediation log: finding ID, severity, file changed, commit SHA (you have not committed yet — you will fill this in after the commit), date, justification.
7. Commit: `git add <files> && git commit -m "fix(<scope>): <one-liner> [<finding-id>]"`. The commit message format matters; the grader greps for the finding ID.
8. Repeat for the next finding.

By the end of Saturday morning, fifteen commits have landed and fifteen findings are resolved.

### Day 2 (Saturday afternoon) — rescan and document

1. Run all three scanners against the remediated stack. Save the output to `final-checkov/`, `final-prowler/`, `final-scoutsuite/`.
2. Confirm that no HIGH or CRITICAL findings remain. If any remain, return to the remediation step.
3. Open the design-doc template. Fill it in:
   - **Section 1 — Account topology.** Describe the (notional or real) account structure. Even for a single-account lab, articulate the structure as if it were the security account of a three-account organisation; the design discipline is the same.
   - **Section 2 — Identities.** Inventory: humans (via SSO permission sets), services (via IAM roles), automation (via OIDC-federated roles). Name each.
   - **Section 3 — Permission matrix.** A table: rows are role names, columns are service classes (S3, EC2, RDS, IAM, CloudTrail, KMS), cells are the action scope (read / read-write / admin / none). One row per role.
   - **Section 4 — SCP inventory.** List the SCPs from Exercise 4 that you would deploy and to which OUs. Or, if your account is not part of an Organization, articulate the SCPs you *would* deploy if it were.
   - **Section 5 — Exception log.** Any deviations from least privilege. If none, say so explicitly. If any, list each with a justification and an expiry date.
   - **Section 6 — Scanner baseline.** Reference the final scanner outputs and state the finding counts.
   - **Section 7 — Change log.** A condensed view of the fifteen remediation commits.
4. Commit: `git add design-doc.md && git commit -m "docs: IAM design doc"`.

### Day 3 (Sunday morning) — review and submit

1. `terraform destroy` if you applied. Confirm the account is empty.
2. Push the branch. Open the pull request.
3. The PR description: a one-line summary, links to each deliverable, the before-and-after scanner counts.

---

## Grading rubric

- **Findings log completeness (20 points).** Every finding from the baseline scanner output is in the log with the correct ID, severity, and scanner source.
- **Remediation correctness (30 points).** Every finding's fix is in a separate commit with the finding ID in the message. The remediations are minimal (no gratuitous re-architecture).
- **Final scanner cleanliness (20 points).** No HIGH or CRITICAL findings remain. LOW and INFORMATIONAL findings are acceptable if documented in the exception log.
- **Design doc quality (20 points).** All seven sections are filled. The permission matrix is concrete (not "engineers can read everything"). The SCP inventory references specific actions, not vague intentions.
- **Submission hygiene (10 points).** Clean commit history. No private keys or account IDs in the diff. PR description complete.

Total: 100 points. A passing submission is 75 or above.

---

## Honesty about scope

This mini-project is a single small AWS account, fifteen specific misconfigurations, a weekend of work. Real cloud-security programmes scan dozens of accounts continuously, integrate with SIEM, automate remediation through service-control-policy-managed Lambda, and negotiate exception requests with auditors who have read every CIS Benchmark cover-to-cover. The skills are the same; the operational tooling is heavier; the deadlines are tighter.

The honest articulation in the design doc is the point: the auditor reading your final document should be able to say "I would accept this design for a small AWS account today" or "I would accept this design with the following two follow-ups". A design doc that leaves the auditor needing to ask basic questions has not done its job.

---

## Pointers

- Cite the AWS IAM User Guide and the CIS AWS Foundations Benchmark when justifying remediations.
- Cite Prowler / Checkov / ScoutSuite documentation when citing tool behaviour.
- Cite NIST SP 800-207 when articulating the architectural posture.
- The mini-project is *not* about reaching zero findings on every scanner; some findings are legitimately suppressed for the codebase. The mini-project *is* about being explicit about every finding — fixed, suppressed, or accepted — and being able to defend each decision.
