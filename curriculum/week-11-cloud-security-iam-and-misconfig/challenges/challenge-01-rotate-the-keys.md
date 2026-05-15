# Challenge 1 — Rotate the Keys

> Scenario design exercise. No code is required; the deliverable is a written plan plus a Terraform diff. Read the exercises before attempting the challenge.

---

## Authorized-use disclaimer

Every artefact in this challenge is exercised against an AWS account you own, or against a notional account you describe in writing without touching real resources. Do not exercise this scenario against an account whose ownership or written authorisation you cannot point to.

---

## The scenario

A developer on your team has, six hours ago, force-pushed a commit that included a live AWS access-key pair into a public GitHub repository. They noticed within five minutes; the repository is now private; the commit has been amended and force-pushed; the developer has changed their console password and is shaken. The access key was in their personal IAM-user profile, attached to a managed policy named `DeveloperFullAccess` that, on inspection, is a copy of `AdministratorAccess` with the suffix `WithBilling`. They are pretty sure GitHub did not mirror the push to any third-party search index, but they are not sure. They have not yet contacted the security team.

You are the security on-call.

The Slack message lands at 03:14 UTC on a Saturday. You open the laptop, get a coffee, and begin.

The clock matters. The longer the key is live, the larger the blast radius. AWS's documented response time for revoking a publicly-shared key when AWS itself discovers it (through its automated GitHub-scanning pipeline) is approximately three hours; in this scenario, the key has been live for six. You cannot assume AWS has already disabled the key, and you must not depend on AWS's automated response.

The account has 12 humans, ~40 IAM roles, 3 IAM users (including the developer's, plus two legacy CI users), one CloudTrail trail (organization-wide, multi-region), and CloudWatch alarms on a few high-value metrics. The organisation has a sandbox OU, a staging OU, a prod OU, and a security OU; the developer's user lives in the prod OU's master account. The break-glass identity is a separate IAM user (`break-glass-root`) with a Yubikey in a fire-resistant safe in the security director's office.

---

## What you produce

Three artefacts, all in writing, in the response document the challenge expects:

### Artefact 1 — The 60-minute response plan

A numbered list of actions, with timestamps, that you execute in the first 60 minutes. The list must include — explicitly, not implied:

- The first three CloudTrail queries you run to determine the blast radius of the key. Write the actual `aws logs filter-log-events` or Athena queries.
- The IAM action you take *before* you do anything else (do not reveal it here — the answer is in the SOLUTIONS hint at the end of this file).
- The communication you send and to whom (developer, manager, security team, other on-call).
- The decision-point at which you escalate to the break-glass identity, with the condition that triggers escalation.
- The decision-point at which you contact AWS Trust & Safety, with the condition that triggers contact (and the URL of the AWS support form you use).

The plan is graded on completeness, sequencing, and the explicit conditions on each branching action. A plan that says "contain the breach" without specifying *how* fails. A plan that names every action by AWS-API or AWS-CLI verb passes.

### Artefact 2 — The Terraform diff

The developer's `DeveloperFullAccess` managed policy is owned by Terraform. Your immediate remediation produces a Terraform diff that:

- Detaches the policy from the developer's IAM user.
- Replaces the developer's IAM user with an IAM Identity Center permission-set assignment (so they sign in via SSO instead of a long-lived user).
- Adds an SCP at the prod-OU level that denies `iam:CreateUser` and `iam:CreateAccessKey` so this class of mistake cannot recur.
- Removes the `DeveloperFullAccess` policy entirely from the account.
- Adds a `permissions boundary` to every role in the prod-OU master account that caps the role at `PowerUserAccess` minus IAM (so an escalation through a future compromise of a role cannot recreate the IAM user).

Write the diff as Terraform HCL, including the `resource` blocks for the SCP and the permissions boundary. Do not write the diff against a real account; write it as a notional change to a hypothetical Terraform repo.

### Artefact 3 — The post-incident write-up

A two-page (~1 500 word) post-incident write-up modelled on the format Week 9 introduced. Include:

- **Summary.** What happened, in three sentences.
- **Timeline.** UTC timestamps from 03:09 (when the developer force-pushed) through the resolution.
- **Root cause.** The mechanical root cause (the key was in the commit). The systemic root cause (the IAM user existed at all; the policy was `AdministratorAccess`-equivalent; pre-commit hooks did not catch the key; the secret-scanner alert path is broken in this org or did not fire fast enough). Be specific.
- **Blast radius.** From the CloudTrail queries in artefact 1, the list of API calls the key made during its live window. If the queries return no suspicious calls, state that explicitly with the supporting query result.
- **Remediation.** From artefact 2.
- **Lessons learned.** Three to five. At least one must reference a control already discussed in Weeks 1-10 (e.g., the secret-scanning hook from Week 5; the threat-model discipline from Week 4) that, if applied, would have prevented this incident.

---

## Constraints

- The developer is upset and embarrassed. Your communication tone matters. The Slack messages you draft in artefact 1 are graded on tone as well as content; a message that begins "you've made a serious mistake" is wrong both ethically and operationally (people who feel attacked retreat; people who feel supported help you respond).
- AWS Trust & Safety contact is real. The form is at https://aws.amazon.com/forms/aws-customer-incident-response. The contact path is genuine; do not invent fictional response phone numbers.
- CloudTrail's log delivery latency is up to 15 minutes. Your queries must account for the possibility that the very-latest API calls are not yet indexed. State this explicitly in the plan.

---

## What "good" looks like

A well-designed response identifies the three classes of action:

- **Contain** (the actions you take in the first 5 minutes to stop further damage).
- **Eradicate** (the actions you take in the first 60 minutes to remove the attacker's foothold, if any).
- **Recover** (the actions you take over the following days to restore normal operations).
- **Improve** (the actions you take over the following weeks to prevent recurrence).

A well-designed response prioritises *containment* over *investigation*. Investigation is important and is the bulk of the work, but it happens after the bleeding has stopped. A response that spends the first 30 minutes running CloudTrail queries before disabling the key has its priorities wrong.

A well-designed response does not assume the worst case. The key has been live for six hours. The attacker may have done nothing. The attacker may have exfiltrated every secret in every Secrets Manager secret in the account. The response must contain *and* investigate, and the investigation drives the recovery scope.

---

## SOLUTIONS hint (read after attempting)

The single most-important action in the first 60 seconds: **`aws iam delete-access-key --user-name <developer> --access-key-id <key-id>`**. Disable, do not deactivate. Deactivating a key (`UpdateAccessKey --status Inactive`) leaves the key visible to the attacker; deletion removes it from IAM entirely. AWS revokes the credential immediately upon deletion; any in-flight API call with that credential fails on the next call.

The decision that requires the most care: when to *also* delete the developer's IAM user (versus just the key). Deleting the user is recoverable (you can recreate via Terraform) but disruptive. The recommendation: delete the key first (seconds), disable the user's console password second (minutes), delete the user only after the SSO replacement is in place (hours-to-days). This sequence minimises the developer's disruption while removing the attacker's options.

The CloudTrail query that bounds the blast radius is the one that filters by `userIdentity.accessKeyId = <the-leaked-key-id>`. Every API call attributable to the key is in this filter's results. The query lives at https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-find-leaked-keys.html (AWS publishes the canonical pattern).

---

## Submission

Submit the three artefacts as a single markdown document. The grader reads for completeness, sequencing, communication tone, and adherence to the AWS-published canonical response. A response that omits the AWS T&S form, or that fails to specify CloudTrail query precision, does not pass.
