# Week 11 — Exercise Solutions

> Read each exercise file before reading its solution. The solutions walk through the *reasoning* the exercise tests; the policy text or the code is in the corresponding file.

---

## Exercise 1 — Policy Anatomy (`exercise-01-policy-anatomy.json`)

The exercise asks six questions. The answers:

### (1) The four required JSON keys

- `Version` — present, set to `"2012-10-17"`.
- `Statement` — present, an array of six statement objects.
- `Effect` — present in every statement (five `Allow`, one `Deny`).
- `Action` — present in every statement, occasionally as `NotAction` in statement five.

### (2) The optional keys present

- `Id` — present at policy level (`c6-week11-exercise-01-anatomy-policy`).
- `Sid` — present on every statement (`BuildPipelineFullAccess`, `DeploymentArtefactReadWrite`, `TimeBoundProductionWriteWindow`, `DenyKMSWriteEverExceptDuringRotation`, `AllowDescribeAcrossAccount`, `AssumeDeployerAcrossAccount`).
- `Resource` — present on every statement except where `NotAction` carries the negation (the `AllowDescribeAcrossAccount` statement uses `NotAction` and a wildcard `Resource`).
- `Condition` — present on statements 2, 3, 4, 5, and 6.
- `NotAction` — present on statement 5.

### (3) Every action and every resource the policy grants

The grant is not least-privileged. Statement 1 alone grants:

- `s3:*`, `ecr:*`, `ec2:*`, `logs:*`, `cloudwatch:*` on `*` (every resource in the account, every region).
- `iam:PassRole`, `iam:GetRole`, `iam:ListRoles` on `*`.

Statements 2 and 3 *appear* to narrow access — statement 2 scopes the S3 access to two named buckets with a TLS condition and a tag-match condition; statement 3 scopes the ECR access to a single repository name pattern with a time-bound condition — but statement 1 has already granted the same actions much more broadly on `*`. The narrower statements are inert because IAM's union-of-allows semantics means the broader grant wins.

Statement 6 is the only statement that actually scopes a sensitive action (`sts:AssumeRole`) tightly. It grants the action to two specific role ARNs in two specific accounts, conditioned on MFA and on a tag match. This statement is correct.

### (4) Every condition that gates the grant

- Statement 2: `aws:SecureTransport = true` and `aws:PrincipalTag/Pipeline = ci-deployer`. (Inert in the presence of statement 1.)
- Statement 3: `2026-05-14T08:00:00Z < aws:CurrentTime < 2026-05-14T18:00:00Z`. (Inert in the presence of statement 1.)
- Statement 4: `aws:MultiFactorAuthPresent = false`. The `Deny` effect makes this statement bite when MFA is absent. It is the only condition that materially constrains the policy.
- Statement 5: `aws:RequestedRegion ∈ {us-east-1, us-west-2}` with `StringEqualsIfExists`. The `IfExists` suffix is important — it means the condition is satisfied when the key is absent. For region-less global services, the condition is satisfied vacuously and the `NotAction`-scoped allow applies.
- Statement 6: MFA present plus `aws:PrincipalTag/Pipeline = ci-deployer`.

### (5) Three things wrong with the policy from a least-privilege standpoint

1. **Statement 1 is `Action: <list> on Resource: "*"`.** The action list includes `s3:*`, `ecr:*`, and `ec2:*` — every API in three sprawling services on every resource. This is functionally administrative access to S3, ECR, and EC2. The "build pipeline" stated purpose justifies pulling images, pushing images, and writing logs; it does not justify the ability to delete every S3 bucket in the account.
2. **`iam:PassRole` on `Resource: "*"`.** `iam:PassRole` lets a principal pass an IAM role to a service (e.g., when launching an EC2 instance, passing the role to be assumed by the instance). With `Resource: "*"`, the build pipeline can pass *any* role to *any* service. Combined with statement 1's `ec2:*`, the pipeline can launch an EC2 instance with an administrator role attached and own the account. This is the canonical privilege-escalation primitive.
3. **The narrower statements 2 and 3 are inert.** Statement 1's broad allow already covers everything they would grant. Removing statement 1 (or removing the broad actions from it) would make 2 and 3 the operative grants, restoring the least-privilege intent.

Other defects worth naming, but not asked for in the exercise:

4. The `Deny` on KMS in statement 4 fires *when MFA is absent*. The CI pipeline runs in a build robot that does not have a human present to perform MFA. The build robot will fail every KMS call. This is either intentional (the policy is deliberately preventing KMS access from CI) or a bug; the policy does not say which, and a least-privilege policy would clarify.
5. The cross-account assume-role permissions in statement 6 trust the principal's tag. The tag value is set by whoever provisions the principal. If an attacker can write the tag (statement 1's broad `ec2:*` includes `ec2:CreateTags`), they can tag a principal as `ci-deployer` and assume the production-deployer role.

### (6) Specific Prowler / Checkov check IDs expected to fire

Prowler:

- `iam_policy_no_administrative_privileges` — fires because the policy is effectively administrative on S3, ECR, EC2.
- `iam_policy_avoid_full_access` — fires on `s3:*`, `ecr:*`, `ec2:*`.
- `iam_policy_allows_privilege_escalation` — fires on the `iam:PassRole` + `ec2:RunInstances` combination.
- `iam_policy_attached_only_to_group_or_roles` — fires if attached to an individual user rather than a role.

Checkov:

- `CKV_AWS_40` — IAM policy should not have wildcards in actions.
- `CKV_AWS_49` — IAM policy should not allow administrative actions.
- `CKV_AWS_60` — IAM role with overly permissive trust policy (if the trust policy were equally broad).
- `CKV_AWS_61` — IAM policy with cross-account access requires conditions (the assume-role statement does have conditions, so this would not fire).
- `CKV_AWS_111` — IAM policy with write access should restrict resource.

---

## Exercise 2 — Author a Least-Privilege Policy (`exercise-02-least-priv-deployer.json`)

The exercise asks you to compare your own draft against the file. The walk-through below traces the design from blank to the candidate answer.

### Step 1 — Read the requirements list

The seven bullet points list the actions the role needs (pull source, build, push to ECR, write logs, read SSM, use a specific KMS key), the region constraint (us-east-1 only), the transport constraint (TLS only), the explicit denies, and the federation pattern (OIDC from GitHub Actions, no long-lived credentials).

### Step 2 — Translate each requirement into a Statement

The candidate answer has nine statements; the requirements list has roughly seven items. The mapping:

- Requirements "TLS required" and "us-east-1 only" become *deny-style* statements at the top of the policy (`RequireTLS`, `LockToOneRegion`). Putting the deny at the top is editorial — IAM evaluates the union of statements, not in order — but it reads better.
- Requirement "pull source from CodeCommit" becomes the `PullSourceFromCodeCommit` statement, scoped to one repository ARN.
- Requirement "push to ECR" splits into two: `AuthenticateToECR` (the auth-token action requires `Resource: "*"` because the token is account-scoped, not repository-scoped) and `PushImagesToOneRepository` (the layer-upload and image-push actions, scoped to one repository ARN).
- Requirement "write build logs" becomes `WriteBuildLogsToOneLogGroup`, scoped to one log group and its child streams.
- Requirement "read SSM parameters" becomes `ReadDeployConfigFromOneSSMPrefix`, scoped to a parameter-name path prefix.
- Requirement "decrypt the app's KMS key" becomes `DecryptOnlyTheAppKMSKey`, scoped by `kms:ViaService` (only when the call is on behalf of SSM or ECR) and by the resource's `Project` tag.
- Requirement "explicit denies" becomes the final `ExplicitDenyOnSensitiveActions` statement listing the IAM, Organizations, CloudTrail, S3-administrative, and KMS-destructive actions.

### Step 3 — Choose `Resource` ARNs precisely

Each statement's `Resource` is as narrow as the service supports:

- CodeCommit: `arn:aws:codecommit:us-east-1:123456789012:c6-week11-app` — one repo.
- ECR: `arn:aws:ecr:us-east-1:123456789012:repository/c6-week11-app` — one repo.
- Logs: `arn:aws:logs:us-east-1:123456789012:log-group:/aws/codebuild/c6-week11-app` *and* `:*` (the wildcard suffix is required to address log streams within the group).
- SSM: `arn:aws:ssm:us-east-1:123456789012:parameter/c6-week11/app/*` — one prefix.
- KMS: `*` with the `kms:ViaService` condition narrowing — KMS does not allow naming a key by alias in a `Resource` ARN, so the narrowing has to live in the condition.

### Step 4 — Conditions

Two important condition mechanics:

- `StringEqualsIfExists` versus `StringEquals`. The `IfExists` variant is satisfied vacuously when the key is missing. Useful for global-service calls that do not have a region; harmful when applied to keys that *must* be present for the policy to be safe.
- `ForAnyValue:StringEquals` — required when the condition compares against a multi-value request key (like the list of services in `kms:ViaService` for a call that crosses services).

### Step 5 — The explicit deny

The last statement is the most-important. It denies the actions that would let the role escalate privilege:

- IAM modification (`CreateUser`, `CreateAccessKey`, `AttachRolePolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`).
- Organizations modification (any action).
- CloudTrail tampering.
- S3 administrative actions (`CreateBucket`, `DeleteBucket`, `PutBucketAcl`, `PutBucketPolicy`, `PutBucketPublicAccessBlock`).
- KMS destructive actions (`ScheduleKeyDeletion`, `DisableKey`, `DisableKeyRotation`).

Why a deny when none of these actions are in the allow? Because of defence in depth. The deny survives a future careless edit that adds a broader allow. The deny is the seat belt; the narrow allows are the careful driving.

### Step 6 — Verify

`aws iam simulate-principal-policy` against a test role with this policy attached and a list of representative API calls. The simulator's verdict is the policy's truth. Cite https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html.

---

## Exercise 3 — ABAC by Project Tag (`exercise-03-abac-by-project-tag.tf`)

The Terraform file is a complete runnable stack. The walk-through:

### Step 1 — The resources

`aws_s3_bucket.project_buckets` is a `for_each` resource that creates one bucket per project name. Each bucket is tagged with `Project = <name>` via the resource's `tags` block. The `default_tags` on the provider apply additional tags (`Course`, `Exercise`, `Environment`) — important for ABAC to remember that the principal sees the *combined* tag set, not just the per-resource block.

`aws_iam_role.project_roles` is a `for_each` resource that creates one role per project name. Each role is tagged with `Project = <name>`. The role's trust policy permits the principal account's root to assume the role, conditioned on MFA being present in the session.

### Step 2 — The single ABAC policy

`aws_iam_policy.abac_project_match` is the policy with four statements:

1. `RequireTLS` — deny everything when `aws:SecureTransport` is false.
2. `ListBucketsOnTagMatch` — allow `s3:ListBucket` etc. on every `c6-week11-abac-*` bucket *when the principal's `Project` tag equals the resource's `Project` tag*.
3. `ReadWriteObjectsOnTagMatch` — same condition, applied to object-level actions.
4. `TaggingDiscipline` — deny tag modifications on the `Project` key. Prevents a principal from retagging a resource to gain access.

The condition `"aws:ResourceTag/Project" = "$${aws:PrincipalTag/Project}"` uses Terraform's `$${...}` escape (the doubled `$$` becomes a literal `${...}` in the rendered policy JSON, which IAM then interprets as a policy-variable interpolation).

### Step 3 — The attachment

`aws_iam_role_policy_attachment.project_role_abac` attaches the *single* ABAC policy to *every* per-project role. One policy, N attachments, scales with the number of projects.

### Step 4 — Verification

The `verification_commands` output describes the four `aws s3 ls` calls that prove the policy works:

- Assume the apollo role; list the apollo bucket → success.
- Assume the apollo role; list the beacon bucket → AccessDenied (the tag mismatch fails the condition).
- Assume the beacon role; list the beacon bucket → success.
- Assume the beacon role; list the apollo bucket → AccessDenied.

If you observe a different result, the most-likely cause is: the session's tags are missing (the role was created without the `Project` tag), or the bucket's tags are missing (Terraform applied to an existing bucket that did not have the tag), or you forgot the MFA flag on the `aws sts assume-role` call.

### Why this scales

Add a third project (`Project = cassandra`):

```hcl
variable "project_names" {
  default = ["apollo", "beacon", "cassandra"]
}
```

`terraform apply`. A new bucket is provisioned with `Project = cassandra`. A new role is provisioned with `Project = cassandra`. The single ABAC policy already applies. No edits to the policy were required. The same policy that worked for two projects now works for three.

---

## Exercise 4 — Three SCPs for an OU (`exercise-04-scp-guardrails.json`)

### SCP 01 — Region lockdown

What it permits: every action, every resource, *as long as* `aws:RequestedRegion` is `us-east-1` or `us-west-2` — or the action is in the `NotAction` list (global / region-less services).

What it denies: any action against a region other than the two approved ones.

The `NotAction` list is exhaustive enough to cover all the global AWS services that this kind of SCP routinely breaks for hapless operators: `iam`, `organizations`, `sts`, `support`, `cloudfront`, `route53`, `waf*`, `shield`, `globalaccelerator`, `trustedadvisor`, `budgets`, `ce`, `cur`, `aws-marketplace`, `savingsplans`, `tag*`, `health`. The first time you deploy a region SCP, you will discover three or four additional services that should have been in the `NotAction` list and were not; the canonical AWS Organizations guide at https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html lists the consensus set.

Most-likely-to-lock-you-out: this one, when used carelessly. If you forget to exclude `cloudfront` and you have CloudFront distributions, every CloudFront API call is denied.

Deploy order: this one *third*. Region lockdown is high-blast-radius; deploy after the protective SCPs are in place to give yourself time to test.

### SCP 02 — CloudTrail / Config / GuardDuty protection

What it permits: nothing (deny statements only).

What it denies: actions that would tamper with the three audit / detection services. CloudTrail (`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors`, `RemoveTags`). Config (`DeleteConfigRule`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel`, `StopConfigurationRecorder`). GuardDuty (`DeleteDetector`, `DisassociateMembers`, `StopMonitoringMembers`, `UpdateDetector`).

Most-likely-to-lock-you-out: not particularly likely; the actions denied are rarely-used. The risk is denying legitimate maintenance actions — a Config rule that genuinely needs to be deleted will require a break-glass session in the management account.

Deploy order: this one *first*. Audit-trail protection is the highest-value, lowest-risk SCP and should be in place before any other SCP that could mask issues by accident.

### SCP 03 — Public S3 prevention plus IAM-user denial

What it permits: nothing (deny statements only).

What it denies:

- `s3:PutAccountPublicAccessBlock` with `RestrictPublicBuckets = false` — prevents disabling BlockPublicAccess at the account level.
- `s3:PutBucketAcl` with a public ACL — prevents setting a public ACL on any bucket.
- `s3:PutObject` / `PutObjectAcl` with a public ACL — prevents writing public objects.
- `iam:CreateUser`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:CreateServiceSpecificCredential` — prevents creating IAM users in an OU that should use IAM Identity Center.

Most-likely-to-lock-you-out: not particularly likely; the actions denied are well-defined and rarely the right thing to do in modern AWS.

Deploy order: this one *second*. After audit protection, the next-highest-value SCP is the prevention of the misconfigurations that produce most public breaches.

### The deployment order, summarised

1. SCP 02 — protect the audit trail.
2. SCP 03 — prevent public S3 and IAM-user creation.
3. SCP 01 — lock the OU to two regions.

Each SCP is tested in a sandbox OU first; the sandbox OU is a child OU with one or two empty test accounts, and the operator runs `aws s3 ls`, `aws ec2 run-instances`, and similar canary commands to confirm both that the legitimate actions still work and that the prohibited actions are now refused.

---

## Exercise 5 — Prowler Triage (`exercise-05-prowler-triage.py`)

The script is straightforward. The walk-through targets the design decisions, not the syntax.

### Why parse ASFF and not Prowler's native JSON?

ASFF (the AWS Security Finding Format) is a stable schema. Prowler's native JSON has evolved between major versions (v3 to v4 to v5 reshaped fields). The ASFF output is the format AWS Security Hub consumes, which means it has API-stability guarantees from AWS. Tooling that reads ASFF survives a Prowler upgrade.

### Why a triage report rather than just a finding list?

Two reasons. First, the raw finding list is too large to scan; a real Prowler run produces hundreds of findings, and the human eye needs aggregation to find patterns. Second, the triage report is the artefact you bring to a weekly review meeting: severity counts, top services, top checks, top compliance failures. The conversation is then "we have 30 HIGH findings, 22 of them in IAM, all clustered around `iam_user_no_access_keys` — let's deprecate IAM users for that OU this sprint" — a conversation the raw list does not support.

### The exit-code convention

`0` for success, `1` for bad input, `2` for "findings over threshold". The `--fail-on` flag gates the third. In CI:

```bash
python3 exercise-05-prowler-triage.py "$REPORT" --fail-on HIGH || exit $?
```

The CI step fails when a HIGH-or-CRITICAL finding is present. The build artefact (the triage summary) is still produced because the script prints the summary before evaluating the gate.

### Common parsing gotchas

ASFF emitted by Prowler 4.x sometimes uses `GeneratorId: "prowler-<check_id>"` and sometimes `GeneratorId: "<check_id>"` directly. The script strips the prefix when present. The other variation is whether `Compliance.RelatedRequirements` is a list of strings (the documented form) or a list of objects (an older variant). The script tolerates the list-of-strings form; if you encounter the list-of-objects form, add a normalisation step that extracts the string identifier from each object.

---

## Exercise 6 — Drive Checkov from CI (`exercise-06-checkov-ci.py`)

### Why a wrapper rather than vanilla `checkov`?

Three reasons:

1. **Pinned configuration.** Calling `checkov --directory .` from CI inherits Checkov's defaults, which change between minor versions. The wrapper pins the frameworks, the output format, and the skip-check list explicitly.
2. **Severity gating.** Checkov's own exit-code convention is "non-zero when any check fails". A real codebase has dozens of LOW-severity findings that are legitimate and not worth blocking on. The wrapper gates on HIGH-or-above by default, with the threshold configurable per-codebase.
3. **PR-comment generation.** The wrapper emits a markdown summary that a CI workflow can post back to the pull request via `gh pr comment`. The summary is human-readable and links the failing checks to file paths and line ranges.

### Why parse the JSON output rather than scrape stdout?

stdout is for humans; JSON is for tools. Checkov's stdout format changes between versions (the colour coding, the line breaks, the truncation rules); the JSON output is part of Checkov's contract and is stable.

### The `--use-existing-report` flag

The flag lets the script run against a pre-recorded report file, which is essential for unit testing. The Week 11 grader's automated test harness drops a known-good `results_json.json` into the script's input and verifies the summary it produces; the test does not depend on Checkov being installed in the grader environment.

### Skip discipline

The `--skip-check` flag accepts repeated values or comma-separated lists (`--skip-check CKV_AWS_50,CKV_AWS_79`). Every skip should also appear in a code comment near the resource it applies to, with a justification:

```hcl
resource "aws_lambda_function" "image_processor" {
  # checkov:skip=CKV_AWS_50:X-Ray tracing not supported on this runtime version
  function_name = "image-processor"
  runtime       = "python3.11"
  ...
}
```

A skip without a justification is a defect.

### CI integration

The recommended GitHub Actions workflow:

```yaml
name: IaC Security
on:
  pull_request:
    paths: ['terraform/**']

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.11'}
      - run: pipx install checkov==3.* 
      - name: Run Checkov via wrapper
        run: |
          python3 exercise-06-checkov-ci.py \
            --directory terraform \
            --fail-on HIGH \
            --emit-markdown checkov-summary.md
      - name: Post PR comment
        if: failure()
        run: gh pr comment ${{ github.event.pull_request.number }} -F checkov-summary.md
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The job runs on every PR that touches Terraform. Checkov runs. The wrapper gates on HIGH. The markdown summary is generated regardless. On failure, the summary is posted to the PR. The author sees the findings in the PR thread, not buried in CI logs.

---

## Where to go next

After working through the six exercises:

- Challenge 1 (rotate the keys) and Challenge 2 (cross-account role trust) — apply the language and tooling to higher-stakes scenarios with less scaffolding.
- The mini-project — the deliberate-misconfig Terraform stack and the design-doc deliverable.
- The quiz on Sunday — twenty-five short-answer questions; one sitting; no notes.
