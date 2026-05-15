# Challenge 2 — Cross-Account Role Trust

> Design exercise. The deliverable is a written design plus IAM JSON policy text for both ends of the trust relationship. Read the exercises before attempting the challenge.

---

## Authorized-use disclaimer

The policies in this challenge are written for a notional multi-account AWS Organization you describe in writing. If you choose to exercise the design against real accounts, those accounts must be ones you own or for which you hold written authorisation from their owner.

---

## The scenario

Your organisation runs in AWS with three accounts:

- **Account A — Security**. Account ID `111111111111`. Contains the centralised security tooling: a Prowler runner in a Lambda, an Athena instance over the CloudTrail logs from every account, a Slack-notification webhook. Operated by the security team.
- **Account B — Production**. Account ID `222222222222`. Runs the customer-facing application. Operated by the application engineering team. The team has full administrative access to Account B; they do not have access to A or C.
- **Account C — Data Lake**. Account ID `333333333333`. Holds the long-term data archive in S3 plus the analytics workloads. Operated by a small data team.

The new requirement: a daily reporting job in Account A needs to read CloudTrail logs from Account B (via Account B's S3 bucket where CloudTrail writes), correlate them with operational data in Account C (a specific S3 prefix in C's data lake), and write the correlated output to a private S3 bucket in Account A. The job runs on EventBridge schedule from Account A, executes in a Lambda in Account A, and must complete within 15 minutes. The job must not be able to do anything other than read the two designated source paths and write to the one designated destination.

The data team in Account C is uneasy about the request. They have heard "we just need to grant the security team access" too many times and want the grant scoped tightly. They want to know exactly what API calls Account A will make, exactly which S3 prefix is in scope, and exactly what conditions gate the access.

The application team in Account B is less anxious because the bucket in question already holds CloudTrail logs and they understand the security team needs to read those logs. They are still entitled to see the policy.

---

## What you produce

Four artefacts:

### Artefact 1 — The IAM role in Account A

The role the Lambda assumes when it runs. Provide:

- The role name and a one-line purpose.
- The trust policy (who is allowed to assume this role).
- The identity-based policy attached to the role (what the role is allowed to do).
- A reasoned justification for each `Action` in the identity-based policy.

The trust policy should permit only the Lambda service to assume the role, scoped to the specific Lambda function ARN. The identity-based policy should permit:

- Reading from Account B's CloudTrail S3 bucket (one prefix only).
- Reading from Account C's data lake S3 prefix.
- Writing to Account A's output bucket.
- Logging to a specific CloudWatch log group in Account A.
- *Decrypting* with whichever KMS keys are needed (Account B and Account C are likely to have CloudTrail logs and data-lake objects encrypted with their own keys).

### Artefact 2 — The resource-based policies in Account B and Account C

Each of Accounts B and C must have a bucket policy on the relevant bucket *and* (if the bucket is encrypted) a key policy on the relevant KMS key that explicitly permits the Account A role to perform the actions.

Provide both the bucket policy text and the key policy text. The bucket policy must restrict the grant to:

- The specific Account A role ARN (not "any principal in Account A").
- The specific S3 actions needed (`s3:GetObject`, `s3:ListBucket`, with a `s3:prefix` condition for the listing).
- TLS-only access (`aws:SecureTransport = true`).
- The specific Account A *not* simply by account ID but by the role's ARN.

### Artefact 3 — The condition design

Cross-account trust is exactly the place where conditions earn their cost. The challenge: enumerate every condition you would add to the trust policy, identity-based policy, and resource-based policies, and explain what attack each condition defends against.

At minimum, your enumeration must include:

- An `aws:SourceAccount` condition (or `aws:SourceArn`) on the trust policy. (Defends against the *confused deputy* attack — a third party tricking the AWS service into using its credentials to access your resources.)
- A `sts:ExternalId` condition. (Defends against the same confused-deputy problem in cross-organisation trust; arguably unnecessary in within-organisation trust but the cost is small.)
- An `aws:PrincipalArn` condition on the resource-based policies that names the *exact* role ARN. (Defends against the case where Account A grows new roles you did not vet.)
- An `aws:SecureTransport` condition. (Defends against accidental plaintext access; cheap to add; never wrong.)
- A `s3:prefix` condition on the `ListBucket` permission. (Constrains the listing to the relevant prefix; the listing without it discloses the bucket's other contents.)
- A `kms:ViaService` condition on any KMS decrypt that goes through a service principal. (Defends against direct calls to KMS that should not be allowed.)

For each, write one paragraph explaining the threat the condition defends against. If you propose additional conditions, include them with a similar justification.

### Artefact 4 — The change-management plan

You cannot deploy these policies all at once. The order of operations matters:

1. **Account A** — create the role (with the trust policy and the identity-based policy) first. The role exists but the resource-based policies do not yet permit it; the role cannot do anything yet.
2. **Account C** — the data team reviews the proposed bucket policy and KMS key policy, asks questions, and either approves or asks for changes. Iterate. When approved, deploy.
3. **Account B** — the application team does the same. Deploy when approved.
4. **Account A** — deploy the EventBridge schedule and the Lambda function. The first invocation succeeds (the policies are now consistent across all three accounts).
5. **Account A** — monitoring. Add a CloudWatch alarm on the Lambda's error rate. Add an Athena query that confirms the role's CloudTrail entries are consistent with the expected access pattern.

Write the change-management plan as a numbered list with the per-account owner, the approval gate, and the rollback procedure for each step. The rollback procedure for an Account-B policy change is non-trivial — you cannot simply revert because in-flight invocations from Account A will fail; describe the graceful path.

---

## Constraints

- No long-lived IAM users. The Account A role is service-role-only (trust policy permits only `lambda.amazonaws.com`).
- No `Principal: "*"` anywhere. Every grant names a specific role, service, or account.
- No `Resource: "*"` on the identity-based policy. Every `Resource` is a specific ARN or ARN-with-wildcard at a path level.
- The policies are committed to Terraform. The challenge expects the IAM JSON, not Terraform HCL — but a real deployment lands the JSON inside `aws_iam_policy` / `aws_s3_bucket_policy` / `aws_kms_key_policy` resources.

---

## What "good" looks like

A good design is *visibly mistrustful in both directions*. Account A's policy assumes Account B's bucket could be misconfigured and constrains the actions it will perform. Account B's bucket policy assumes Account A could be compromised and constrains *who* in Account A can read and *under what conditions*. The two ends of the trust meet in the middle, with neither end fully trusting the other.

A good design names every condition. Every `Condition` block has a corresponding paragraph in Artefact 3 explaining what attack it defends against. A condition without a justification is a defect; remove it.

A good design accounts for failure. The change-management plan in Artefact 4 has a rollback for every step. The grader will probe for "what happens when Account C's KMS key rotates", "what happens when the Lambda timeout is exceeded mid-read", "what happens when Account A's role is accidentally deleted" — and a good design has an answer.

---

## SOLUTIONS hint (read after attempting)

The confused-deputy primer: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html. The relevant conditions are `aws:SourceAccount` and `aws:SourceArn`; AWS documentation prefers the latter when the source can be named specifically.

The cross-account bucket-policy pattern: https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html#example-bucket-policies-acl-3. The cross-account KMS-key-policy pattern: https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html.

The `sts:ExternalId` pattern is described at https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html. It is overkill for within-organisation trust but the cost of adding it is trivial and the cost of *not* adding it when the trust pattern eventually expands to a third party is high.

---

## Submission

Submit the four artefacts as a single markdown document. The grader reads for the specificity of the conditions, the symmetry of mistrust between the ends, the completeness of the change-management plan, and the adherence to the AWS-published canonical patterns. A submission that grants `Principal: {"AWS": "arn:aws:iam::111111111111:root"}` instead of the specific role ARN fails on the first artefact.
