# Week 11 — Quiz

> 25 short-answer questions. One sitting; no notes; aim for under 45 minutes. Answer in your own words. If a question begins with "Cite", give the canonical reference (URL or document name) you would point a colleague at.

---

## Section 1 — IAM fundamentals and the AWS policy language (Q1-Q9)

**Q1.** Name the four conceptual ingredients of every IAM decision and give a one-word AWS-vocabulary translation of each.

**Q2.** In one sentence, define an Amazon Resource Name (ARN) and write the canonical six-colon-separated structure.

**Q3.** What value does the `Version` field of an IAM policy take in 2026, and what would AWS do if you submitted `"Version": "2008-10-17"`?

**Q4.** Translate the iptables-style intuition "default deny" into the IAM policy-evaluation algorithm in one sentence.

**Q5.** Name the four required JSON keys in every IAM policy statement, and name three optional keys.

**Q6.** Explain in two sentences why the canonical pattern `{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}}` is one of the most-deployed defensive policies in production AWS.

**Q7.** What is the difference between an *identity-based* policy and a *resource-based* policy, and what JSON key appears on a resource-based policy that does not appear on an identity-based one?

**Q8.** In two sentences, describe what the `Principal` field on an IAM role's *trust policy* controls.

**Q9.** Cite the canonical free reference for AWS IAM policy evaluation logic.

---

## Section 2 — Identity, resource, ABAC, and SCPs (Q10-Q17)

**Q10.** ABAC stands for what, and what is the canonical AWS ABAC condition that says "the principal's `Project` tag must equal the resource's `Project` tag"?

**Q11.** In one sentence, articulate the most-important operational property ABAC provides over identity-based access control as the number of teams grows.

**Q12.** What is the difference between a Service Control Policy and an identity-based policy in terms of *what each grants*?

**Q13.** Name three actions that a well-deployed Service Control Policy at the organisation level routinely denies, and explain in one sentence why each denial matters.

**Q14.** Why are Service Control Policies *not* applied to the AWS Organizations management account, and what is the standard recommendation about what workloads run in the management account?

**Q15.** GCP's equivalent of AWS SCPs is called what, and name two example constraints.

**Q16.** Azure's equivalent of AWS SCPs is called what, and name two effects it can apply that AWS SCPs cannot.

**Q17.** Cite the canonical free reference for the AWS ABAC tutorial.

---

## Section 3 — Misconfiguration scanning (Q18-Q25)

**Q18.** In one sentence, define what a *misconfiguration scanner* is and name three free open-source ones.

**Q19.** What is the structural difference between Prowler and Checkov in terms of *what each operates on*?

**Q20.** Name the AWS Security Finding Format (ASFF) and explain in one sentence why it matters that Prowler emits ASFF.

**Q21.** What is the recommended least-privilege IAM role for a Prowler scan against a real AWS account?

**Q22.** Name three Checkov check IDs you would expect to fire on a Terraform stack that declares an S3 bucket with `acl = "public-read"`.

**Q23.** In two sentences, describe the trade-off between running Prowler weekly against a live account and running Checkov on every commit against the Terraform source.

**Q24.** Cite the CIS Benchmark you would consult for AWS-specific configuration baselines, give its version number as of May 2026, and name one control inside it that maps to "no root account access key exists".

**Q25.** Cite NIST SP 800-207 and explain in one sentence why it is the framing reference for "every API call is authenticated and authorised".

---

## Answer guidance

Answers should be short and specific. "Long, vague, and confident" reads worse than "short, precise, and honest about what you do not know". If a question asks for a URL or a document name, the answer is incomplete without one. The grader looks for:

- **Q1.** Subject, Resource, Action, Condition — translating to Principal, Resource, Action, Condition (sometimes the subject is the implicit principal).
- **Q3.** `"Version": "2012-10-17"`. Submitting `"2008-10-17"` produces a policy parsed under the older grammar, which lacks several features (multi-value conditions, policy variables); AWS still accepts it for back-compat but flags it in advisor output.
- **Q5.** Required: `Version` (at policy level), `Statement`, `Effect`, `Action`. Optional: `Sid`, `Principal`, `Resource`, `Condition`, `NotAction`, `NotResource`, `NotPrincipal`, `Id`.
- **Q12.** SCPs do not grant permissions; they only *limit* the maximum permissions the targeted accounts can have. Identity-based policies grant permissions.
- **Q13.** Example denials: `cloudtrail:StopLogging` (preserves the audit trail); `iam:CreateUser` (forces IAM Identity Center usage); `s3:PutAccountPublicAccessBlock` with `RestrictPublicBuckets=false` (prevents public S3); region lockdown via the `aws:RequestedRegion` condition.
- **Q14.** The management account is the root of the Organizations tree and is excluded from SCP enforcement by design. Recommendation: keep the management account empty — no workloads, no roles beyond what Organizations itself requires, no resources. The management account is the highest-blast-radius identity in the organisation and is best left minimal.
- **Q15.** GCP Organisation Policies. Examples: `iam.disableServiceAccountKeyCreation`, `compute.requireOsLogin`, `storage.uniformBucketLevelAccess`.
- **Q16.** Azure Policy. Effects unique to Azure Policy: `modify` (mutates the resource at create time to bring it into compliance); `deployIfNotExists` (deploys a related resource when the policy is non-compliant); `auditIfNotExists` (similar pattern for audit-only).
- **Q18.** Prowler (live AWS/Azure/GCP), Checkov (IaC text), ScoutSuite (multi-cloud HTML report). Other valid answers: tfsec, kics, AWS Config rules, cloudquery.
- **Q19.** Prowler operates on *live cloud-account API state* — it makes read-only API calls. Checkov operates on *static IaC text* — it reads Terraform/CloudFormation/Kubernetes YAML on disk without any cloud credentials.
- **Q20.** AWS Security Finding Format. The schema is stable and AWS-published; tooling that consumes ASFF survives Prowler version upgrades, and AWS Security Hub ingests ASFF natively.
- **Q21.** `SecurityAudit` + `ViewOnlyAccess` (both AWS-managed) + a small explicit allow list for newer services not in either. Trust policy restricts assumption to the security account with MFA required.
- **Q22.** `CKV_AWS_20` (S3 bucket should not have public ACL), `CKV_AWS_53`-`CKV_AWS_56` (S3 BlockPublicAccess settings), and at least one of `CKV_AWS_18`, `CKV_AWS_19`, `CKV_AWS_21` (logging, encryption, versioning — typically also missing alongside a public ACL).
- **Q23.** Trade-off: Checkov-on-commit catches the misconfiguration *before* it ever reaches production (cheapest possible fix, milliseconds), but it only sees the IaC text and misses drift introduced by console clicks or by AWS service updates that change defaults. Prowler-against-live catches drift but is slower (minutes per run), requires cloud credentials, and discovers misconfigurations only after they have been provisioned.
- **Q24.** CIS Amazon Web Services Foundations Benchmark v3.0.0 (current as of 2026). Control 1.4 — "Ensure no root user account access key exists."
- **Q25.** NIST SP 800-207, "Zero Trust Architecture", https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf. The seven tenets — including "all communication is secured regardless of network location" and "access to individual enterprise resources is granted on a per-session basis" — frame "every API call is authenticated and authorised" as the cloud-native expression of the same architectural commitment.

Score yourself out of 25. A passing answer is 18 or above. Re-read the relevant lecture for any section you scored below 6 out of 9.
