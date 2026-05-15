# Lecture 2 — Identity-, Resource-, Attribute-Based Policies and Service Control Policies

> *Lecture 1 introduced the four ingredients of an IAM decision and the AWS policy grammar. Lecture 2 takes the four conceptual *kinds* of policy that combine to produce a real account's authorisation surface — identity-based, resource-based, attribute-based, and service-control — and walks through when each is the right tool, what each is bad at, and how they interact at evaluation time.*

---

## 1. The four kinds of policy, mapped to the four ingredients

A useful way to organise the policy taxonomy is to ask, for each policy type, which of the four ingredients (subject, resource, action, condition) the policy is *primarily* about.

| Policy type        | Primary axis        | Attached to           | Common purpose                                              |
|--------------------|---------------------|------------------------|-------------------------------------------------------------|
| Identity-based     | Subject             | User / group / role    | "What can *this principal* do?"                              |
| Resource-based     | Resource            | The resource           | "Who can do what on *this thing*?"                           |
| Attribute-based    | Condition           | Identity (with tags)   | "Match on tags, not on identity binding"                     |
| Service-Control    | Subject (account)   | Account / OU           | "What is the account, in aggregate, allowed to even attempt?"|

The four are not exclusive. A real account uses all four simultaneously. A request walks through all four during evaluation. The art of IAM design is choosing, for each access control requirement, which of the four expresses the requirement most clearly and most safely.

---

## 2. Identity-based policies in depth

Identity-based policies are the default policy attachment in AWS. They attach to:

- **An IAM user** — a long-lived identity, typically with a console password and access keys. The modern recommendation is to *avoid* IAM users for humans; humans should sign in via an identity provider (AWS IAM Identity Center, formerly AWS SSO, or a customer-operated SAML / OIDC IdP), which produces short-lived role-sessions. IAM users still make sense for machine identities that cannot use role-based credentials (some on-prem CI workers, some legacy SDKs), and even there the recommended pattern is *no* IAM user if you can use IAM Roles Anywhere or a federated equivalent.
- **An IAM group** — a container for users. Policies attached to the group apply to every user in the group. Groups are a convenience for the *attachment* relationship; they are not principals themselves and cannot make API calls.
- **An IAM role** — a short-lived identity assumed by a principal (a user, a service, another role) via the `sts:AssumeRole` API. The role-session has its own credentials (an access-key ID, a secret access key, a session token) and an expiry typically between one hour and twelve hours. Roles are the *correct* attachment point for almost every permission grant in a modern AWS account.

The two flavours of identity-based policy:

- **Managed policies.** Named. Reusable. Attached to any number of identities. AWS-managed (the catalogue includes `AdministratorAccess`, `ReadOnlyAccess`, `SecurityAudit`, `PowerUserAccess`, hundreds more) or customer-managed (your own). The IAM service tracks every attachment, and the IAM Access Analyzer can tell you which identities have which policies. Managed policies are the right default.
- **Inline policies.** Embedded in a single identity. Lifecycle-bound to the identity (delete the user; the inline policy vanishes). Invisible in the managed-policy listings (you have to inspect each identity individually to find them). Useful when a permission set is genuinely unique to one identity and you want it to vanish when the identity does. Otherwise, prefer managed.

The size limits matter:

- Managed policy: 6 144 characters maximum (excluding whitespace).
- Inline policy on a user: 2 048 characters.
- Inline policy on a group: 5 120 characters.
- Inline policy on a role: 10 240 characters.
- Maximum managed policies attached to a single identity: 20 (default; can be increased to 50 by request).

These limits sound generous and are not. A real least-privilege policy for an engineer who works on three services in two regions is regularly over 3 000 characters. The size limits push policy *composition*: rather than one giant policy, you attach several smaller ones, each scoped to a service area. The principal's effective permissions are the union of the attached policies' allows.

---

## 3. Resource-based policies in depth

Resource-based policies attach to a resource and govern access to *that* resource. The resource is the policy's scope; the `Principal` field specifies who the policy applies to.

The AWS services that support resource-based policies are an enumerable list:

- **S3 buckets** — *bucket policy*. The most-misused resource-based policy in the cloud.
- **KMS keys** — *key policy*. Every KMS key has a key policy; you cannot grant access to a KMS key without going through its key policy. (You can also grant access via IAM, but only if the key policy delegates to IAM with the canonical `"Principal": {"AWS": "arn:aws:iam::<account>:root"}` statement.)
- **SQS queues** — *queue policy*.
- **SNS topics** — *topic policy*.
- **Lambda functions** — *function policy* (a.k.a. resource-based policy on the Lambda).
- **Secrets Manager secrets** — *secret policy*.
- **EFS file systems** — *file-system policy*.
- **VPC endpoints** — *endpoint policy*.
- **IAM roles** — the *trust policy*, which is a specialised resource-based policy controlling who can assume the role. (Yes, the role is both a principal — the identity assuming it — and a resource — the thing being assumed.)

The structural difference between an identity-based and a resource-based policy is the `Principal` field. Identity-based policies *omit* `Principal` because the principal is whatever the policy is attached to. Resource-based policies *require* `Principal` because the principal is variable.

A canonical KMS key policy:

```json
{
  "Version": "2012-10-17",
  "Id": "key-default-policy",
  "Statement": [
    {
      "Sid": "DelegateToAccountIAM",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowSpecificRoleToDecrypt",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/c6-week11-reader"
      },
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "*"
    }
  ]
}
```

Two statements. The first is the standard "delegate to account-level IAM" statement; without it, IAM policies on identities in the account cannot grant access to the key, because the key policy is the *anchor* of all key-access decisions. The second statement grants a specific role decrypt access, independent of whatever IAM policies are attached to that role.

The trust policy on a role is the same structure, scoped differently:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowGitHubActionsToAssume",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

This is the modern pattern for letting a GitHub Actions workflow assume a role in AWS without storing a long-lived access key in GitHub. The `Principal` is the OIDC identity provider GitHub publishes; the conditions restrict which repository and which branch can complete the assumption. The result: a CI job can call AWS APIs as the role, but only when running from the `main` branch of the named repository. The blast radius of a compromised CI environment is bounded by the role's permissions, *and* the role's trust policy refuses to issue credentials to any other origin.

The single most-disastrous misconfiguration of a trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

`"Principal": {"AWS": "*"}` on an `sts:AssumeRole` trust policy means *any AWS account in the world can assume this role*. Combined with administrative permissions on the role, this is a take-the-account credential exposed to the entire AWS user base. Prowler's check `iam_role_cross_account_readonlyaccess_policy` and several related checks catch this; the mini-project deliberately ships a stack with one of these and expects you to spot it before scanning.

---

## 4. When to choose identity-based vs resource-based

The choice between identity-based and resource-based for a given access requirement is not arbitrary. The pattern:

- **Use identity-based when the access is *about who can do what*, and the answer is the same across many resources.** A developer who can read every bucket in their team's account is an identity-based grant: one policy, one identity, many resources.

- **Use resource-based when the access is *about who can touch this resource*, and the answer is the same across many requesters.** A bucket that is shared with three other AWS accounts is a resource-based grant: one policy, one resource, many principals.

- **Use both when the access spans accounts.** Cross-account access in AWS requires both an identity-based policy in the *caller's* account and a resource-based policy on the *resource's* account. Either alone is insufficient — both must allow the action.

- **Use neither when ABAC fits.** If the access requirement is "principals tagged X can act on resources tagged X", ABAC is one policy instead of N identity attachments.

The most-common mistake is using a resource-based policy where an identity-based one would have been clearer. The S3 bucket policy is the worst offender: engineers reach for the bucket policy because the AWS console makes it discoverable, when the cleaner solution is to grant the right identities access via their own policies. The bucket policy then needs only to *deny* anonymous access and to require TLS — the two invariants that are properties of the resource itself.

---

## 5. ABAC in production

Lecture 1 introduced ABAC with the canonical EC2 example. This section addresses what ABAC looks like at the scale of a real account.

The core ABAC pattern is: tag everything, write one policy per action class that conditions on tag matching. Concretely:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ABACAdminOnMatchingTeam",
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "rds:*",
        "elasticloadbalancing:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Team": "${aws:PrincipalTag/Team}"
        }
      }
    },
    {
      "Sid": "ABACTaggingDiscipline",
      "Effect": "Deny",
      "Action": [
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "rds:AddTagsToResource",
        "rds:RemoveTagsFromResource"
      ],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringNotEquals": {
          "aws:TagKeys": ["Team", "Environment", "Project"]
        }
      }
    }
  ]
}
```

The first statement is the ABAC grant. The second statement enforces *tagging discipline*: principals are denied from creating or deleting tags on the three keys that drive ABAC decisions. Without this guard, a malicious or careless principal could retag a resource into their team and gain access; with the guard, tag changes on critical keys are blocked.

ABAC's operational properties:

- **Authoring effort is constant** in the number of teams. Adding a new team means tagging the team's people and the team's resources with the new `Team` value. No policy edits.
- **Audit effort is concentrated.** Instead of auditing N×M attachments, you audit the tagging discipline (are resources correctly tagged?) and the policy (is the condition correct?).
- **The blast radius of a tagging error is large.** If a production database accidentally gets tagged `Team=Hackathon`, every hackathon-team principal can now drop it. Mitigations: SCPs that deny tag changes on production resources outside a change-management workflow; CloudTrail alerts on tag changes; periodic Prowler scans for un-tagged resources.

GCP's equivalent is *IAM conditions with CEL on resource attributes*. The syntax is different; the architecture is the same:

```json
{
  "role": "roles/compute.admin",
  "members": ["group:apollo-eng@example.com"],
  "condition": {
    "title": "Apollo resources only",
    "expression": "'apollo' in resource.tags || resource.name.startsWith('projects/apollo-')"
  }
}
```

Azure's equivalent is *ABAC conditions on role assignments*, in preview / GA as of 2026 depending on service. Azure storage was the first service to support ABAC conditions on role assignments; the syntax is the Azure ABAC condition language (a subset of the Azure Policy language). Cite https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-overview.

NIST SP 800-162 is the conceptual reference for ABAC across vendors; pages 1-25 cover the architectural framing without privileging any one cloud's syntax.

---

## 6. Service Control Policies

Service Control Policies sit at the top of the policy stack in AWS Organizations. An SCP applies to an AWS account (or to an Organizational Unit — OU — containing multiple accounts) and defines the *maximum* permissions any principal in the targeted accounts can have. SCPs are *guardrails*, not grants. An SCP cannot give a principal a permission; an SCP can only take away (or fail to allow) permissions that the principal's identity-based and resource-based policies would otherwise grant.

A canonical SCP:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "support:*",
        "sts:*",
        "cloudfront:*",
        "route53:*",
        "waf:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    }
  ]
}
```

Read this carefully. The `NotAction` list contains actions that are global (no region) — IAM, Organizations, Support, STS, CloudFront, Route53, WAF. The statement says: deny every action *other than* the ones in `NotAction`, when the requested region is *not* `us-east-1` or `us-west-2`. The effect: any principal in any account this SCP applies to is locked into operating in `us-east-1` and `us-west-2`. They cannot accidentally provision in `eu-central-1` because they forgot to set the region in their CLI profile.

The pattern is one of the most-deployed defensive SCPs in real AWS organisations. The reason: regional sprawl is a routine cost-and-audit problem, and an SCP is the only mechanism that prevents it cheaply.

Other canonical SCPs (the ones the mini-project's Exercise 4 reproduces):

```json
{
  "Sid": "DenyDisableCloudTrail",
  "Effect": "Deny",
  "Action": [
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors"
  ],
  "Resource": "*"
}
```

Deny disabling CloudTrail at all. CloudTrail is the cloud's audit log; an attacker who has compromised the account often *starts* by trying to disable CloudTrail so subsequent actions go unrecorded. An SCP that denies these actions even for the account's administrators is the textbook last-line-of-defence. The break-glass identity at the management-account level is the only path to legitimate CloudTrail changes.

```json
{
  "Sid": "DenyIAMUserCreation",
  "Effect": "Deny",
  "Action": [
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile"
  ],
  "Resource": "*"
}
```

Deny the creation of IAM users. In organisations that use AWS IAM Identity Center (SSO), IAM users are obsolete; an SCP that forbids them prevents drift.

```json
{
  "Sid": "DenyPublicS3",
  "Effect": "Deny",
  "Action": [
    "s3:PutBucketPublicAccessBlock"
  ],
  "Resource": "*",
  "Condition": {
    "Bool": {"s3:PublicAccessBlockConfiguration.RestrictPublicBuckets": "false"}
  }
}
```

Deny disabling the S3 BlockPublicAccess configuration on any bucket. AWS introduced BlockPublicAccess in 2018 specifically because the bucket-policy misconfiguration class was so frequent; an SCP that keeps BlockPublicAccess on guarantees no bucket in the account can be made public, regardless of what the bucket policy says.

The SCP semantics are *Allow-list or Deny-list*:

- **Deny-list SCPs** (the most common) start from "allow everything" and subtract specific actions. The default SCP attached to every account is `FullAWSAccess` (an Allow on `*:*`), and deny-list SCPs subtract from it.
- **Allow-list SCPs** start from "allow nothing" and add back specific actions. Useful for environments with tight scope (e.g., a sandbox OU that should only be able to use a handful of services).

SCPs do not apply to the management account. The management account is the root of the organisation tree and is — by design — outside the SCP enforcement scope. This is one reason serious organisations keep the management account empty: no workloads, no roles, no resources, just the Organisations service itself. Compromise of the management account is fatal; you minimise its surface.

---

## 7. SCP equivalents in GCP and Azure

**GCP Organisation Policies** are the GCP equivalent. They are *constraint-based* — instead of writing a JSON policy that denies specific actions, you set a *boolean* constraint that the GCP control plane enforces. Examples:

- `iam.disableServiceAccountKeyCreation` = `enforced` → no service-account keys can be created anywhere in the Organisation.
- `compute.requireOsLogin` = `enforced` → every Compute Engine VM must require OS Login.
- `storage.uniformBucketLevelAccess` = `enforced` → no GCS bucket can use per-object ACLs.
- `iam.allowedPolicyMemberDomains` = `[example.com]` → IAM bindings can only reference principals from `example.com`.

The full constraint catalogue at https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints is ~100 constraints, each named, each documented. Constraints can be set at the Organisation, Folder, or Project level, with the most-restrictive ancestor's setting winning.

**Azure Policy** is the Azure equivalent and is the most-flexible of the three. Azure Policy definitions are JSON documents with a *rule* (the predicate) and an *effect* (`audit`, `deny`, `append`, `modify`, `auditIfNotExists`, `deployIfNotExists`, `disabled`). A canonical Azure Policy:

```json
{
  "properties": {
    "displayName": "Deny storage accounts with public network access",
    "policyType": "Custom",
    "mode": "All",
    "policyRule": {
      "if": {
        "allOf": [
          {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
          {"field": "Microsoft.Storage/storageAccounts/publicNetworkAccess", "equals": "Enabled"}
        ]
      },
      "then": {"effect": "deny"}
    }
  }
}
```

Read: if the resource is a storage account and its `publicNetworkAccess` property is `Enabled`, deny the deployment. The effect, applied at the Management Group level, prevents any subscription from ever provisioning a public storage account.

Azure Policy has more expressive power than SCPs (it can `modify` resources at create time, not just `deny` them; it can run remediations against existing non-compliant resources) but it also has more complexity. Learning Azure Policy properly is its own week.

---

## 8. Policy evaluation across the four kinds

When a request arrives, every applicable policy of every kind is in scope:

- The SCP (or org-policy or Azure-policy) for the account / OU / project / management-group containing the principal.
- The identity-based policies attached to the principal (or to groups the principal is in, or to the role the principal is assuming).
- The permissions boundary on the principal, if any.
- The session policy on the role-session, if any.
- The resource-based policy on the resource, if any.
- The ABAC conditions evaluated against the request's tag context.

A *yes* requires every layer to permit the action. A *no* requires only one layer to deny it. The architectural consequence: layers are *not* independent. An overly-permissive identity-based policy can still be neutralised by a restrictive SCP. A missing resource-based policy can still be sufficient if the resource is in the same account as the principal and the identity-based policy grants the action. A typo in any of the layers can break access in non-obvious ways.

The mental discipline: when a request fails, the answer is almost never "the policy was wrong". The answer is almost always "the *interaction* between two policies was wrong". The standard troubleshooting sequence:

1. Run the action with `aws sts get-caller-identity` first to confirm the credentials are what you think they are.
2. Use the IAM **policy simulator** (https://policysim.aws.amazon.com/) to evaluate the proposed action against the principal's policies. The simulator covers identity-based and resource-based policies but not SCPs perfectly; it is a starting point, not the final answer.
3. Run the action with `--debug` on the CLI; the failure message often names the specific policy or the specific SCP that denied the call.
4. Check CloudTrail. CloudTrail logs every API call, including the failed ones, with the `errorCode` and `errorMessage` fields populated. The error often identifies the policy layer responsible.

---

## 9. Practical policy authoring

The pattern that scales:

1. **Start from a known-good policy.** AWS publishes managed policies that work as starting points for common cases. `ReadOnlyAccess` is the most-frequent starting point; copy it into a customer-managed policy, then narrow.
2. **Narrow on resource first, action second.** Resources are easier to specify precisely than actions. A policy that allows `s3:*` on one bucket is a smaller surface than a policy that allows `s3:GetObject` on every bucket in the account.
3. **Add conditions as the last narrowing step.** Conditions are where most policy bugs live; add them only when the resource and action are already locked down.
4. **Test in a sandbox.** Create a test IAM user (or test role) with only the policy in question; verify it can do what it should and cannot do what it should not.
5. **Run Prowler.** Prowler's checks include policy-quality checks: overly-permissive admin policies, wildcard actions on sensitive APIs, missing MFA conditions on administrative roles.
6. **Commit the policy to Terraform.** Hand-edited policies decay. Terraform-managed policies are reviewable, diff-able, and revertable.

The pattern that does not scale and that you will see in real accounts:

1. Engineer needs to do something; gets a `403`.
2. Engineer adds `AdministratorAccess` to "fix" the permissions error.
3. Action succeeds; engineer moves on.
4. The "temporary" `AdministratorAccess` attachment persists for months.
5. The principal's access key leaks; the entire account is compromised.

This is the failure mode SCPs exist to *partially* prevent — an SCP that denies the principal from receiving `AdministratorAccess` outside an explicit allow-list of accounts will refuse to let step 2 succeed. But SCPs are not a substitute for least-privilege hygiene; they are a backstop. The hygiene is the work.

---

## 10. Where this leaves you

Lecture 1 gave you the vocabulary of IAM. Lecture 2 gave you the four kinds of policy and the discipline of choosing between them. Lecture 3 hands you the tools that find the gaps.

The thread to hold: every misconfiguration the scanners find is the absence of one of the patterns in this lecture. Public S3 buckets are missing the bucket-policy denial and missing the SCP that would have caught it. Wildcard trust policies are misconfigured trust policies. Unused IAM users with active access keys are identity hygiene the SCP could have prevented. The scanners are mechanical readers of the same policy language; the design discipline is yours.

Next: `lecture-notes/03-misconfig-scanning-prowler-checkov-scoutsuite.md`.
