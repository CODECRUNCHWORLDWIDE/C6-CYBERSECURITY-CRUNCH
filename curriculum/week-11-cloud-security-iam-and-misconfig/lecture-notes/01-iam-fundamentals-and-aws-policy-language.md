# Lecture 1 — IAM Fundamentals and the AWS Policy Language

> *Every cloud-API call passes through an authorisation check. The check answers a single question: is this principal allowed to perform this action on this resource under these conditions? This lecture is about how that question is asked, how it is answered, and the JSON document that encodes the answer.*

---

## 1. What IAM actually is

Cloud IAM — **Identity and Access Management** — is the control plane's authorisation layer. It sits between the API endpoint and the business logic of every service the cloud exposes. Every call to `s3:PutObject`, every `ec2:RunInstances`, every `kms:Decrypt` first goes through IAM. IAM either says yes (and the call proceeds) or it says no (and the call returns a `403 AccessDenied` before the service ever runs).

The thing to internalise early is that IAM is *not* network security. A packet on the wire never reaches IAM. IAM only operates after the packet has been parsed, the request has been authenticated, and the API call has been identified. By the time IAM is asked whether the call is authorised, the cloud already knows *who* the caller is (because authentication has succeeded) and *what* they want to do (because the request has been parsed). IAM's job is the *what they are allowed to do* layer, and only that layer.

This matters because every cloud breach you read about is either an authentication failure or an authorisation failure or — usually — both. Authentication failures are when a credential leaks: a developer's access key gets committed to a public GitHub repository, a stolen laptop has cached SSO tokens, a phishing email tricks an administrator into pasting their password into a fake console. Authorisation failures are when an authenticated principal has more permissions than they need: the developer's access key did not need `iam:*`, the stolen laptop did not need permanent administrative credentials, the administrator did not need to be a long-standing administrator at all. The first defence is auth; the second defence is least privilege. This week is about the second.

```
+-----------------+        +----------------+        +----------------+
|   API caller    | -----> |   Cloud API    | -----> |   Service      |
| (user or role)  |        |   endpoint     |        |   (S3, EC2...) |
+-----------------+        +----------------+        +----------------+
                                   |
                                   v
                          +-----------------+
                          |       IAM       |
                          |  (authorise)    |
                          +-----------------+
                                   |
                          Allow / Deny / Implicit Deny
```

That diagram is approximately correct for every public cloud. AWS, GCP, Azure, OCI, Aliyun: same shape, different vocabulary. The vocabulary is what makes the documentation feel incompatible. The model underneath is the same.

---

## 2. The four conceptual ingredients

Every IAM decision is a function of four inputs. Memorise them — every page of the AWS, GCP, and Azure documentation is a variation on these four:

- **Subject** (also called *principal*, *identity*, *caller*). The entity making the request. A human user. A service account. An automated agent. A role-session (a short-lived credential issued by an STS-style service). The control plane *authenticated* this entity before IAM ever saw the request; IAM's job is not to verify identity, only to decide what an already-verified identity may do.

- **Resource**. The thing being acted on. An S3 bucket. A particular object inside an S3 bucket. An EC2 instance. A KMS key. A GCP Pub/Sub topic. An Azure Key Vault. The resource has an *identifier* — in AWS the **Amazon Resource Name (ARN)** — that uniquely names it within the account.

- **Action**. The API call. `s3:GetObject`, `s3:PutObject`, `s3:DeleteBucket`. `compute.instances.delete` in GCP. `Microsoft.Storage/storageAccounts/read` in Azure. Each cloud has its own naming convention; what they share is that every API call is named, and IAM decisions are made action-by-action.

- **Condition** (also called *context*, *predicate*). The circumstances of the call. The source IP address. The time of day. Whether multi-factor authentication was used in this session. The tag values on the principal making the call. The tag values on the resource being acted on. Conditions are how IAM gets *expressive* — they let you say "allow this action, but only if X is true at the moment the call is made".

The IAM decision function is, in pseudo-code:

```
def decide(subject, resource, action, condition) -> Allow | Deny:
    applicable_policies = policies_attached_to(subject, resource)
    if any_policy_explicitly_denies(applicable_policies, subject, resource, action, condition):
        return Deny
    if any_policy_explicitly_allows(applicable_policies, subject, resource, action, condition):
        return Allow
    return Deny   # implicit deny is the default
```

That is approximately the AWS policy-evaluation algorithm, simplified. The exact algorithm adds permission boundaries and session policies as intermediate ceilings, but the *shape* of the decision is the same: an explicit deny anywhere is fatal; otherwise, an explicit allow lets the action through; otherwise, the action is denied because there is no policy permitting it.

The default-deny stance is non-negotiable. Every cloud worth using defaults to deny. A principal with *zero* policies attached can do *nothing* in the account. The only way to do anything is to attach at least one policy that explicitly allows the action. This is why the first week a student spends in AWS feels frustrating: they create an IAM user, they try to do something, and AWS says no. The fix is not to give the user `AdministratorAccess`; the fix is to give the user *exactly* the permissions they need.

---

## 3. Anatomy of an AWS IAM policy

An AWS IAM policy is a JSON document. The grammar is small and the document is human-readable. A trivial policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadFromOneBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::example-org-reports",
        "arn:aws:s3:::example-org-reports/*"
      ]
    }
  ]
}
```

Read this top-to-bottom. The keys:

- **`Version`**. The policy-language version. Always `"2012-10-17"` for new policies. AWS will not deprecate this for the foreseeable future. The value is a string, not a number; the day someone strips the quotes and submits `2012-10-17` as a date, the policy fails to parse.

- **`Statement`**. An array. Each element of the array is a statement. A statement is a single rule. Statements are evaluated independently; the overall policy is the *union* of its statements' verdicts (with explicit deny winning). A policy can have one statement or hundreds; AWS imposes a 6 144-character limit on managed policies (excluding whitespace), which in practice means policies stay small and the complexity moves into *multiple* policies attached to a principal.

- **`Sid`**. Statement Identifier. Optional. Free-form string for human use. AWS does not interpret it; the only constraint is that within a single policy each `Sid` must be unique. Always provide one — when a Prowler report says "the statement `AllowReadFromOneBucket` is overly permissive", you want the `Sid` to be searchable.

- **`Effect`**. Either `"Allow"` or `"Deny"`. The two-valued verdict.

- **`Action`**. The API actions the statement applies to. A string or an array of strings. Each entry is of the form `<service>:<action>`. Wildcards are permitted: `s3:Get*` matches every action that starts with "Get" in S3; `s3:*` matches every action in S3; `*` matches every action in every service. The wildcards are the most-misused feature of the policy language; treat them as a code smell.

- **`Resource`**. The resources the statement applies to. A string or an array of strings, each an ARN. Wildcards within the ARN structure are permitted. `arn:aws:s3:::example-org-reports/*` matches every object in the bucket; `arn:aws:s3:::example-org-*` matches every bucket whose name starts with `example-org-`. The single `*` value matches every resource in every service in the account — the same code smell as `Action: "*"`.

- **`Condition`** (optional). A JSON object whose top-level keys are *condition operators* (e.g., `StringEquals`, `IpAddress`, `Bool`, `DateLessThan`) and whose nested keys are *condition context keys* (e.g., `aws:SourceIp`, `aws:MultiFactorAuthPresent`, `aws:PrincipalTag/Project`). The condition is a predicate that must be true for the statement to apply. We will spend most of section 5 on this.

- **`Principal`** (optional, only legal in resource-based policies). The identity the statement applies to. Section 8 covers this.

- **`NotAction`**, **`NotResource`**, **`NotPrincipal`** (optional). The complements of `Action`, `Resource`, `Principal`. Treat all three as footguns; the legitimate use case for each is narrow.

The **Amazon Resource Name (ARN)** is the universal identifier:

```
arn:aws:<service>:<region>:<account-id>:<resource-type>/<resource-id>
```

Examples:

- `arn:aws:s3:::my-bucket` — an S3 bucket. S3 is global (no region), and S3 ARNs omit the account ID by convention.
- `arn:aws:s3:::my-bucket/path/to/object.txt` — an object inside an S3 bucket.
- `arn:aws:iam::123456789012:user/alice` — an IAM user.
- `arn:aws:iam::123456789012:role/c6-week11-deployer` — an IAM role.
- `arn:aws:ec2:us-east-1:123456789012:instance/i-0abc1234` — an EC2 instance.
- `arn:aws:kms:us-east-1:123456789012:key/12345678-90ab-cdef-1234-567890abcdef` — a KMS key.

Every IAM policy you read this week will be parsed in your head into these pieces. Practice on the first exercise until you can read an ARN at a glance.

---

## 4. The policy evaluation algorithm

The exact algorithm AWS runs when it evaluates a request, paraphrased from the canonical reference at https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html:

1. **Authenticate the request.** Decode the signature. Look up the principal. (Not IAM's job — happens before IAM.)
2. **Gather the applicable policies.** All identity-based policies attached to the principal; all resource-based policies on the resource; all SCPs that cover the principal's account; the principal's permissions boundary, if any; any session policy attached to the role-session.
3. **Evaluate SCPs.** If any SCP applicable to the principal's account denies the action — explicit deny *or* the action is not in any allow statement of the SCP — the request is denied. SCPs are the outer ceiling.
4. **Evaluate the resource-based policy.** If the resource has a resource-based policy, evaluate it. An explicit `Allow` here can be sufficient on its own, depending on the service and on cross-account considerations.
5. **Evaluate the identity-based policies.** Walk through every policy attached to the principal. Collect every `Allow` and every `Deny`.
6. **Evaluate the permissions boundary.** If the principal has a permissions boundary, the boundary further constrains the union of the identity-based allows. The effective permissions are the *intersection* of the identity-based allows and the boundary's allows.
7. **Evaluate the session policy.** If the principal is a role-session and the session was created with an inline session policy, that policy further constrains the effective permissions.
8. **Apply explicit denies.** Any explicit `Deny` from any layer trumps every `Allow`. Period.
9. **Decide.** If at least one applicable `Allow` survives every ceiling and no explicit `Deny` matched, the action is permitted. Otherwise, the action is denied.

The two takeaways:

- **Explicit deny is fatal.** A single `Deny` statement at any layer denies the action. SCPs use this aggressively (deny all actions outside approved regions, deny disabling CloudTrail).
- **Allow requires a chain of yes.** For the action to succeed, the SCP must allow it, an identity-based or resource-based policy must allow it, the permissions boundary (if present) must allow it, and the session policy (if present) must allow it. Any "no" or "silent" at any layer ends the request.

The mental model the AWS documentation team draws is a nested set of envelopes. The outermost envelope is the SCP (the maximum permissions the account is *capable of* granting). Inside that, the permissions boundary (the maximum permissions this principal is *capable of* receiving). Inside that, the identity-based and resource-based policies (the permissions this principal is *actually* granted). Inside that, the session policy (the permissions this particular session is using). For an action to succeed, it has to be allowed in *every* envelope.

---

## 5. Conditions

The `Condition` block is what turns IAM from "this principal can do this action on this resource" into "this principal can do this action on this resource *when X is true*". Conditions are how IAM gets expressive enough to encode real policies.

A condition block is a JSON object whose top-level keys are *condition operators* and whose nested keys are *condition context keys*:

```json
"Condition": {
  "Bool": {
    "aws:MultiFactorAuthPresent": "true"
  },
  "IpAddress": {
    "aws:SourceIp": ["203.0.113.0/24", "198.51.100.0/24"]
  },
  "DateLessThan": {
    "aws:CurrentTime": "2026-12-31T23:59:59Z"
  }
}
```

The semantics: every operator block must be satisfied; within an operator block with an array value, the predicate is "at least one of the array entries matches" (`StringEquals` is logical-OR within an array). The overall condition is satisfied only when every operator block is satisfied.

The operators worth knowing now (the full list is in the canonical reference; the frequently-used subset is small):

- **`StringEquals`**, **`StringNotEquals`**, **`StringLike`** (with wildcards), **`StringNotLike`**.
- **`NumericEquals`**, **`NumericLessThan`**, **`NumericGreaterThan`**, etc.
- **`DateEquals`**, **`DateLessThan`**, **`DateGreaterThan`**, etc.
- **`Bool`** for boolean condition keys (the value is the literal string `"true"` or `"false"`).
- **`IpAddress`**, **`NotIpAddress`** for source-IP gating with CIDR notation.
- **`ArnEquals`**, **`ArnLike`** for ARN comparisons.
- **`Null`** for testing whether a condition key is present at all (`"Null": {"aws:MultiFactorAuthPresent": "false"}` is the canonical "MFA was used" check, because `aws:MultiFactorAuthPresent` is only set when the session had an MFA challenge).

The condition context keys split into:

- **Global keys**, prefixed `aws:`. Available for every service. Examples: `aws:SourceIp`, `aws:CurrentTime`, `aws:MultiFactorAuthPresent`, `aws:PrincipalTag/<TagName>`, `aws:ResourceTag/<TagName>`, `aws:RequestTag/<TagName>`, `aws:SecureTransport`.
- **Service-specific keys**, prefixed `<service>:`. Examples: `s3:x-amz-acl` (the ACL header on an S3 PUT), `ec2:InstanceType`, `iam:PassedToService`.

The condition mechanic is what makes ABAC possible (section 7), what makes MFA-enforced policies possible, and what makes time-bounded access possible. It is also what makes policies subtle. Take this:

```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "Bool": {"aws:MultiFactorAuthPresent": "false"}
  }
}
```

What does this say? "Deny every action on every resource when MFA is not present in the session." Attach it to an administrator role, and the role is administrative *only when the session has MFA*. Without MFA, the administrator can do nothing. The policy is one of the most-deployed defensive policies in AWS — and the one most-likely to be misread by an engineer who has never seen it before.

---

## 6. Identity-based vs resource-based policies

AWS distinguishes two attachment points for policies. The mechanics overlap; the conceptual difference is important.

- **Identity-based policies** attach to an IAM identity — a user, a group, or a role. They answer the question "what can *this principal* do?" They cannot have a `Principal` field because the principal is implicit (it is whatever the policy is attached to). Identity-based policies come in two flavours: *managed policies* (named, reusable, attached to many principals) and *inline policies* (embedded into a single principal's definition, lifecycle-bound to it). Managed policies are the better choice for almost every case.

- **Resource-based policies** attach to a resource — an S3 bucket, a KMS key, an SQS queue, a Lambda function, a Secrets Manager secret. They answer the question "who can do what on *this thing*?" They include a `Principal` field that specifies which identities the policy applies to. Resource-based policies enable cross-account access (principals from one account can be named in a resource policy in another account) and they enable anonymous access (an S3 bucket policy with `"Principal": "*"` makes the bucket public — the most-misconfigured policy in the cloud).

A canonical resource-based policy, the S3 bucket policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadOnlyFromCorpAccount",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::987654321098:root"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::corp-shared-bucket",
        "arn:aws:s3:::corp-shared-bucket/*"
      ],
      "Condition": {
        "Bool": {"aws:SecureTransport": "true"}
      }
    }
  ]
}
```

The `Principal` field names account `987654321098`'s root user; AWS treats `arn:...:root` as "any principal in that account that has been granted, by its own account's IAM, permission to act on this resource". The condition enforces TLS — no plaintext reads.

The S3 bucket policy is also the source of the worst-known misconfiguration:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

`"Principal": "*"` means *any caller on the public internet*. Combine with `s3:GetObject` and an object key, and the bucket is anonymously readable. This is the policy that has exposed terabytes of customer data in dozens of public incidents. The week's mini-project starter Terraform stack *deliberately* deploys a bucket with this policy; the student's job is to spot it, scan-detect it, and remediate it.

---

## 7. Attribute-based access control (ABAC)

The N×M problem. An organisation has *N* environments (dev, staging, prod, plus per-project subsets). An organisation has *M* engineers, each with permissions to some subset of those environments. With identity-based policies, the policy count grows as O(N×M): every (engineer, environment) pair needs a policy or a group membership. With ten environments and 200 engineers, the management surface is 2 000 attachments. Most of them are wrong.

ABAC replaces the N×M attachment table with a small number of policies that make decisions on *tags*. The principal carries tags (`Project=Apollo`, `Environment=Staging`). The resource carries tags (`Project=Apollo`, `Environment=Staging`). The policy says "allow the action when the principal's `Project` tag equals the resource's `Project` tag". One policy. Hundreds of resources. Hundreds of principals. The same policy authorises every (matching tag) pair.

The canonical AWS ABAC pattern:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOpsOnMatchingProject",
      "Effect": "Allow",
      "Action": [
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:RebootInstances"
      ],
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalTag/Project": "${aws:ResourceTag/Project}"
        }
      }
    }
  ]
}
```

Read the condition carefully. `aws:PrincipalTag/Project` is the value of the `Project` tag on the principal making the call. `${aws:ResourceTag/Project}` is *the value of the `Project` tag on the resource being acted on*, interpolated into the condition value. The `StringEquals` then says: the principal's `Project` tag must equal the resource's `Project` tag. If a principal tagged `Project=Apollo` tries to start an instance tagged `Project=Apollo`, the action is allowed. If the same principal tries to start an instance tagged `Project=Beacon`, the action is denied.

ABAC scales. Adding a new project means tagging the new resources and the new principals; no policy changes. Adding a new engineer means tagging them; no policy changes. The policies stay small. The audit surface stays manageable.

The trade-off is *tagging discipline*. If a resource is provisioned without the `Project` tag, the ABAC policy will not apply, and the resource will be silently inaccessible to the principals who should be able to manage it. The remediation is to enforce tagging at provisioning time — via an SCP that denies the creation of resources without required tags, or via Terraform modules that always include the tag block. The canonical AWS ABAC tutorial walks through the full pattern; cite https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_attribute-based-access-control.html.

NIST SP 800-162 is the conceptual reference for ABAC, predating cloud and written about access-control architecture in general. Read pages 1-25 if you want the architectural framing; the AWS tutorial is enough for the implementation.

---

## 8. GCP IAM sidebar

GCP IAM rearranges the same primitives.

- **Resource hierarchy**: Organisation > Folder > Project > Resource. The hierarchy is a tree; bindings at any level are *inherited* by descendants.
- **Roles**: a collection of permissions. Predefined (`roles/storage.objectViewer`, `roles/compute.admin`, `roles/iam.serviceAccountUser` — there are hundreds) or custom (you author them in YAML / JSON / Terraform).
- **Principals** (called *members* in older docs): Google accounts (`user:alice@example.com`), groups (`group:eng@example.com`), service accounts (`serviceAccount:my-app@my-project.iam.gserviceaccount.com`), domains, plus the special `allUsers` (anonymous) and `allAuthenticatedUsers` (any Google identity).
- **Bindings**: a (role, principal, resource) triple. Apply at the appropriate hierarchy level.
- **Conditions**: optional, attached to bindings. Use Common Expression Language (CEL) as the predicate language. Roughly equivalent in expressiveness to AWS condition blocks, syntactically very different.

A GCP IAM binding in JSON:

```json
{
  "policy": {
    "bindings": [
      {
        "role": "roles/storage.objectViewer",
        "members": ["group:reports-readers@example.com"],
        "condition": {
          "title": "Only the reports bucket",
          "expression": "resource.name == 'projects/_/buckets/example-reports'"
        }
      }
    ]
  }
}
```

The shape is different from AWS — GCP packages everything into a single `bindings` array at the resource level — but the four ingredients are there: subject (`members`), resource (the binding's attachment point and the optional CEL `resource.name`), action (the permissions inside `role`), condition (the CEL `expression`).

**GCP Organisation Policies** are the GCP equivalent of AWS SCPs. They are *constraints* applied at the Organisation, Folder, or Project level that limit what the IAM bindings at that level can do. Examples: `iam.disableServiceAccountKeyCreation` (forbid the creation of long-lived service-account keys), `compute.requireOsLogin` (force OS Login on every VM), `storage.uniformBucketLevelAccess` (require uniform — i.e., no per-object ACLs — on every GCS bucket), `iam.allowedPolicyMemberDomains` (restrict the email domains that can appear in any IAM binding). The full constraint catalogue is at https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints.

The canonical GCP IAM reference is https://cloud.google.com/iam/docs.

---

## 9. Azure RBAC sidebar

Azure rearranges the same primitives differently again.

- **Scope**: a resource ID prefix. Management Group > Subscription > Resource Group > Resource. A role assignment at any scope is inherited by descendants.
- **Role definitions**: JSON documents with `actions`, `notActions`, `dataActions`, `notDataActions`, `assignableScopes`. Built-in or custom. The built-in catalogue at https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles has hundreds of roles, each with a list of which API operations it permits.
- **Security principals** (Azure's term for IAM identities): users, groups, service principals (the Azure equivalent of service accounts), managed identities (the Azure equivalent of EC2 instance profiles).
- **Role assignments**: a (role definition, security principal, scope) triple.

A custom Azure role definition:

```json
{
  "Name": "C6 Week 11 Storage Reader",
  "Description": "Read-only access to blobs in scoped storage accounts.",
  "Actions": [
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/listKeys/action"
  ],
  "NotActions": [],
  "DataActions": [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
  ],
  "NotDataActions": [],
  "AssignableScopes": [
    "/subscriptions/00000000-0000-0000-0000-000000000000"
  ]
}
```

The shape is again different — Azure splits *control-plane* actions (`Actions`) from *data-plane* actions (`DataActions`), which has no AWS equivalent and is one of the structural pleasures of Azure RBAC.

**Azure Policy** is *separate* from Azure RBAC and provides the guardrail mechanism. Examples: `Audit storage accounts with public network access`, `Deny resources without a "costcenter" tag`, `Require HTTPS on all storage accounts`. Azure Policy effects (`audit`, `deny`, `append`, `modify`, `auditIfNotExists`, `deployIfNotExists`) are more flexible than AWS SCPs but also more numerous; learning Azure Policy is a course of its own. The canonical reference is https://learn.microsoft.com/en-us/azure/governance/policy/.

**Management Groups** are the Azure equivalent of AWS OUs — the hierarchical container scope above the subscription.

---

## 10. The principle of least privilege

The phrase comes from Saltzer and Schroeder's 1975 paper "The Protection of Information in Computer Systems", which enumerated eight design principles for secure systems. The third principle was *least privilege*: every program and every user of the system should operate using the least set of privileges necessary to complete the job. Fifty years on, the principle is the single most-cited piece of security architecture, and it is no easier to apply now than it was then.

Operationally, least privilege in cloud IAM means three things:

1. **Minimum actions.** A policy permits only the actions the principal actually performs. Not `s3:*` when the principal only reads. Not `Action: "*"` when the principal only manages EC2. The starting point is the smallest action set that lets the principal do its job, and you grow the set when something breaks — not the other way around.
2. **Minimum resources.** A policy permits only the resources the principal actually touches. Not `Resource: "*"` when the principal works on one bucket. Not the entire account's S3 namespace when one prefix is enough. The starting point is the most-specific ARN pattern that covers the principal's working set.
3. **Minimum conditions.** A policy applies only under the conditions the principal legitimately operates under. MFA-only for administrative actions. Source-IP-bound when the principal is a build robot whose IP is known. Time-bound when the access is a temporary engagement.

The hard part is the "grow the set when something breaks" loop. The cloud APIs do not, by default, tell you which permissions a principal *would have used* if granted them. AWS does provide tooling: **IAM Access Analyzer** (https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html) generates least-privilege policies from CloudTrail logs of a principal's past activity. Run a principal for a week with `ReadOnlyAccess` plus `IAM:PassRole`, observe what they actually called, and Access Analyzer will emit a policy that covers exactly that set.

Least privilege is not zero trust. Zero trust is an *architectural* posture in which there is no implicit trust based on network location, and every access decision is made fresh at request time. Least privilege is a *policy* property in which the permissions granted to a principal are the minimum needed. Zero trust depends on least privilege as a building block, but the two are not the same. Cite NIST SP 800-207 for zero trust and the AWS Well-Architected Framework Security Pillar for the operational guidance on least privilege.

---

## 11. Failure modes worth memorising

The cloud-misconfig literature has converged on a small set of patterns that account for the majority of public breaches. Each is worth memorising as a pattern your eye should catch when reading a policy:

- **`"Action": "*"` plus `"Resource": "*"` on a non-administrative role.** The role exists for one purpose; the policy says it can do everything. Common when an engineer copy-pasted `AdministratorAccess` to fix a permissions error and never narrowed it back down.
- **`"Principal": "*"` on a resource-based policy.** Anonymous access. Sometimes intentional (a public website's static assets) but almost always wrong. Every S3 bucket policy with this should have a corresponding `aws:SourceIp` or `aws:SourceVpc` condition narrowing the access; without it, the resource is publicly readable.
- **`"Principal": {"AWS": "*"}` on a role's trust policy.** Any AWS account in the world can assume the role. Combined with administrative permissions on the role itself, this is a take-the-account credential. The trust policy should always name a specific account or AWS service.
- **Missing MFA conditions on administrative policies.** An administrator's session that did not present MFA is functionally equivalent to a compromised access key. Modern policies condition admin actions on `aws:MultiFactorAuthPresent` being true.
- **Wildcards in conditions.** `aws:SourceIp` set to `0.0.0.0/0` is a no-op (the condition is always true). `aws:PrincipalTag/Project` matching `*` is a no-op (every tag value matches). Conditions that always evaluate to true are condition theatre; Prowler flags them.
- **Inline policies on shared resources.** Inline policies are invisible in the managed-policy listings. A misconfiguration in an inline policy can persist for years because nobody looks. Prefer managed policies; reserve inline for ephemeral or principal-bound permissions that should disappear with the principal.

Every one of these patterns appears in the mini-project's starter Terraform stack. Reading this lecture twice will not equip you to spot them all at first glance. The exercises and the mini-project will.

---

## 12. Where this leaves you

You now have a model of how IAM works, a working knowledge of the AWS policy language, the sidebar awareness of GCP IAM and Azure RBAC, the policy-evaluation algorithm in your head, and the principle of least privilege as your design star. Lecture 2 takes the four kinds of policy (identity-based, resource-based, ABAC, SCP) and digs deeper into when each is the right tool. Lecture 3 introduces the three scanners that find the gaps your hand-written policies leave behind.

The arc: by the end of Wednesday's lecture, the student should be able to read a Terraform stack, predict the scanner findings before running the scanners, and articulate the remediation in code rather than in clicks.

Next: `lecture-notes/02-identity-resource-abac-and-scps.md`.
