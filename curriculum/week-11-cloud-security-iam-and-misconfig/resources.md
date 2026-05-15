# Week 11 — Resources

Every link below is free and primary unless explicitly tagged otherwise. The "tagged paid" items appear because they are widely cited; nothing in the curriculum requires them.

---

## Primary references — AWS IAM

- **AWS IAM User Guide — the canonical reference.** https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html — maintained continuously by AWS, the User Guide is the authoritative source for IAM behaviour, policy syntax, evaluation logic, and the dozens of small interactions between IAM and other AWS services. Read at minimum the chapters "Identities", "Access management for AWS resources", "Policies and permissions in IAM", and "IAM JSON policy reference" before starting Exercise 1.

- **AWS IAM policy evaluation logic.** https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html — the single most important page in the entire IAM documentation. The page diagrams the evaluation order: explicit deny first, then service control policies, then resource-based policies, then identity-based policies, then permissions boundaries, then session policies. Read this page twice; the second time, sketch the flowchart on paper.

- **AWS IAM JSON policy reference.** https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html — the syntax bible. Includes the grammar for every element (`Version`, `Id`, `Statement`, `Sid`, `Effect`, `Principal`, `NotPrincipal`, `Action`, `NotAction`, `Resource`, `NotResource`, `Condition`) plus the catalogue of condition operators and global condition keys.

- **AWS IAM global condition context keys.** https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html — the keys that can appear inside a `Condition` block. The frequently-used ones: `aws:SourceIp`, `aws:MultiFactorAuthPresent`, `aws:PrincipalTag/<TagName>`, `aws:ResourceTag/<TagName>`, `aws:RequestTag/<TagName>`, `aws:CurrentTime`, `aws:SecureTransport`.

- **AWS Service Authorization Reference.** https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html — for every AWS service, the canonical list of actions, the resource types they apply to, and the service-specific condition keys. The reference Prowler's check authors cite when adding new checks.

- **AWS Organizations User Guide.** https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html — for SCPs, OUs, and the multi-account model. Read the chapters "Managing AWS Organizations policies" and "Service control policies".

- **AWS ABAC tutorial.** https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_attribute-based-access-control.html — a working ABAC example with all the tags, principals, and policies the pattern needs. The canonical AWS-published walkthrough for Exercise 3.

- **AWS Security Reference Architecture (SRA).** https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html — AWS's prescriptive guidance for multi-account security architecture. Free, ~150 pages, dense. The IAM design doc in the mini-project takes inspiration from this document.

---

## Primary references — GCP IAM

- **GCP IAM documentation — the canonical reference.** https://cloud.google.com/iam/docs — Google's official documentation for IAM. Read at minimum the "IAM overview", "Roles and permissions", "Policy syntax", and "Conditions overview" pages.

- **GCP IAM overview.** https://cloud.google.com/iam/docs/overview — the conceptual introduction. The 10-minute read that anchors the GCP sidebar in Lecture 1.

- **GCP IAM resource hierarchy.** https://cloud.google.com/iam/docs/resource-hierarchy-access-control — Organisation > Folder > Project > Resource, plus the inheritance rules.

- **GCP IAM conditions.** https://cloud.google.com/iam/docs/conditions-overview — GCP's equivalent of AWS condition blocks, with the Common Expression Language (CEL) as the predicate format.

- **GCP IAM custom roles.** https://cloud.google.com/iam/docs/creating-custom-roles — the mechanism for building project-specific roles from individual permissions.

- **GCP Organisation Policy Service.** https://cloud.google.com/resource-manager/docs/organization-policy/overview — GCP's equivalent of AWS SCPs. Constraint-based: `iam.disableServiceAccountKeyCreation`, `compute.requireOsLogin`, `storage.uniformBucketLevelAccess`, and dozens more.

- **Service accounts in GCP.** https://cloud.google.com/iam/docs/service-accounts — the IAM identity used by workloads. Includes the recommended-but-overlooked pattern of Workload Identity Federation for short-lived credentials.

---

## Primary references — Azure RBAC

- **Azure RBAC documentation — the canonical reference.** https://learn.microsoft.com/en-us/azure/role-based-access-control/ — Microsoft Learn's RBAC home. Read at minimum the "What is Azure RBAC?", "Built-in roles", "Custom roles", and "Role assignments" pages.

- **Azure RBAC role definitions.** https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions — the schema for a role definition (`actions`, `notActions`, `dataActions`, `notDataActions`, `assignableScopes`).

- **Azure built-in roles.** https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles — the catalogue. The frequently-cited ones: `Reader`, `Contributor`, `Owner`, `User Access Administrator`, `Storage Blob Data Reader`, `Key Vault Secrets User`.

- **Azure Policy documentation.** https://learn.microsoft.com/en-us/azure/governance/policy/ — distinct from RBAC; Azure Policy is the guardrail mechanism. Read "Overview", "Built-in policy definitions", and "Effects".

- **Azure Management Groups.** https://learn.microsoft.com/en-us/azure/governance/management-groups/overview — the hierarchical scope above subscription level. The Azure equivalent of AWS OUs.

- **Microsoft Entra ID (formerly Azure AD).** https://learn.microsoft.com/en-us/entra/identity/ — the identity service that backs Azure RBAC. Cited for sign-in conditional access, which is the closest Azure has to AWS condition keys.

---

## Primary references — Prowler

- **Prowler GitHub repository.** https://github.com/prowler-cloud/prowler — source code, issues, releases. The README is the install reference. Apache 2.0 licence. Maintained continuously by ProwlerPro plus an active open-source contributor base.

- **Prowler documentation.** https://docs.prowler.com/ — versioned, comprehensive, free. Read "Tutorials → AWS", "Tutorials → Azure", "Tutorials → GCP", and "Reference → Checks".

- **Prowler check inventory.** https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/ — the catalogue of AWS checks. Each check has an ID (e.g., `iam_no_root_access_key`), a CIS Benchmark mapping, a severity, and a remediation note.

- **Prowler compliance frameworks.** https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/compliance/ — Prowler can scope a scan to a compliance framework: CIS, GDPR, HIPAA, PCI-DSS, ISO 27001, SOC 2, NIST 800-53, FedRAMP, AWS FTR.

- **Prowler ASFF output.** https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/securityhub/ — Prowler's JSON-ASFF output integrates with AWS Security Hub. Useful even without Security Hub because ASFF is a stable schema; Exercise 5 parses ASFF output.

- **Prowler community Slack.** https://join.slack.com/t/prowler-workspace/ — the active project community.

---

## Primary references — Checkov

- **Checkov GitHub repository.** https://github.com/bridgecrewio/checkov — source code, issues, releases. Apache 2.0 licence. Maintained by Palo Alto Networks (Bridgecrew was acquired in 2021, kept open-source).

- **Checkov documentation.** https://www.checkov.io/ — the project's landing page and documentation. Read "Getting Started → Installing", "Concepts → Policies as code", and "Frameworks → Terraform".

- **Checkov check catalogue.** https://www.checkov.io/5.Policy%20Index/all.html — every check Checkov ships, with its ID, severity, and the remediation it recommends.

- **Checkov custom policies.** https://www.checkov.io/3.Custom%20Policies/Custom%20Policies%20Overview.html — extend Checkov with your own checks. Two syntaxes: YAML for simple attribute matches, Python for arbitrary logic.

- **Checkov CI/CD integration.** https://www.checkov.io/4.Integrations/GitHub%20Actions.html — the recommended deployment for the Exercise 6 workflow.

---

## Primary references — ScoutSuite

- **ScoutSuite GitHub repository.** https://github.com/nccgroup/ScoutSuite — source code, issues, releases. GPL-2.0 licence. Maintained by NCC Group, an information-security consultancy.

- **ScoutSuite wiki.** https://github.com/nccgroup/ScoutSuite/wiki — the documentation. Read "Setup", "Usage", and "Rules" before running the first scan.

- **ScoutSuite rule packs.** https://github.com/nccgroup/ScoutSuite/tree/master/ScoutSuite/providers/aws/rules — the AWS rule pack. JSON-formatted; each rule names the dotted-key path it inspects and the condition that triggers a finding.

- **ScoutSuite supported services.** https://github.com/nccgroup/ScoutSuite/wiki/Supported-Services — the matrix of provider × service × rule-count.

---

## Primary references — Terraform and OpenTofu

- **Terraform documentation.** https://developer.hashicorp.com/terraform/docs — the canonical reference for Terraform syntax, the HCL language, the state model, and the provider ecosystem. Terraform is BSL 1.1 since August 2023; the relevant sections of the docs still apply to OpenTofu.

- **AWS provider for Terraform.** https://registry.terraform.io/providers/hashicorp/aws/latest/docs — the resource and data-source catalogue. The mini-project's `main.tf` uses ~15 of these resources; the documentation page for each is linked inline in the file's comments.

- **OpenTofu documentation.** https://opentofu.org/docs/ — the MPL 2.0 fork of Terraform. Drop-in compatible for the mini-project; install instructions at https://opentofu.org/docs/intro/install/. Use whichever the student prefers.

- **Terraform IAM resources reference.** https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy — the resource the mini-project's IAM policies are authored as.

---

## CIS Benchmarks

- **CIS Benchmarks home.** https://www.cisecurity.org/cis-benchmarks/ — the Center for Internet Security's benchmark catalogue. Free PDF downloads after a name-and-email form. Updated continuously.

- **CIS Amazon Web Services Foundations Benchmark v3.0.0.** https://www.cisecurity.org/benchmark/amazon_web_services — the most-cited cloud-security baseline. ~100 controls organised into "Identity and Access Management", "Storage", "Logging", "Monitoring", and "Networking". Prowler's CIS profile maps directly to this benchmark.

- **CIS Google Cloud Platform Foundation Benchmark v3.0.0.** https://www.cisecurity.org/benchmark/google_cloud_computing_platform — the GCP equivalent. Smaller surface, broadly parallel structure.

- **CIS Microsoft Azure Foundations Benchmark v3.0.0.** https://www.cisecurity.org/benchmark/azure — the Azure equivalent.

- **CIS Kubernetes Benchmark v1.9.0.** https://www.cisecurity.org/benchmark/kubernetes — cited for the Exercise 6 Checkov scan, which includes Kubernetes manifest checks.

- **CIS Docker Benchmark v1.6.0.** https://www.cisecurity.org/benchmark/docker — cited in Lecture 3 for the broader picture of static-config scanning.

---

## NIST standards

- **NIST SP 800-207, "Zero Trust Architecture".** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf — the canonical free description of zero-trust architecture. Pages 1–20 cover the seven tenets; the rest is implementation guidance. The framing source for the "every API call is authenticated and authorised" stance.

- **NIST SP 800-204, "Security Strategies for Microservices-based Application Systems".** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf — pre-zero-trust but useful for the service-identity discussion.

- **NIST SP 800-204A, "Building Secure Microservices-based Applications Using Service-Mesh Architecture".** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf — extension of 800-204; cited for service-to-service identity.

- **NIST SP 800-53 Rev. 5, "Security and Privacy Controls for Information Systems and Organizations".** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — the catalogue of controls that AWS, GCP, and Azure compliance attestations map to. The Access Control (AC) family is the relevant one for IAM.

- **NIST SP 800-162, "Guide to Attribute Based Access Control (ABAC) Definition and Considerations".** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf — the canonical free reference for the ABAC model. Pre-cloud (2014) but architecturally still correct.

---

## Supplementary references

- **AWS Well-Architected Framework — Security Pillar.** https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html — AWS's prescriptive security guidance. Free; ~80 pages. Read "Identity and Access Management" and "Detection".

- **AWS Customer Compliance Center.** https://aws.amazon.com/compliance/ — AWS's published mappings of its services to compliance frameworks. Useful when arguing scope with an auditor.

- **GCP architecture framework — Security.** https://cloud.google.com/architecture/framework/security — GCP's prescriptive security guidance. Mirrors the AWS Well-Architected Security Pillar in structure.

- **Microsoft Cloud Adoption Framework — Security.** https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/secure/ — Azure's equivalent.

- **Cloud Security Alliance, "Top Threats to Cloud Computing — Pandemic Eleven".** https://cloudsecurityalliance.org/research/topics/cloud-threats — CSA's periodically-updated catalogue of cloud-specific threat scenarios. Free PDF after a form.

- **Verizon Data Breach Investigations Report (DBIR).** https://www.verizon.com/business/resources/reports/dbir/ — annual; free PDF. The DBIR is where the "misconfiguration is the dominant cloud-breach root cause" claim originates.

- **OWASP Cloud-Native Application Security Top 10.** https://owasp.org/www-project-cloud-native-application-security-top-10/ — OWASP's cloud-specific top-10 list. Less mature than the original OWASP Top 10 but useful for framing.

- **Capital One breach disclosure (2019).** https://www.capitalone.com/about/newsroom/cyber-incident/ — the original disclosure. Cited as the worked example of an SSRF-into-IAM-credentials misconfiguration.

- **AWS post-mortem of the Capital One incident pattern.** https://aws.amazon.com/blogs/security/how-to-prevent-uncontrolled-costs-from-changes-in-iam-permissions/ — AWS's own writing on the class of failure (without naming Capital One). The architectural lessons.

---

## Tooling and supplementary

- **`aws` CLI reference.** https://docs.aws.amazon.com/cli/latest/reference/ — the canonical reference for `aws iam`, `aws sts`, `aws organizations`, `aws cloudtrail`, and the dozens of other service commands the exercises invoke.

- **`aws sts get-caller-identity`.** The single most useful diagnostic command in any AWS troubleshooting session. Returns the account ID, the IAM ARN, and the user ID of the current credentials.

- **`gcloud` CLI reference.** https://cloud.google.com/sdk/gcloud/reference — the canonical reference for the GCP CLI.

- **`az` CLI reference.** https://learn.microsoft.com/en-us/cli/azure/reference-index — the canonical reference for the Azure CLI.

- **`tfsec`.** https://github.com/aquasecurity/tfsec — alternative to Checkov, owned by Aqua Security, MIT-licensed. Mentioned in Lecture 3 for completeness; Checkov is the worked example because its rule catalogue is larger.

- **`kics`.** https://github.com/Checkmarx/kics — Checkmarx's IaC scanner; covers Terraform, CloudFormation, Kubernetes, Helm, Docker, OpenAPI, Ansible, Pulumi. Apache 2.0. Mentioned in Lecture 3 for completeness.

- **`cloudquery`.** https://github.com/cloudquery/cloudquery — open-source cloud-asset inventory. Useful as a complement to ScoutSuite when the operator wants SQL-queryable inventory. MPL 2.0.

- **`cartography`.** https://github.com/cartography-cncf/cartography — Lyft's open-source asset-inventory-into-Neo4j tool. Useful for graph-based blast-radius analysis. Apache 2.0.

- **`AWS IAM Access Analyzer`.** https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html — AWS's built-in tool that identifies resources shared with external principals. Free; complementary to Prowler. Mentioned in Lecture 2.

---

## Standards and RFCs cited inline this week

- **RFC 7519, "JSON Web Token (JWT)".** https://www.rfc-editor.org/rfc/rfc7519 — the token format used by GCP service-account credentials, Azure AD tokens, and many AWS IAM Identity Center workflows. Cited when introducing federated identity.

- **RFC 6749, "The OAuth 2.0 Authorization Framework".** https://www.rfc-editor.org/rfc/rfc6749 — the protocol underlying federated cloud sign-in. Cited for completeness.

- **RFC 7591, "OAuth 2.0 Dynamic Client Registration Protocol".** https://www.rfc-editor.org/rfc/rfc7591 — relevant when discussing service-to-service auth in cloud environments.

- **RFC 8693, "OAuth 2.0 Token Exchange".** https://www.rfc-editor.org/rfc/rfc8693 — the standard underlying STS-style credential exchange. Cited in Lecture 2.

---

## Reading order

Week 11 is dense. The recommended reading order:

1. This `resources.md` (you are here).
2. `lecture-notes/01-iam-fundamentals-and-aws-policy-language.md` plus the **AWS IAM policy evaluation logic** page.
3. `lecture-notes/02-identity-resource-abac-and-scps.md` plus the **AWS ABAC tutorial**.
4. **NIST SP 800-207, pages 1-20** before `lecture-notes/03-misconfig-scanning-prowler-checkov-scoutsuite.md`.
5. **CIS AWS Foundations Benchmark v3.0.0**, skim the Identity and Access Management section.
6. Exercises 1 through 6 in order.
7. Challenges 1 and 2 in either order.
8. Mini-project.
9. Quiz on Sunday.

---

## Bibliography (suggested citation form for the design doc in the mini-project)

If the mini-project's write-up cites a source, prefer the following form:

- Amazon Web Services. *AWS Identity and Access Management User Guide.* Continuously updated. https://docs.aws.amazon.com/IAM/latest/UserGuide/
- Amazon Web Services. *AWS Organizations User Guide.* Continuously updated. https://docs.aws.amazon.com/organizations/latest/userguide/
- Center for Internet Security. *CIS Amazon Web Services Foundations Benchmark v3.0.0.* 2024. https://www.cisecurity.org/benchmark/amazon_web_services
- Google. *Google Cloud Identity and Access Management Documentation.* Continuously updated. https://cloud.google.com/iam/docs
- Microsoft. *Azure Role-Based Access Control Documentation.* Continuously updated. https://learn.microsoft.com/en-us/azure/role-based-access-control/
- National Institute of Standards and Technology. *Special Publication 800-207, Zero Trust Architecture.* August 2020. https://doi.org/10.6028/NIST.SP.800-207
- National Institute of Standards and Technology. *Special Publication 800-162, Guide to Attribute Based Access Control.* January 2014. https://doi.org/10.6028/NIST.SP.800-162
- Prowler Cloud. *Prowler Documentation.* Continuously updated. https://docs.prowler.com/
- Bridgecrew (Palo Alto Networks). *Checkov Documentation.* Continuously updated. https://www.checkov.io/
- NCC Group. *ScoutSuite Wiki.* Continuously updated. https://github.com/nccgroup/ScoutSuite/wiki

The exact form is your choice; consistency within a document matters more than the choice between style guides.
