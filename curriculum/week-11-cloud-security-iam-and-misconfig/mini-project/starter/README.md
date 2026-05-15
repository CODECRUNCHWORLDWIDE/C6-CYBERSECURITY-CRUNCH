# Mini-Project Starter — Inventory

This directory ships a deliberately-misconfigured Terraform stack plus templates the student fills in. Inventory:

- `main.tf` — the misconfigured stack. Fifteen deliberate findings (see Lecture 3 section 5). Validates clean; if applied, provisions free-tier resources.
- `variables.tf` — inputs with safe defaults. Override `apply_destructive` only after reading every defect.
- `outputs.tf` — outputs that surface the misconfigurations for inspection.
- `findings-template.md` — empty findings log. Copy to `findings.md`; fill in during triage.
- `remediation-template.md` — empty remediation log. Copy to `remediation.md`; append a row per fix.
- `design-doc-template.md` — empty design document. Copy to `design-doc.md`; fill in during Day 2.

---

## Quick start

```bash
cp -r starter/ work/
cd work/
terraform init
terraform validate
checkov --directory . --output cli --compact
```

The Checkov scan emits ~15 failing checks across the categories enumerated in `../README.md`.

---

## Do not commit

Add the following to `.gitignore` in your working copy:

```
.terraform/
.terraform.lock.hcl
terraform.tfstate
terraform.tfstate.backup
*.tfvars
*.tfvars.json
crash.log
crash.*.log
scoutsuite-report/
```

`terraform.tfstate` may contain bucket names, ARNs, and (depending on resources) decrypted secret values. The state file is not a secret in the cryptographic sense, but it is operational data the grader does not need.

---

## Tear-down

If you applied:

```bash
terraform destroy
```

Confirm with `aws s3 ls` (empty), `aws ec2 describe-instances` (no `running` or `pending`), `aws cloudtrail describe-trails` (only your pre-existing trails, if any). The starter stack is small enough that the destroy completes in under five minutes.
