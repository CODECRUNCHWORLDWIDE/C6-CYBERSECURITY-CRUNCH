# Mini-Project — Audit a Real Python Codebase with bandit + semgrep + pip-audit

> Run the full Python security toolchain — `bandit`, `semgrep`, `pip-audit` — against a real Python codebase you wrote (your C1 mini-project, a C16 portfolio piece, any repo of your own). Document every finding. Triage every finding. Patch the true positives. The artifact, at the end, is the audit report a hiring manager reads alongside your Week 1-4 portfolio outputs.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The mini-project target is code *you wrote*. Audit on a local      │
│  clone. If the target is deployed somewhere, do not exercise        │
│  findings against the deployed service unless you operate it        │
│  personally. The toolchain runs against source on your laptop,      │
│  which is always authorised.                                        │
│                                                                     │
│  If during this work you find a finding in an upstream dependency   │
│  (a `pip-audit` CVE in a third-party package), do not publish a     │
│  novel PoC against that upstream project; follow the project's      │
│  SECURITY.md and the Week 3 coordinated-disclosure process.         │
└─────────────────────────────────────────────────────────────────────┘
```

This mini-project is the synthesis of Week 5. The lectures named the hazards. The exercises gave you each hazard end-to-end. The challenge practised the audit method on a small project. The mini-project does it at full scale, on a codebase you own, with the produced artifact being a public repository a future employer can read.

**Estimated time:** 7 hours, spread across Thursday-Saturday.

---

## 1. Pick the target

The target must satisfy all of:

- **You wrote it.** This is non-negotiable. The audit experience requires familiarity with what the code is *supposed* to do; that familiarity is your asset for triage.
- **Python, ≥ 200 lines.** Smaller than this and the scanners will produce too few findings to be educational.
- **Ideally ≤ 5 kLoC.** Above this and the triage workload exceeds the mini-project budget.
- **Has a dependency manifest.** `requirements.txt`, `pyproject.toml` (PEP 621 or Poetry), or `Pipfile`. `pip-audit` needs something to scan.

Strong candidates, in priority order:

1. **Your C1 mini-project.** The end-of-C1 Flask/FastAPI/CLI artifact. Most C1 graduates have one.
2. **A C16 portfolio piece** (C16 is the Python-heavy track).
3. **A Week 4 mini-project from this track** (the OWASP-Top-10 lab app). The Week 4 app is *deliberately* vulnerable, so the audit produces findings; the lesson is then about *coverage* — does the toolchain catch every category Week 4 placed?
4. **Any personal Python repo** you have under your own GitHub account.

If you do not have any of the above, clone a *single-author* small Python project under a permissive licence and audit your local copy read-only. Be explicit in the report that the target is third-party.

Record in the audit report:

- Repository URL.
- Commit hash audited.
- Line count (`tokei .` or `scc .`).
- Languages and frameworks.
- Your relationship to the code.

---

## 2. What you will produce

A public GitHub repo named `c6-week-05-audit-<yourhandle>` (or a subfolder of your portfolio repo) containing:

- `README.md` — one-page intro: target, scope, summary of findings, links to each section.
- `audit-report.md` — the cover document (~1500-2500 words) following the structure in §5 below.
- `findings/` — one Markdown file per finding, in the standard format (template in §4).
- `notes/` — the raw tool output (bandit, semgrep, pip-audit) captured to text and SARIF.
- `patches/` — optional diffs / branches that implement the "fix now" findings. The audit-only deliverable does not require patches; the audit-plus-patch deliverable is the stronger portfolio piece.
- `.github/workflows/python-security.yml` — the CI workflow from Lecture 3, configured for the audited project. Commit to the audit repo even if you do not commit it upstream.
- `LICENSE` — GPL-3.0 (consistent with C6) or a permissive licence of your choice for the document text.

### The commit / PR shape

If you choose to also *patch* the project (recommended for portfolio strength), each "fix now" finding is one PR (or one commit in the audit repo):

```
PR #1  — F-01: replace pickle.loads in cart import with JSON + pydantic schema
PR #2  — F-02: replace subprocess(shell=True) ping wrapper with [args] form
PR #3  — F-03: bump requests to 2.32.3 (closes GHSA-9wx4-h78v-vm56, GHSA-j8r2-6x86-q33q)
...
```

Each PR description follows the same finding template (§4). The portfolio signal is the *commit history* + the *finding files* together.

---

## 3. The audit method

### 3.1 Phase 0 — Setup (15 min)

```bash
# In the target's directory (or a fresh clone):
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt              # whatever the manifest is
pip install bandit semgrep pip-audit safety
mkdir -p notes findings patches
```

### 3.2 Phase 1 — Read first (30-60 min)

Before running tools, read the code top to bottom. Open every Python file. The reading does two things:

1. Forms your *prior* on the risk surface — where you expect findings.
2. Builds the familiarity needed to triage tool output quickly.

Note in `audit-report.md` Section "Pre-scan hypotheses": which files look risky and why.

### 3.3 Phase 2 — Run the toolchain (15 min)

```bash
# Bandit
bandit -r . -ll --confidence-level low -f txt  -o notes/bandit.txt
bandit -r . -ll --confidence-level low -f json -o notes/bandit.json
bandit -r . -ll --confidence-level low -f sarif -o notes/bandit.sarif

# Semgrep
semgrep --config p/python \
        --config p/owasp-top-ten \
        --config p/security-audit \
        --config p/secrets \
        --text  --output notes/semgrep.txt .
semgrep --config p/python \
        --config p/owasp-top-ten \
        --config p/security-audit \
        --config p/secrets \
        --sarif --output notes/semgrep.sarif .

# Add framework-specific config if applicable:
# semgrep --config p/flask .  >> notes/semgrep-flask.txt
# semgrep --config p/django .  >> notes/semgrep-django.txt
# semgrep --config p/fastapi . >> notes/semgrep-fastapi.txt

# pip-audit — adapt the input flag to your manifest
pip-audit -r requirements.txt --format json \
          --output notes/pip-audit.json || true
pip-audit -r requirements.txt > notes/pip-audit.txt
```

### 3.4 Phase 3 — Triage every finding (3-4 hours)

For every finding from every tool, write a `findings/F-NN-<short-id>.md` file. The template is §4 below.

The four-bucket model:

1. **True positive, fix now.** Patch in this audit (or in a follow-up PR).
2. **True positive, accept risk (documented).** Trade-off written explicitly.
3. **False positive.** Suppress with `# nosec` / `# nosemgrep` / `--ignore-vuln` *and a written reason*.
4. **Won't fix (out of scope).** Vendored code, abandoned scripts, etc.

Tally the buckets in the audit report's summary table.

### 3.5 Phase 4 — Patch (1-2 hours, optional but recommended)

For each "fix now" finding:

1. Branch (`git checkout -b fix/F-NN`).
2. Patch.
3. Re-run the toolchain; confirm the finding is gone.
4. Write tests if applicable (regression test that the bug is fixed).
5. Commit, PR, link from the finding file.

Even one patch is valuable for the portfolio; ten is strong.

### 3.6 Phase 5 — Write the report (1 hour)

The cover document, ~1500-2500 words. Structure in §5.

---

## 4. Finding template

Every file in `findings/` follows this exact template. Cite by `findings/F-NN-<short-id>.md`:

```markdown
# F-NN — <Short, specific title>

| Field | Value |
|---|---|
| Hazard class | <e.g. Deserialisation of untrusted data> |
| CWE | CWE-NNN |
| OWASP 2021 | A0N — <name> |
| Tool | bandit B301 / semgrep <rule-id> / pip-audit GHSA-... |
| Severity (tool) | Low / Medium / High |
| Severity (you, after triage) | Low / Medium / High / Critical |
| Confidence | Low / Medium / High |
| Location | `path/to/file.py:LINE-LINE` |
| Triage bucket | TP-fix / TP-accept / FP / Won't-fix |
| Status | Open / In progress / Fixed (#PR) / Suppressed |

## Description

One-to-two paragraphs. What the bug is, anchored to the line. Cite Lecture 1 / 2 / 3 section.

## Evidence

```python
# 3-8 lines of the offending code with file:line annotation.
```

## Proof-of-concept (if applicable; local only)

If the bug is exploitable end-to-end on your local clone, the short PoC. Skip if the
finding is "vulnerable dependency" (no PoC needed — the OSV advisory has it).

## Triage reasoning

Why this bucket. For TP-accept, the trade-off. For FP, why the scanner pattern matched
but the code is safe. For Won't-fix, the out-of-scope justification.

## Remediation

The patch, anchored to lines. Either a diff snippet or a prose description.

## References

- Week 5 Lecture N, Section X.
- CWE-NNN: <url>
- (CVE if relevant): <url>
- OWASP Cheat Sheet: <url>
- (Upstream advisory if pip-audit): <url>

## History

- YYYY-MM-DD — found by <tool>.
- YYYY-MM-DD — triaged: <bucket>.
- YYYY-MM-DD — patched in PR #N.
```

---

## 5. Audit-report structure

`audit-report.md`, ~1500-2500 words. Sections:

### 5.1 Executive summary (~150 words)

Target, scope, top-line findings count by severity, recommendation in one sentence.

### 5.2 Scope and method (~200 words)

What was audited, what was not. Tool versions. Configuration choices. The specific commit hash audited.

### 5.3 Pre-scan hypotheses (~200 words)

What you expected to find from reading the code, before running tools. Be honest about what you got wrong.

### 5.4 Findings summary (~150 words + a table)

A table with one row per finding:

| ID | Title | Hazard | CWE | Severity (you) | Tool | Bucket | Status |
|----|-------|--------|-----|----------------|------|--------|--------|
| F-01 | pickle.loads in cart import | Deserialisation | CWE-502 | High | bandit B301 | TP-fix | Fixed (#PR-1) |
| F-02 | ... | ... | ... | ... | ... | ... | ... |

### 5.5 Findings detail (~400 words across all)

Two-to-five sentences per finding, summarising the finding file. The reader can drill into `findings/F-NN-*.md` for the full record.

### 5.6 Tool comparison (~200 words)

Which findings only `bandit` caught. Which only `semgrep`. Which only `pip-audit`. The overlap / disagreement analysis is the *empirical evidence* for running multiple tools.

### 5.7 Remediation roadmap (~200 words)

For each "fix now," the patch sketch and the priority. For each "accept risk," the trade-off. For each "false positive," the suppression and the reason.

### 5.8 CI integration (~150 words)

The workflow you committed (`.github/workflows/python-security.yml`). What it runs, what it fails on, how baselines were established (if the target had pre-existing findings you treated as a baseline).

### 5.9 Reflection (~200 words)

What you learned about your own code. Patterns you saw. Habits you will change.

---

## 6. Acceptance criteria

The mini-project is complete when **all** of the following are true:

- [ ] Target picked and recorded (URL, commit hash, line count, frameworks).
- [ ] All three tools (`bandit`, `semgrep`, `pip-audit`) run with output captured in `notes/`.
- [ ] *Every* tool finding has a `findings/F-NN-*.md` file.
- [ ] *Every* finding has a triage bucket and a reasoning paragraph.
- [ ] *Every* finding has a remediation paragraph (even for TP-accept and Won't-fix — explain what the fix *would* be).
- [ ] *Every* `# nosec` / `# nosemgrep` / `--ignore-vuln` in your project (if any) has a written justification.
- [ ] `audit-report.md` covers all nine sections.
- [ ] `.github/workflows/python-security.yml` runs the toolchain on every push to `main` and on every PR.
- [ ] The repo is public (or a portfolio subfolder is public).
- [ ] The README links the audit report and the findings index.

The mini-project is *stronger* if additionally:

- [ ] At least one "fix now" finding is implemented as a PR (or a commit in the audit repo with a clear diff).
- [ ] A regression test is added for each patched finding.
- [ ] A baseline is committed for any pre-existing findings you choose not to fix in this audit.
- [ ] At least one **custom semgrep rule** is committed in `.semgrep/rules/`.

---

## 7. Submission

1. Push the public repo (or portfolio subfolder).
2. Add a link to `audit-report.md` from your portfolio README's Week 5 entry.
3. Link Week 4 and Week 5 portfolio artifacts side by side: the Week 4 OWASP-Top-10 patch artifact + the Week 5 toolchain-audit artifact. Together they are *the* Python application-security portfolio piece a hiring manager wants to read.

---

## 8. Common pitfalls

- **Triage too shallow.** "True positive, fix later" with no reasoning is not triage. Explain the bucket choice.
- **Too many false positives.** If 80% of findings are FP, you have not read each one carefully. Re-triage; the scanner is rarely *that* wrong.
- **No baseline on a legacy project.** If the target is older and has 100+ findings, ship a baseline first, document it, then take the next 10-20 findings as the audit scope.
- **`# nosec` without a reason.** Reviewers should be able to *audit your suppressions* during code review.
- **`pip-audit` ignored.** Supply-chain findings are easy to under-prioritise because they are not "your" bug. They are the most-exploited class in 2024-2025. Bump and document.
- **No CI.** The toolchain is only valuable if it runs on every push. Commit the workflow.

---

## 9. Stretch — once the core is shipped

- Add **CodeQL** Code Scanning to the repo (free for public; native to GitHub). Compare CodeQL's findings to the three-tool baseline.
- Add a **`semgrep` custom ruleset** for the project's conventions (deprecated internals, naming patterns, framework idioms).
- Write a **`pre-commit`** hook config (`.pre-commit-config.yaml`) that runs `bandit -r src/` locally before each commit. Document the per-developer setup.
- Run the same toolchain against a **second** project of yours (a C1 alongside a C16, say). Write a comparison report — which scanner findings are *habits of yours*?

---

## 10. Why this is the artifact

A working-quality application-security engineer can take an unfamiliar Python repository on Monday morning and, by Wednesday, produce: a triaged finding list, a CI pipeline that catches the same class of bug on every future PR, and a remediation plan. The Week 5 mini-project is *that exact deliverable*, on code you wrote, with the audit report a hiring manager can read alongside your Week 4 OWASP artifact.

Build the artifact. Push it. Link it from your portfolio.
