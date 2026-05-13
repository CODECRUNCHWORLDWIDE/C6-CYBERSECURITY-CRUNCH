# Challenge 1 — Audit Your Own C1 Mini-Project

**Estimated time:** ~2 hours. Python 3.11. Local clone, read-only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The target is code *you wrote*. Audit on a local clone. If the     │
│  C1 mini-project is deployed somewhere, do not exercise findings    │
│  against the deployed service unless you operate it personally;     │
│  the toolchain runs against the source code on your laptop, which   │
│  is always authorised.                                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You shipped a Python mini-project in C1 (Code Crunch Convos) — a Flask app, a CLI tool, a data scraper, a tiny FastAPI service, whatever it was. You probably did not run a security tool against it at the time. Now you will.

The point of this challenge is to practise the *audit method* on a small, *familiar* codebase before applying it to a larger or unfamiliar one (which is the mini-project this week or any real engagement). Familiarity is the asset: you know what the code is supposed to do, so triage is fast.

This challenge covers:

- All Python-specific hazards from Lectures 1 and 2 (deserialisation, SSRF, ReDoS, stdlib footguns).
- The full three-tool toolchain from Lecture 3 (`bandit`, `semgrep`, `pip-audit`).
- The four-bucket triage discipline.

---

## Step 0 — Pick the target (5 min)

If you have a **C1 mini-project**, use that. Look for:

- A Flask, Django, or FastAPI app (web-facing surface is the richest).
- A CLI tool that reads stdin or argv (subprocess / eval / pickle surface).
- A scraper or API consumer (HTTP client surface).

If you do **not** have a C1 mini-project — perhaps you came to C6 via another route — pick instead:

- Any Python repository you wrote (a script ≥ 100 lines is enough).
- A small Python repo *under a permissive licence* that you have a local clone of, that has ≤ 5 kLoC and is **single-author** (multi-author projects already have triage and would muddy the lesson). Examples: a small CLI utility, a personal Django side-project, a tiny FastAPI service.

Record:

- Repo URL (or path on your laptop).
- Commit hash you audited.
- Line count (`tokei` or `scc`).
- Languages and frameworks.

---

## Step 1 — Read first, scan second (20 min)

Before running any tool, *read* the codebase. The point is to form your own hypotheses, then compare to the tools' findings. A scanner is a check on your read, not a replacement for it.

For each of the following hazard classes, walk the codebase and note candidate findings:

- **Deserialisation.** `grep -rE "pickle|yaml\.load|shelve|dill|joblib" .` Where do these appear? Are the inputs trusted (local file we write) or attacker-influenced (network, user-uploaded, environment)?
- **Subprocess.** `grep -rE "subprocess|os\.system|os\.popen|commands\." .` Any `shell=True`? Any string interpolation into the command?
- **`eval` / `exec` / `compile`.** `grep -rE "\beval\(|\bexec\(|\bcompile\(" .`
- **HTTP clients.** `grep -rE "requests\.(get|post|put|delete|head|patch)|urlopen|httpx\.|aiohttp\." .` Any URLs from user input?
- **Regex on user input.** `grep -rE "re\.(compile|match|search|fullmatch|sub|findall)" .` For each, check whether the *input* is user-controlled (the pattern usually is not).
- **Random / time-derived randomness.** `grep -rE "random\.|time\.time\(\)" .` Any of these output ever visible to a user? (Session IDs, tokens, "random" filenames, ...)
- **Tempfile.** `grep -rE "tempfile\." .` Any `mktemp`?
- **XML.** `grep -rE "xml\.etree|lxml|xml\.dom|xml\.sax" .` Any `defusedxml`?
- **`verify=False`** on requests / urllib3.
- **Hardcoded secrets.** `grep -rE "(password|secret|token|api_key|aws_)" . | grep -vE "test|example"`. (This is noisy; tighten the grep for your project.)

Write your hypotheses in `audit-report.md` as a "pre-scan" section. Be honest about what you do and do not expect to find.

---

## Step 2 — Run the toolchain (15 min)

Run all three tools against the target.

```bash
mkdir -p notes

# Bandit
bandit -r . -ll --confidence-level low \
       -f txt -o notes/bandit-output.txt
bandit -r . -ll --confidence-level low \
       -f json -o notes/bandit-output.json

# Semgrep
semgrep --config p/python \
        --config p/owasp-top-ten \
        --config p/security-audit \
        --config p/secrets \
        --text --output notes/semgrep-output.txt .
semgrep --config p/python \
        --config p/owasp-top-ten \
        --config p/security-audit \
        --config p/secrets \
        --sarif --output notes/semgrep-output.sarif .

# pip-audit — if there's a requirements.txt or pyproject.toml
pip-audit -r requirements.txt > notes/pip-audit-output.txt || true
# or:
# pip-audit > notes/pip-audit-output.txt
```

If `requirements.txt` does not exist (perhaps you used `poetry.lock` or `Pipfile.lock`), point `pip-audit` at the appropriate manifest. For `poetry`, `pip-audit --poetry`. For an installed environment, run from inside the venv with no `-r` flag.

If your project produces *zero* findings on all three tools, your target is too small or you got lucky. Pick a slightly larger project; the lesson requires a non-empty result set.

---

## Step 3 — Triage every finding (60 min)

For each finding in each tool, write a finding file in `findings/F-NN-<short-id>.md`. The standard finding format:

```markdown
# F-NN — <Short title>

**Hazard class:** <e.g. Deserialisation of untrusted data>
**CWE:** CWE-NNN
**OWASP 2021:** A0N
**Tool:** bandit B301 / semgrep <rule-id> / pip-audit GHSA-...
**Severity (tool):** Medium
**Severity (you, after triage):** High (or unchanged, or accept-risk)
**Location:** `path/to/file.py:LINE`

## Description

One paragraph. What the bug is, anchored to the line.

## Evidence

```python
# 2-5 lines of the offending code, with line number prefix.
```

## Triage bucket

- [ ] True positive, fix now
- [ ] True positive, accept risk (documented below)
- [ ] False positive (suppressed below)
- [ ] Won't fix (out of scope)

## Reasoning

One paragraph explaining the bucket choice.

## Remediation

The patch, anchored to the line. Either a diff snippet or a prose description of the change.

## References

- Lecture 1 / 2 / 3 section.
- CVE-... (if relevant; ReDoS or supply chain).
- OWASP Cheat Sheet URL.
```

The bucket counts matter. Expect a roughly bell-shaped distribution:

- **True positive, fix now:** the bugs that are bugs and you can patch.
- **True positive, accept risk:** the bugs that are bugs but the cost of fixing exceeds the cost of the bug. Write the trade-off.
- **False positive:** the tool's pattern matched but the actual code is safe. The classic case is `subprocess(shell=True)` on a hardcoded command. Suppress with `# nosec` / `# nosemgrep` *and a written reason*.
- **Won't fix:** vendored code, abandoned scripts, etc.

If you find yourself with 80% "false positive," re-read each one. The scanner is rarely *that* wrong; more often you have not thought hard enough about taint flow.

---

## Step 4 — Write the audit report (15 min)

`audit-report.md` is the cover document. ~600-1000 words. Sections:

1. **Target.** Project name, commit hash, line count, languages, frameworks, your relationship to the code.
2. **Method.** "Read first, scan second" as in Step 1; tool versions and configs.
3. **Pre-scan hypotheses.** Your read of the code's risk surface, before running tools. Be honest about what you missed.
4. **Findings summary.** A table: F-NN, hazard class, tool, severity (your scored), bucket. One row per finding.
5. **The interesting findings.** Two or three paragraphs on the most interesting findings — the one the tools caught that you missed, the one you caught that the tools missed, the one that was a false positive that *looked* real.
6. **The toolchain delta.** Which findings only `bandit` caught? Which only `semgrep`? Where they overlap? Where each missed something?
7. **Remediation plan.** For each "fix now" finding, what you would commit. For each "accept risk," the trade-off. (You do not need to *implement* the fixes for the challenge — that is the mini-project.)
8. **Reflection.** What you learned about your own code. Be calibrated, not performative. The point is to recognise patterns you will catch sooner next time.

---

## Acceptance

- Target picked and recorded with commit hash and line count.
- All three tools run; output captured in `notes/`.
- Every finding has a `findings/F-NN-*.md` file in the standard format.
- Every finding has a triage bucket and a reasoning paragraph.
- `audit-report.md` covers all eight sections above.
- If your target produced zero findings, the report says so and explains why (likely: too small a target; pick a larger one).
- If your target produced 50+ findings, the report says so and explains which 5-10 you triaged in depth (do not pretend to have triaged all 50 carefully in 2 hours; pick the highest-severity).

---

## Stretch

If you finish early:

- Implement one of the "fix now" patches and re-run the toolchain to confirm the finding is gone. Add the diff and the re-run output to the report.
- Run **CodeQL** against the same target (free for public GitHub repos under Code Scanning). Compare to the three-tool baseline.
- Run `safety` against the requirements as a cross-check on `pip-audit`. Note any disagreement.
- Write a `semgrep` custom rule for one anti-pattern *specific to your project* — a deprecated internal API, a naming convention, anything project-specific that a registry rule could not catch.
- Re-audit a *different* project of yours (e.g., a C16 mini-project). Compare the finding distribution to your C1 project. Are your habits getting better, worse, or stable?
