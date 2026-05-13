# Lecture 3 — bandit, semgrep, pip-audit in CI

> *Lectures 1 and 2 showed you the hazards. This lecture shows you how to detect them on every push. The three tools — `bandit` for AST-level Python smells, `semgrep` for pattern-matching across languages and frameworks, `pip-audit` for the supply chain — are the minimum viable Python security toolchain in 2025. Configuring them is one afternoon; running them costs cents per CI minute; triaging the findings is the work no tool can do for you.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Run the tools against codebases you own or against public open-    │
│  source you have a local clone of. Tool findings are *yours* to     │
│  triage on your machine; do not file findings or PoCs against an    │
│  upstream project without coordinated disclosure (Week 3).          │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers:

- **`bandit`** — what it is, the rule catalogue, configuration, baselines, the CI integration.
- **`semgrep`** — what it is, which rulesets to enable, how to write a custom rule, the CI integration.
- **`pip-audit`** — what it is, the OSV database, lockfile workflow, the CI integration, the `--ignore-vuln` policy.
- **Triage discipline** — the four-bucket model, suppression-with-justification.
- **A complete GitHub Actions workflow** — the YAML you commit on day one to a Python repo.

---

## 1. The three-tool toolchain

There is no single tool that finds every Python security finding. The three tools below overlap and complement.

| Tool         | What it scans                  | Strength                                | Weakness                                  |
|--------------|--------------------------------|-----------------------------------------|-------------------------------------------|
| `bandit`     | Python source AST              | Cheap; stable; specific to Python smells | Pattern-based; misses taint flow; some false positives |
| `semgrep`    | Source code, multi-language    | Rule registry; cross-framework; taint flow with extensions | Slower; rule maintenance work; "expert mode" rules paid (the free tier still covers the OWASP and security-audit sets) |
| `pip-audit`  | `requirements*.txt`, lockfile  | Supply chain; OSV-backed; cheap to run  | Only reports *known* CVEs; does not find novel issues; depends on lockfile discipline |

Run all three. Treat them as overlapping, not redundant; each one catches things the others miss.

---

## 2. `bandit` — the AST-level lint

### 2.1 What it is

`bandit` is a static analyser that walks the Python AST and matches a fixed catalogue of patterns. It is maintained by the Python Code Quality Authority (PyCQA), under the same umbrella as `flake8` and `isort`. It is not magic; it is a curated set of "this call is dangerous in this context" rules.

### 2.2 Install and first run

```bash
pip install bandit
bandit --version
bandit -r path/to/project
```

`-r` means recursive. `bandit` walks every `.py` file under the path, applies every active rule, and emits a report grouped by severity (Low / Medium / High) and confidence (Low / Medium / High).

### 2.3 The rule catalogue

Rules are identified by `Bxxx` codes. The full catalogue lives at <https://bandit.readthedocs.io/en/latest/plugins/index.html>. The numbering is grouped:

- **B1xx** — Application-level smells. `B101` (`assert` for security), `B102` (`exec`), `B103` (set bad file permissions), `B104` (binding to all interfaces), `B105` / `B106` (hardcoded password / hardcoded secret), `B107` (hardcoded SQL), `B108` (insecure `/tmp` path), `B110` (try/except/pass).
- **B2xx** — Misc. `B201` (`Flask(debug=True)`), `B202` (`tarfile` without member check).
- **B3xx** — Blacklists for crypto, network, deserialisation. `B301` (`pickle`), `B302` (`marshal`), `B303` (`hashlib.md5/sha1`), `B304` (insecure cipher), `B305` (insecure cipher mode), `B306` (`mktemp_q`), `B307` (`eval`), `B308` (`mark_safe`), `B309` (`HTTPSConnection` insecure), `B310` (`urllib_urlopen`), `B311` (`random`), `B312` (`telnetlib`), `B313`-`B320` (XML APIs without `defusedxml`), `B321` (FTP).
- **B4xx** — Imports. `B401` (`telnetlib` import), `B402` (`ftplib`), `B403` (`pickle` import), `B404` (`subprocess` import — *informational; the import itself is fine, the usage matters*), `B405`-`B412` (XML / Crypto / `requests` imports).
- **B5xx** — Crypto. `B501` (`requests` `verify=False`), `B502` (`SSLv2`/`SSLv3`), `B503` (bad SSL defaults), `B504` (`SSL.Connection` w/o protocol), `B505` (weak crypto key size), `B506` (`yaml.load`), `B507` (`paramiko` `AutoAddPolicy`).
- **B6xx** — Subprocess. `B601` (`paramiko` `exec_command`), `B602` (`subprocess` `shell=True`), `B603` (subprocess without shell, *informational*), `B604` (any other shell-invocation), `B605` (`os.system`), `B606` (`os.popen`), `B607` (subprocess with partial path), `B608` (SQL-injection-shaped `execute`).
- **B7xx** — Misc Flask/Django. `B701` (`jinja2.autoescape=False`), `B702` (`mako.Template`), `B703` (`django.mark_safe`).
- **B9xx** — Test files / patterns.

Every rule has a doc page; cite the rule ID in your audit reports.

### 2.4 Configuration

`bandit` reads `.bandit` (legacy) or a `[tool.bandit]` section in `pyproject.toml` (recommended).

```toml
# pyproject.toml
[tool.bandit]
exclude_dirs = ["tests", "build", ".venv"]
# Skip B101 (assert) in the test suite only — done via per-file pragma below;
# rather than disabling globally, prefer the per-file `# nosec` comment.

[tool.bandit.assert_used]
skips = ["**/test_*.py", "**/*_test.py"]
```

For most projects, **do not** disable rules globally. Disable per-call with a `# nosec` comment that *cites the reason*:

```python
# Sometimes the right answer for a legitimate test fixture:
data = pickle.loads(fixture_bytes)  # nosec B301 — test fixture from our own conftest.
```

The rule is: every `# nosec` is reviewable. Reviewers ask "why is this safe?" and the comment answers. A `# nosec` with no justification is a code smell.

### 2.5 Baselines

When you adopt `bandit` on an existing codebase, you will have findings. The recommended sequence:

1. Run `bandit -r . -f json -o bandit-baseline.json` to capture the current state.
2. Commit `bandit-baseline.json`.
3. In CI, run `bandit -r . -b bandit-baseline.json --severity-level medium`. New findings (not in the baseline) fail the build; existing findings (in the baseline) are tracked but do not fail.
4. Allocate time to drain the baseline. The point is to *stop the bleeding*, then catch up.

### 2.6 Severity tuning

`bandit` defaults `B311` (`random` for security) to *Low* severity. In the context of a web application that uses `random` for tokens, that is **High** severity. The default thresholds are conservative; raise them per project.

```toml
[tool.bandit]
# Override severity for the rules where the default is too lenient for this project:
# bandit does not have a global severity-override flag in pyproject.toml as of 2025-Q4;
# the convention is to run with --severity-level low (catch everything) and let triage
# determine real severity.
```

In CI: `bandit -r . --severity-level low --confidence-level medium`. Catch everything that is at least medium confidence; you triage from there.

### 2.7 CI integration

A minimal step in GitHub Actions:

```yaml
- name: Bandit
  run: |
    pip install bandit
    bandit -r src/ -ll -f sarif -o bandit.sarif
  continue-on-error: true

- name: Upload Bandit SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bandit.sarif
```

`-ll` is "low severity OR higher." SARIF output uploads to GitHub Code Scanning, where findings appear in the Security tab and on PR diffs inline.

---

## 3. `semgrep` — the pattern-matching scanner

### 3.1 What it is

`semgrep` is a multi-language pattern-matching engine. You write rules in YAML; the rules match on AST patterns; the matches become findings. Semgrep Inc. maintains a free registry of community and curated rulesets covering OWASP categories, framework-specific concerns, and general code quality. The Pro engine adds taint-flow and inter-procedural analysis; the OSS engine is the free, self-hosted core that runs the registry rules.

For Python security, you want at least:

- `p/python` — the general Python ruleset.
- `p/owasp-top-ten` — the OWASP Top 10 cross-language ruleset.
- `p/security-audit` — broad SAST coverage.
- `p/secrets` — hardcoded credential detection.
- Framework-specific: `p/flask`, `p/django`, `p/fastapi` — only the ones your project uses.

### 3.2 Install and first run

```bash
pip install semgrep
semgrep --version
semgrep --config p/python --config p/owasp-top-ten --config p/security-audit .
```

Each `--config` is a registry ruleset (you can also point at a local YAML file). Semgrep runs the union of all rulesets and emits a report.

### 3.3 Writing a custom rule

The minimum rule has an `id`, a `pattern`, a `message`, a `severity`, and a `languages`. Example: catch `requests.get(...)` where the URL is a function-call result (a proxy for "the URL is user-derived"):

```yaml
# .semgrep/rules/requests-unfiltered-url.yml
rules:
  - id: requests-unfiltered-url
    patterns:
      - pattern: requests.get($URL, ...)
      - pattern-not: requests.get("...", ...)
      - pattern-not: requests.get(SAFE_URL_CONST, ...)
    message: |
      requests.get() called with a non-literal URL. Confirm the URL is allow-listed
      against private/loopback/link-local IPs (A10 SSRF, CWE-918).
    languages: [python]
    severity: WARNING
    metadata:
      cwe: CWE-918
      owasp: A10:2021
```

Run against your project: `semgrep --config .semgrep/rules .`.

The pattern syntax supports metavariables (`$URL`), wildcards (`...`), ellipses for function bodies, and structural matches. The full reference is at <https://semgrep.dev/docs/writing-rules/overview>.

### 3.4 Ignoring and suppressing

`.semgrepignore` (same format as `.gitignore`) excludes files from scanning. Per-line suppression is `# nosemgrep` (optionally `# nosemgrep: rule-id` to target a specific rule) — same rule as bandit: **explain the suppression**.

```python
data = pickle.loads(fixture)  # nosemgrep: avoid-pickle — test fixture, conftest-owned.
```

### 3.5 CI integration

```yaml
- name: Semgrep
  run: |
    pip install semgrep
    semgrep --config p/python --config p/owasp-top-ten --config p/security-audit \
            --sarif --output semgrep.sarif --error .
  continue-on-error: true

- name: Upload Semgrep SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: semgrep.sarif
```

`--error` makes the step exit non-zero on any finding. `continue-on-error: true` lets the workflow still upload SARIF before failing the job (you choose whether to fail the workflow on findings — the recommendation is *yes, on new findings, against a baseline*).

---

## 4. `pip-audit` — the supply chain scanner

### 4.1 What it is

`pip-audit` is the Python Packaging Authority's official supply-chain vulnerability scanner. It reads your dependency manifest (`requirements.txt`, `pyproject.toml`, or the installed environment), queries the OSV database for each package version, and reports known CVEs. Maintained by Trail of Bits under the PyPA umbrella.

OSV (Open Source Vulnerabilities) is Google-led, schema-defined, and aggregates from PyPA Advisory Database, GitHub Advisory Database, and others. The data backing `pip-audit` is the same data backing Dependabot.

### 4.2 Install and first run

```bash
pip install pip-audit
pip-audit --version
pip-audit                                # Scans installed environment.
pip-audit -r requirements.txt            # Scans a requirements file.
pip-audit --strict                       # Exit non-zero on any finding.
pip-audit --format json -o audit.json    # JSON for machine consumption.
```

Findings look like:

```
Found 2 known vulnerabilities in 1 package
Name      Version  ID                  Fix Versions
--------- -------- ------------------- ------------
requests  2.27.0   GHSA-9wx4-h78v-vm56 2.31.0
requests  2.27.0   GHSA-j8r2-6x86-q33q 2.32.0
```

`GHSA-...` are GitHub Security Advisory IDs (one-to-one with CVEs).

### 4.3 The lockfile workflow

Vulnerability scanning is only meaningful against a *deterministic* dependency set. Loose pins (`requests>=2`) are not auditable; `requests==2.32.3` is.

The recommended workflow:

1. Maintain `requirements.in` with loose, human-readable pins (`requests`, `flask>=3`).
2. Generate `requirements.txt` with `pip-compile` (from `pip-tools`):

   ```bash
   pip install pip-tools
   pip-compile requirements.in        # writes requirements.txt with exact versions + hashes.
   ```

3. Commit both. Re-run `pip-compile` when you want to update; `pip-compile --upgrade-package requests` for a targeted bump.
4. CI runs `pip-audit -r requirements.txt --strict`.

The `uv` ecosystem (Astral) is a faster Rust-based replacement (`uv pip compile`, `uv lock`); the audit step works the same.

### 4.4 The `--ignore-vuln` policy

When a CVE is in `pip-audit`'s output but you cannot or will not bump (the fix is in a major version that breaks your code; the vulnerable code path is unreachable in your use), you suppress with `--ignore-vuln`:

```bash
pip-audit -r requirements.txt --ignore-vuln GHSA-9wx4-h78v-vm56
```

The suppression goes in a versioned file with a written justification:

```bash
# pip-audit-ignores.txt
GHSA-9wx4-h78v-vm56  # 2025-05-13 — requests SSRF advisory; we use a strict allow-list
                     # on every requests.get and do not honour redirects; reachability
                     # assessment in security-notes/ssrf-coverage.md.
```

In CI: `pip-audit -r requirements.txt $(awk '{print "--ignore-vuln "$1}' pip-audit-ignores.txt | xargs)`. Same rule as `# nosec`: every ignore is justified, every justification is reviewable.

### 4.5 CI integration

```yaml
- name: pip-audit
  uses: pypa/gh-action-pip-audit@v1
  with:
    inputs: requirements.txt
    strict: true
```

The official Action is maintained by PyPA and handles SARIF upload automatically.

---

## 5. The triage discipline

A scanner produces findings. Findings are *not* bugs. A finding is a hypothesis that needs adjudication. The four-bucket model:

1. **True positive, fix now.** The finding is a real bug, you can patch in this PR. Patch it.
2. **True positive, accept risk (documented).** The finding is a real bug, but the cost of fixing exceeds the cost of the bug given your threat model. Write the justification in a `security-notes/` file; reference it from the `# nosec` / `# nosemgrep` / `--ignore-vuln` line.
3. **False positive (suppressed with a comment).** The scanner's pattern matched but the actual code is safe (e.g., the `subprocess(shell=True)` is on a constant string, not user input). Suppress with a comment that names the reason.
4. **Won't fix (out of scope).** Third-party code you copied into your repo that you are not in a position to patch, etc. Document, link, move on.

The two errors to avoid:

- **Alert fatigue** — leaving findings unscored produces noise that hides real issues. After a week of triage backlog, no one looks at the dashboard.
- **Over-suppression** — bulk-`# nosec`-ing every finding to make CI green silently regresses security. Every suppression must have a justification.

The triage *is* the work. A scanner's value is proportional to the discipline of its triage.

---

## 6. A complete GitHub Actions workflow

Save as `.github/workflows/python-security.yml`:

```yaml
name: python-security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install tooling
        run: |
          python -m pip install --upgrade pip
          pip install bandit semgrep pip-audit

      - name: Bandit (SARIF)
        run: |
          bandit -r src/ -ll -f sarif -o bandit.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: bandit.sarif
          category: bandit

      - name: Semgrep (SARIF)
        run: |
          semgrep --config p/python \
                  --config p/owasp-top-ten \
                  --config p/security-audit \
                  --config p/secrets \
                  --sarif --output semgrep.sarif . || true
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep.sarif
          category: semgrep

      - name: pip-audit
        uses: pypa/gh-action-pip-audit@v1
        with:
          inputs: requirements.txt
          strict: true
```

What it does:

- Runs on every push to `main` and every PR against `main`.
- Installs the three tools.
- Runs `bandit`, emits SARIF, uploads to Code Scanning (findings appear inline on PR diffs).
- Runs `semgrep` with four rulesets, emits SARIF, uploads to Code Scanning.
- Runs `pip-audit` strict; the job fails on any unsuppressed CVE.

The first three steps run with `|| true` so SARIF still uploads even if the tool finds something; the `pip-audit` step is `strict: true` and fails the workflow.

The right baseline for an existing project is: ship the workflow once, accept the initial flood of findings, baseline `bandit`, suppress with justification, and treat *new* findings as red.

---

## 7. Beyond the three — what to add next

The three-tool baseline is the minimum. Once you are comfortable, add:

- **CodeQL** (GitHub) for taint-flow on Python. Free for public repos and for GitHub Enterprise with Advanced Security. Adds `py/unsafe-deserialization`, `py/redos`, `py/sql-injection`, and others.
- **Trivy** for container scanning if you ship Docker images.
- **`gitleaks`** for committed secrets (overlap with `p/secrets` but more aggressive).
- **`detect-secrets`** (Yelp) for the same secrets surface, with an interactive baseline mode that is friendlier for first-time onboarding.
- **OSSF Scorecard** for project-health signals (signed releases, branch protection, dependency review).
- **Sigstore** for signing your own releases (`cosign`, PEP 740).

Each adds coverage. None replaces the three above.

---

## 8. The exercise tie-in

Exercise 3 (`exercise-03-run-bandit-semgrep.md`) walks the first-run experience: scan a small intentionally vulnerable script with `bandit` and `semgrep`, read every finding, write the triage. The mini-project then puts you in front of a real codebase (your own C1 or C16 project) and asks you to do the same at scale.

---

## 9. Summary

- `bandit` is the AST-level Python smell catalogue. Configure with `pyproject.toml`. Baseline existing findings. Run with `--severity-level low --confidence-level medium` in CI. Suppress per-call with `# nosec` *and a reason*.
- `semgrep` is the pattern-matching multi-language SAST. Enable `p/python`, `p/owasp-top-ten`, `p/security-audit`, `p/secrets`, and the framework-specific ruleset for your stack. Write project-specific custom rules in `.semgrep/`. Suppress per-call with `# nosemgrep` *and a reason*.
- `pip-audit` is the supply-chain scanner backed by OSV. Run against a `pip-compile`-generated lockfile. `--strict` in CI. Ignore individual CVEs in a versioned `pip-audit-ignores.txt` with a written justification.
- The four-bucket triage is the work. *Every* suppression has a justification reviewable in a PR.
- The minimum CI workflow is one YAML file, runs in ~2 minutes on a small project, and uploads SARIF to Code Scanning.

The mini-project this week is to run this toolchain against a real Python codebase *you wrote* — your C1 mini-project, a C16 portfolio piece, any repo of your own. The artifact is the documented triage of every finding the tools produced.

---

*End of Lecture 3. End of Week 5 lectures.*
