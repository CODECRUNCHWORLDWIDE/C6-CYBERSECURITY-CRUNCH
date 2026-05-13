# Exercise 3 — First-Run bandit, semgrep, pip-audit

**Estimated time:** 45 minutes. Python 3.11. Local only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Run the scanners against the intentionally vulnerable sample       │
│  in this exercise, against your own code, or against public open-   │
│  source code you have a local clone of. Tool findings are yours to  │
│  triage on your machine; do not file findings or PoCs against an    │
│  upstream project without coordinated disclosure (Week 3).          │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You are about to drop the three-tool toolchain — `bandit`, `semgrep`, `pip-audit` — into a Python project for the first time. Before you point it at production code (next week's mini-project), you will run it against a small *intentionally vulnerable* sample, read every finding, and write the per-finding triage. The point is to calibrate your eye against known-bad code so you recognise true positives vs. false positives on real code.

This exercise covers:

- `bandit` first-run experience and rule-ID reading.
- `semgrep` first-run experience with multiple rulesets.
- `pip-audit` first-run experience against a deliberately old requirements file.
- The four-bucket triage discipline from Lecture 3.

---

## Step 1 — Build the vulnerable sample (10 min)

Create `vuln_sample.py`:

```python
# vuln_sample.py — INTENTIONALLY VULNERABLE. Do not deploy.
# AUTHORIZED USE ONLY — local lab. Contains one example of nearly every Python smell.
import hashlib
import os
import pickle
import random
import subprocess
import time
from xml.etree import ElementTree as ET

import requests
import yaml


PASSWORD = "hunter2"                                                      # B105
DEBUG = True                                                              # B201


def login_token() -> str:
    """A 'random' token — Mersenne Twister + time. Insecure (CWE-330)."""
    return hashlib.md5(                                                   # B324
        f"{time.time()}-{random.random()}".encode()                       # B311
    ).hexdigest()


def run_ping(host: str) -> int:
    """Shell-injection sink (CWE-78)."""
    return os.system(f"ping -c 1 {host}")                                 # B605, B607


def run_traceroute(host: str) -> bytes:
    """Subprocess with shell=True — same hazard, different API."""
    return subprocess.check_output(                                       # B602
        f"traceroute {host}", shell=True
    )


def load_cart(blob: bytes) -> dict:
    """Pickle deserialisation of untrusted input (CWE-502)."""
    return pickle.loads(blob)                                             # B301


def load_config(yaml_text: str) -> dict:
    """yaml.load default loader — CWE-502."""
    return yaml.load(yaml_text)                                           # B506


def parse_uploaded_xml(xml_text: str) -> ET.Element:
    """xml.etree.ElementTree — XXE / billion-laughs (CWE-611, CWE-776)."""
    return ET.fromstring(xml_text)                                        # B314


def url_preview(user_url: str) -> str:
    """SSRF — unfiltered URL fetch (CWE-918)."""
    return requests.get(user_url, verify=False, timeout=5).text[:1000]    # B501 (verify=False) + custom SSRF


def make_tempfile() -> str:
    """tempfile.mktemp — TOCTOU (CWE-377)."""
    import tempfile
    path = tempfile.mktemp()                                              # B306
    with open(path, "w") as f:
        f.write("hello")
    return path


def evaluate(expression: str) -> int:
    """eval on user input (CWE-94)."""
    return eval(expression)                                               # B307


if __name__ == "__main__":
    print(login_token())
```

Now create `requirements.txt` — pin to known-vulnerable versions so `pip-audit` has something to report:

```
# requirements.txt — deliberately old, for the exercise.
Flask==1.0.2
PyYAML==3.13
requests==2.19.1
Jinja2==2.10
urllib3==1.24.1
```

Install:

```bash
pip install -r requirements.txt
```

(If you would rather not install old packages globally, use a fresh venv.)

---

## Step 2 — First-run `bandit` (10 min)

```bash
bandit -r . -ll --confidence-level low
# -ll = severity low or higher (catch everything for triage)
```

You should see approximately a dozen findings against `vuln_sample.py`, including (at minimum):

- `B105` — Possible hardcoded password: `'hunter2'`.
- `B201` — Use of `Flask(debug=True)` or `DEBUG = True` flag.
- `B301` — `pickle.loads` is unsafe.
- `B306` — `mktemp_q`.
- `B307` — `eval`.
- `B311` — `random` for security.
- `B324` — `hashlib.md5`.
- `B501` — `requests` `verify=False`.
- `B506` — `yaml.load` without `Loader`.
- `B602` — `subprocess` with `shell=True`.
- `B605` — `os.system`.

Save the output:

```bash
bandit -r . -ll --confidence-level low -f txt -o bandit-output.txt
bandit -r . -ll --confidence-level low -f json -o bandit-output.json
```

For *each* finding, write a one-line triage in `bandit-triage.md`:

```markdown
# bandit triage — vuln_sample.py

| Line | Rule | Severity | Confidence | Triage | Reason |
|---|---|---|---|---|---|
| 17 | B105 | Low | Medium | TP, fix | Move to env var / secret store. |
| 18 | B201 | High | Medium | TP, fix | Env-driven, default False. |
| 25 | B324 | Medium | High | TP, fix | Use argon2-cffi for passwords; secrets.token_urlsafe for tokens. |
| 26 | B311 | Low | High | TP, fix (severity tune UP) | Mersenne Twister; replace with secrets module. |
| 32 | B605 | High | High | TP, fix | Use subprocess.run([...], shell=False). |
| 32 | B607 | High | High | TP, fix | Use absolute path. |
| 38 | B602 | High | High | TP, fix | Same fix as B605. |
| 44 | B301 | Medium | High | TP, fix | Replace pickle with JSON + pydantic. |
| 49 | B506 | Medium | High | TP, fix | yaml.safe_load. |
| 54 | B314 | Medium | High | TP, fix | defusedxml. |
| 59 | B501 | High | High | TP, fix | verify=True; cite CVE-2024-35195 as receipt. |
| 64 | B306 | Medium | High | TP, fix | tempfile.NamedTemporaryFile. |
| 72 | B307 | Medium | High | TP, fix | ast.literal_eval. |
```

Every finding here is a true positive — the sample is intentionally vulnerable. In a real codebase, expect a mix of true positives and false positives; the triage is identical in shape.

---

## Step 3 — First-run `semgrep` (10 min)

```bash
semgrep --config p/python \
        --config p/owasp-top-ten \
        --config p/security-audit \
        --config p/secrets \
        .
```

The first run downloads the rulesets (one-time, ~30 seconds). Subsequent runs use the cache.

You should see findings overlapping with `bandit`'s, plus some `bandit` misses:

- `python.lang.security.deserialization.avoid-pickle.avoid-pickle` (pickle.loads).
- `python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load` (yaml.load).
- `python.lang.security.audit.dangerous-system-call.dangerous-system-call` (os.system).
- `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` (subprocess with shell=True).
- `python.lang.security.audit.eval-detected.eval-detected` (eval).
- `python.requests.security.disabled-cert-validation.disabled-cert-validation` (verify=False).
- `python.flask.security.audit.debug-enabled.debug-enabled` (DEBUG=True, if Flask is in scope; pure `DEBUG = True` global may or may not trigger).

Save:

```bash
semgrep --config p/python --config p/owasp-top-ten --config p/security-audit --config p/secrets \
        --sarif --output semgrep-output.sarif .

semgrep --config p/python --config p/owasp-top-ten --config p/security-audit --config p/secrets \
        --text --output semgrep-output.txt .
```

Write per-finding triage in `semgrep-triage.md`. Note:

- **Where `semgrep` overlaps with `bandit`:** record one finding per bug (same bug, two scanners is one bug).
- **Where `semgrep` catches something `bandit` missed:** record it as a separate row and note "bandit missed."
- **Where `bandit` caught something `semgrep` missed:** record it inversely.

The point of running both is exactly this overlap-and-difference analysis. Neither tool is complete; together they are closer to complete.

---

## Step 4 — First-run `pip-audit` (10 min)

```bash
pip-audit -r requirements.txt
```

With the deliberately old pins, expect findings against `Flask==1.0.2`, `PyYAML==3.13`, `requests==2.19.1`, `Jinja2==2.10`, `urllib3==1.24.1`. For each, `pip-audit` prints the `GHSA-...` or `CVE-...` ID and the fixed version.

Save:

```bash
pip-audit -r requirements.txt --format json -o pip-audit-output.json
pip-audit -r requirements.txt > pip-audit-output.txt
```

Write per-finding triage in `pip-audit-triage.md`:

```markdown
# pip-audit triage — requirements.txt

| Package | Version | Vulnerability | Fix Version | Triage | Reachability |
|---|---|---|---|---|---|
| Flask | 1.0.2 | GHSA-... (CVE-2018-1000656) | 1.0.3 | TP, bump | Affected feature (open redirect) is reachable in any Flask app that calls `redirect()`. |
| PyYAML | 3.13 | CVE-2017-18342 | 5.1 | TP, bump | We call yaml.load (vuln_sample.py:49) — directly reachable. |
| requests | 2.19.1 | CVE-2018-18074 | 2.20.0 | TP, bump | We follow cross-host redirects (default). Reachable. |
| Jinja2 | 2.10 | CVE-2019-10906 | 2.10.1 | TP, bump | Sandbox escape; only reachable if you use `jinja2.sandbox`. We do not. Reachability LOW. |
| urllib3 | 1.24.1 | CVE-2019-11324 | 1.24.2 | TP, bump | Certificate-pinning bypass. Reachable if you customise `cert_reqs`. We do not. Reachability LOW. |
```

The "reachability" column is the work no scanner does for you. A CVE in a dependency is only a *real* bug to you if the vulnerable code path is reachable in your use. For most CVEs the answer is "yes, reachable" and the fix is to bump. For some, the vulnerable feature is unused and the bump is *still* the right answer (defence in depth, lower triage debt next time).

---

## Step 5 — Write the writeup (5 min)

Create `writeup.md` (200-400 words). Cover:

1. **What each tool found** (count by severity, one sentence each).
2. **Where the tools overlapped** (same finding caught by two scanners — list one or two examples).
3. **Where the tools disagreed** (one caught what the other missed — list one or two examples). The lesson is that no single tool is complete.
4. **The triage discipline** — your distribution across the four buckets: True positive / Accept risk / False positive / Won't fix. For this sample, expect almost all true positive.
5. **What you would change before running this on real code.** The severity threshold (`-ll` was aggressive), the rulesets (you may want `p/flask` if the project is Flask), the baseline (you will need one for any non-trivial codebase).

---

## Acceptance

- `vuln_sample.py`, `requirements.txt`, `bandit-output.txt`, `bandit-output.json`, `bandit-triage.md`, `semgrep-output.txt`, `semgrep-output.sarif`, `semgrep-triage.md`, `pip-audit-output.txt`, `pip-audit-output.json`, `pip-audit-triage.md`, `writeup.md` all present.
- `bandit` produces at least 10 findings on `vuln_sample.py`.
- `semgrep` produces overlapping plus distinct findings.
- `pip-audit` produces at least 5 findings on `requirements.txt`.
- The triage files account for **every** finding, with a bucket and a reason per row.
- The writeup names at least one finding caught by `semgrep` that `bandit` missed, or vice versa.

---

## Stretch

If you finish early:

- Add `# nosec B311 — used for non-security shuffling in the demo script` to one of the `bandit` findings and re-run. Confirm `bandit` ignores that finding now, *and* note that the `# nosec` has a written reason (the discipline from Lecture 3).
- Write a `bandit` baseline of `vuln_sample.py` (`bandit -r . -f json -o baseline.json`); then add a *new* finding to the file and re-run with `-b baseline.json`. Confirm only the new finding is reported.
- Run **CodeQL** against `vuln_sample.py` if you have GitHub Code Scanning enabled on a public repo. Compare findings to `bandit` + `semgrep`. CodeQL's taint-flow analysis catches some things the pattern-based tools miss.
- Try `safety check -r requirements.txt` as a cross-check on `pip-audit`. Note any disagreement.
