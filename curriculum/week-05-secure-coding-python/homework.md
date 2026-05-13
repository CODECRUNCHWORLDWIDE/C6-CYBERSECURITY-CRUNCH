# Week 5 Homework

Six problems, ~6 hours total. Commit each in your Week 5 repo. The exercises were guided drills on single hazard classes; the homework is closer to the work a Python-focused application-security engineer does in a working day.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Run every payload, scanner, and proof-of-concept on machines you   │
│  own — your exercise scripts, your own local copy of any open-      │
│  source project. Do not test any technique on a remote service you  │
│  do not operate.                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Problem 1 — Build a hardened deserialiser helper (45 min)

In a new file `notes/hw1-safe-loader/`:

- `safe_loader.py` — a single module exposing two functions:
  - `safe_load_json(blob: bytes, schema: type[BaseModel], max_bytes: int = 65536) -> BaseModel` — validate size, parse JSON, validate against the pydantic schema, return the validated model.
  - `safe_load_msgpack(blob: bytes, schema: type[BaseModel], hmac_key: bytes, max_bytes: int = 65536) -> BaseModel` — validate size, verify the trailing 32-byte HMAC-SHA256, decode `msgpack` (`strict_map_key=True, raw=False`), validate against schema, return.
- `test_safe_loader.py` — pytest cases:
  - Happy-path JSON roundtrip.
  - Oversized JSON rejected.
  - Schema-violating JSON rejected.
  - Happy-path msgpack roundtrip with the correct HMAC.
  - msgpack with a tampered body rejected.
  - msgpack with no HMAC trailer rejected.
- `README.md` — 200-400 words explaining when to use which loader (rule of thumb: JSON for human-readable / cross-service; msgpack-with-HMAC for binary-efficient between services you both operate).

**Acceptance.** `pytest` passes. `bandit` and `semgrep` report zero findings against the module. The README cites at least one CVE you wrote the module to avoid (`pickle` CVE-2019-6446 / -2022-29216 / -2024-3568).

---

## Problem 2 — Find a ReDoS in your own dependency tree (45 min)

Pick any Python project of your own (the one you used for Week 5 challenge is fine). For each direct dependency in `requirements.txt`:

1. Identify regex usage. The cheap proxy: `pip show <pkg>`, find the install location, then `grep -rE "re\\.(compile|match|search|fullmatch|findall|sub)" <site-packages-path>/<pkg>/`.
2. Pick three regexes (any three) and run the doubling test from Exercise 2 against each.
3. Note the time profile per length.

Write `notes/hw2-redos-survey.md`:

- Dependency, version, file:line of the regex.
- The regex itself (literal source).
- Doubling-test results.
- Classification: linear / polynomial / catastrophic.
- For any catastrophic finding, file an issue with the project (do **not** publish a PoC publicly without coordinated disclosure per Week 3); document that you would file it.

**Acceptance.** At least 3 regexes profiled across at least 2 dependencies. If you find a real catastrophic regex, note it as such; do not assert a false positive. If all three are linear, your dependencies are well-maintained; pick a fourth from an older package.

---

## Problem 3 — A complete CI pipeline you can drop into any Python repo (1 hour)

In `notes/hw3-ci-pipeline/`, produce:

- `.github/workflows/python-security.yml` — the full GHA workflow from Lecture 3, plus:
  - A `pre-commit` step that runs `bandit -r src/` locally.
  - A SARIF upload for both `bandit` and `semgrep`.
  - A `pip-audit` step that *passes* on ignored CVEs only if `pip-audit-ignores.txt` exists with a written justification.
  - A `pytest` step that runs after the SAST steps.
- `pip-audit-ignores.txt` — empty template with a header comment explaining the format (one ID per line, comment with date + justification).
- `pyproject.toml` snippet — `[tool.bandit]` configuration with `exclude_dirs = ["tests", "build", ".venv"]` and any per-rule skips you justify.
- `.semgrep/rules/custom.yml` — at least one custom rule of your own design (any rule; cite the rationale in a comment).
- `README.md` — 200-400 words explaining what each step does and what each tool catches.

**Acceptance.** The workflow file is syntactically valid YAML (run `yamllint` or paste into GitHub Actions linter). The README explains, per step, what hazard class it covers. The custom semgrep rule has a non-trivial `pattern`; one-liner string matchers do not count.

---

## Problem 4 — Reproduce a real CVE in your own lab (1.5 hours)

Pick one published Python CVE from the last 24 months. Suggestions (verify each is still in the OSV / NVD records before using):

- **CVE-2024-23334** — `aiohttp` static-route path traversal.
- **CVE-2024-3568** — `transformers` `trust_remote_code` pickle RCE.
- **CVE-2024-35195** — `requests` proxy credential leak.
- **CVE-2023-32681** — `requests` proxy-Authorization on redirect.
- **CVE-2022-40898** — `wheel` ReDoS.
- **CVE-2022-29216** — TensorFlow Keras Lambda layer pickle.
- **CVE-2019-6446** — `numpy.load` default `allow_pickle=True`.

In `notes/hw4-cve-reproduction/`:

- `README.md` — the CVE, the affected versions, the fixed versions, the upstream advisory link.
- `reproduce.md` — your reproduction steps. Pin the *vulnerable* version, write a small program that triggers the bug *on your own machine*, demonstrate the impact (file written, process spawned, secret leaked to a local-only listener — *not* exfiltrated anywhere).
- `patch.md` — install the *fixed* version, re-run the same program, show the bug is gone.
- A safe-tag: the reproduction must run only against a local-only target (`127.0.0.1`, a file in `/tmp`, an in-memory listener). The PoC must not touch a remote service.

**Acceptance.** The CVE is real (cite NVD / GHSA URL). The vulnerable repro works. The fix repro shows the bug is gone. The safety tag is honoured.

---

## Problem 5 — A defender's `bandit` baseline for a real Python project (1 hour)

Pick a small open-source Python project (any project you actually use; choose one with ≤ 10 kLoC for a manageable baseline). Clone it, install dependencies, and:

1. Run `bandit -r . -ll --confidence-level low -f json -o baseline.json`.
2. Triage every High and Medium finding (Low is optional). Each gets a row in a triage CSV: file, line, rule, severity, confidence, bucket (TP-fix / TP-accept / FP / Won't-fix), reason.
3. For each "FP" finding, draft the exact `# nosec Bxxx — reason` comment you would PR upstream (do **not** actually PR unless the project welcomes such contributions and you follow `CONTRIBUTING.md`).
4. For each "TP-fix" finding, write a one-paragraph patch sketch.

Write `notes/hw5-bandit-baseline.md` — the report. Include the project name, commit hash, the baseline summary (counts per bucket), and the table.

**Acceptance.** At least 10 findings triaged in detail (or 100% of findings if the project has fewer). The "FP" buckets have explicit reasons that would survive a code-review comment. The "TP" buckets have realistic patch sketches.

---

## Problem 6 — Write a semgrep custom rule for a Python anti-pattern (45 min)

Pick a Python anti-pattern that is **not** covered by any registry ruleset (`p/python`, `p/owasp-top-ten`, `p/security-audit`, `p/secrets`, `p/flask`, `p/django`, `p/fastapi`). Examples:

- "We are deprecating `requests.get`; new code should use the internal `http_client.get` wrapper that does the SSRF allow-list."
- "Direct `os.environ` access for secrets is forbidden; use `secrets_store.get(key)`."
- "`logging.info(f'user={user.email}')` — PII in logs."
- "Any function decorated with `@app.route` must also have `@login_required` (deny-by-default routing)."
- "Pydantic models in `models/` must inherit from `BaseModel`, not from any other base class."

In `notes/hw6-semgrep-rule/`:

- `rule.yml` — the rule, with `pattern`, optional `pattern-not`, `pattern-either`, `metavariables`, `message`, `severity`, `metadata`.
- `target_good.py` — a Python file that *does* follow the convention (rule should not fire).
- `target_bad.py` — a Python file that *violates* the convention (rule should fire).
- `expected.txt` — paste of the `semgrep` output showing the rule fired on `target_bad.py` and *not* on `target_good.py`.
- `README.md` — 200-400 words: the anti-pattern, the rule, the false-positive risk, the suppression mechanism.

**Acceptance.** The rule fires on `target_bad.py` and not on `target_good.py`. The README explains the anti-pattern in terms of either a CWE, a project convention, or a regulatory requirement.

---

## Submission

Commit all six in your `c6-week-05` repo under `notes/hw1-...` through `notes/hw6-...`. Push.

The mini-project follows. It is the synthesis of everything in Week 5 against your *own* codebase.
