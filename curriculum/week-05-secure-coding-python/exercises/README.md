# Week 5 — Exercises

Three hands-on exercises in Python. Each one walks a Python-specific hazard class — deserialisation, ReDoS, and first-run security tooling — on small, runnable code you write yourself. The exercises are warm-up for the mini-project, which audits a real Python codebase you wrote (C1 or C16) with the full toolchain.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Run the vulnerable code in this exercise set on your own machine   │
│  only. Bind to 127.0.0.1. Do not expose any exercise script to the  │
│  public internet, even briefly, even behind a "secret" port. Do     │
│  not run the attack payloads against a service you do not operate.  │
└─────────────────────────────────────────────────────────────────────┘
```

## Index

| Exercise | Hazard | Time | Deliverable |
|---|---|---|---|
| [exercise-01-pickle-rce.md](./exercise-01-pickle-rce.md) | `pickle` deserialisation (CWE-502) | 60 min | Vulnerable server, working RCE PoC, patched JSON+pydantic server, write-up |
| [exercise-02-redos-attack.md](./exercise-02-redos-attack.md) | Catastrophic regex (CWE-1333) | 60 min | Catastrophic regex demo, doubling-test output, three patches (rewrite / `re2` / size cap), write-up |
| [exercise-03-run-bandit-semgrep.md](./exercise-03-run-bandit-semgrep.md) | First-run security tooling | 45 min | `bandit` and `semgrep` output on a small vulnerable script, per-finding triage, write-up |

## Setup — once per machine

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install flask pydantic pyyaml requests
pip install bandit semgrep pip-audit
pip install google-re2          # for exercise 2 fix option
```

Verify:

```bash
python -c "import flask, pydantic, yaml, requests; print('ok')"
bandit --version
semgrep --version
pip-audit --version
python -c "import re2; print(re2.__version__)"
```

If `google-re2` fails to install on macOS (it needs a C++ compiler and the upstream `re2` headers), use `pip install pyre2` as a fallback or skip the `re2` patch in exercise 2.

## How to run each exercise

Each exercise has at least one `<topic>_bad.py` (vulnerable) and one `<topic>_good.py` (patched). You write both. Run with:

```bash
python <topic>_bad.py    # exposes the bug; you reproduce it from another terminal
python <topic>_good.py   # the fix; you verify the bug is gone
```

Bind to `127.0.0.1`. Use a non-default port (`5001`, `5002`, `5003`) to avoid colliding with the Week 4 mini-project app.

## Submission

Commit each exercise as a directory in your `c6-week-05` repo:

```
exercise-01-pickle-rce/
    pickle_bad.py
    pickle_good.py
    make_payload.py
    writeup.md
exercise-02-redos-attack/
    redos_demo.py
    redos_good_rewrite.py
    redos_good_re2.py
    redos_good_capped.py
    writeup.md
exercise-03-run-bandit-semgrep/
    vuln_sample.py
    bandit-output.txt
    semgrep-output.txt
    writeup.md
```

Each `writeup.md` is short — 200-400 words — covering:

1. The Python hazard class and the CWE ID(s).
2. The bug, in one sentence anchored to the vulnerable line.
3. The fix, in one sentence anchored to the patched line.
4. The defender-side detection — which scanner rule (`bandit Bxxx`, `semgrep rule-id`, CodeQL query) catches this and at which severity.
5. One residual risk after the fix.

The write-up is the artifact a hiring manager reads. The code is the evidence behind it.
