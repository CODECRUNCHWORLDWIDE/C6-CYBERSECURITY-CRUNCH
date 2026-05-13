# Week 5 — Challenges

One scoped challenge this week. The exercises trained you on isolated hazard classes; the mini-project will put you in front of a real codebase end-to-end. The challenge is the bridge — auditing **your own** C1 mini-project (or any Python repository you wrote) for Python-specific findings, before pointing the toolchain at it as an audit target in the mini-project.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The challenge target is code you own. If you do not have a C1 or   │
│  C16 mini-project to audit, pick a Python repo under your own       │
│  GitHub account, or clone a public repo with a permissive licence   │
│  and audit your local copy read-only. Do not test findings against  │
│  any deployed service you do not operate.                           │
└─────────────────────────────────────────────────────────────────────┘
```

## Index

| Challenge | Time | Deliverable |
|---|---|---|
| [challenge-01-audit-your-c1-mini-project.md](./challenge-01-audit-your-c1-mini-project.md) | ~2 hours | Audit report covering Python-specific hazards in your own past code |

## How challenges differ from exercises and the mini-project

| Exercises | Challenge | Mini-project |
|---|---|---|
| Single hazard class, you write the vulnerable code | Real code you wrote, mixed hazards | Real code you wrote, full toolchain in CI, write-up artifact |
| ~45-60 min each | ~2 hours | ~7 hours |
| Demonstrates a single CWE end-to-end | Practises the audit *method* | Produces the portfolio audit |

The challenge is the *method* practice on your own code at a small scale; the mini-project is the *artifact* you publish.

## Submission

Commit the challenge as a directory in your `c6-week-05` repo:

```
challenge-01-audit-c1-mini-project/
    audit-report.md
    findings/
        F-01-pickle-import.md
        F-02-shell-true-subprocess.md
        ...
    notes/
        bandit-output.txt
        semgrep-output.txt
        pip-audit-output.txt
```

The audit report is the cover document; each finding is its own file in the standard format (title, hazard class, CWE, severity, location, proof-of-concept if applicable on the local clone only, remediation, references). The notes directory captures the raw tool output you used as evidence.

The challenge is the dress rehearsal for the mini-project. Treat it as a practice run with smaller scope.
