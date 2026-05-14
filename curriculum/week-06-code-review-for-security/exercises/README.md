# Week 6 — Exercises

Three hands-on exercises in reviewing pull requests. Each one walks a part of the review method against real or realistic PRs — first the full review against a real public PR (Exercise 1), then a fast pattern-matching drill on twelve diffs (Exercise 2), then a method-comparison against the same PR reviewed two ways (Exercise 3). The exercises feed the mini-project, which is a complete public security code review of a real OSS PR.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The targets of the exercises are public open-source PRs you have   │
│  a local clone of. Review them as a study artifact. Do not file     │
│  the review upstream unless the maintainers welcome that input;     │
│  read CONTRIBUTING.md and SECURITY.md before posting. If you find   │
│  a finding you believe is genuinely exploitable, follow Week 3's    │
│  coordinated-disclosure process: file privately, give the           │
│  maintainer reasonable time, do not publish a public PoC. Do not    │
│  exercise findings against any deployed service.                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Index

| Exercise | Method | Time | Deliverable |
|---|---|---|---|
| [exercise-01-review-a-real-pr.md](./exercise-01-review-a-real-pr.md) | Full review of a real public PR | 90 min | Cover summary + line-anchored comments + final-state decision |
| [exercise-02-spot-the-pattern.md](./exercise-02-spot-the-pattern.md) | Pattern-matching drill (Lecture 2) | 60 min | 12 diff hunks classified with CWE + comment |
| [exercise-03-checklist-vs-model.md](./exercise-03-checklist-vs-model.md) | Same PR reviewed two ways (Lecture 3) | 90 min | Two reviews + a comparison table |

## Setup — once per machine

```bash
# gh CLI authenticated to your GitHub account
gh auth status
gh auth login                                    # if not already

# Week 5 toolchain (re-used)
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install bandit semgrep pip-audit

# Verify
bandit --version
semgrep --version
pip-audit --version
gh --version
```

## How to run each exercise

Each exercise has at least one *real* or *realistic* PR diff as the target. You will read the diff, build a model (when applicable), pattern-match, walk a checklist, and write a review as a Markdown document.

The reviews are *study artifacts*. Do **not** file them upstream by default. The exercises that touch a real upstream PR explicitly say so.

## Submission

Commit each exercise as a directory in your `c6-week-06` repo:

```
exercise-01-review-a-real-pr/
    target.md                # which PR, why, the gh URL
    pre-review-model.md      # your model from Lecture 1 § 6.3
    review.md                # the full review: cover + comments
    decision.md              # approve / request-changes / comment + justification
exercise-02-spot-the-pattern/
    findings.md              # 12 entries; one per diff hunk
exercise-03-checklist-vs-model/
    review-checklist.md      # the checklist-only review
    review-model.md          # the model-only review
    comparison.md            # the side-by-side table + reflection
```

Each Markdown file is **short** — the discipline is brevity. Cover summaries are 200-400 words; per-comment text is 100-300 words. Reviewers who cannot say a finding briefly cannot say it at all.

The write-up is the artifact a hiring manager reads. The clone of the upstream PR is the evidence behind it.
