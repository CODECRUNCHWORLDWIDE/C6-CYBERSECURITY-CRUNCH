# Week 6 — Challenges

One scoped challenge this week. The exercises trained the method on synthesised and real PRs at moderate depth; the mini-project will produce the full, publishable review. The challenge is the bridge — an additional, scoped review of a real OSS PR that exercises the full method (pattern + checklist + model) end-to-end in ~2 hours, *before* the multi-hour mini-project.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The challenge target is a public open-source PR. You review it     │
│  as a study artifact. Do not file the review upstream unless the    │
│  maintainers welcome that contribution (read CONTRIBUTING.md and    │
│  SECURITY.md first). If a finding looks like a real exploitable     │
│  vulnerability, follow Week 3's coordinated-disclosure process;     │
│  do not publish a public PoC. Do not exercise findings against      │
│  any deployed service.                                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Index

| Challenge | Time | Deliverable |
|---|---|---|
| [challenge-01-audit-an-OSS-PR.md](./challenge-01-audit-an-OSS-PR.md) | ~2 hours | Full security review of a real OSS PR — model, comments, decision, posted as a Markdown document |

## How challenges differ from exercises and the mini-project

| Exercises | Challenge | Mini-project |
|---|---|---|
| Single method or warm-up drill | Full method (pattern + checklist + model) end-to-end | Full method + portfolio-grade write-up + (optional) upstream contribution |
| 60-90 min each | ~2 hours | ~7 hours |
| Synthesised or real targets | Real OSS PR, recent or merged | Real OSS PR, recent, security-relevant |
| Demonstrates one technique | Demonstrates the *combination* | Produces the *artifact* |

The challenge is the dress rehearsal for the mini-project. Treat it as a practice run with smaller scope: one real PR, ninety minutes of focused work, the full method.

## Submission

Commit the challenge as a directory in your `c6-week-06` repo:

```
challenge-01-audit-an-OSS-PR/
    target.md                  # which PR, why, the URL
    pre-review-model.md        # the model from Lecture 1 § 6.3
    review.md                  # the review document (cover + comments)
    decision.md                # approve / request-changes / comment
    notes/
        gh-pr-view.txt         # `gh pr view NNNN` raw output
        gh-pr-diff.txt         # `gh pr diff NNNN` raw output
        bandit-pr.txt          # bandit on the PR branch (if applicable)
        semgrep-pr.txt         # semgrep on the PR branch
```

The review document is the cover; each finding is in the five-anchor format. The notes directory captures the raw evidence you triaged the findings against.

The challenge is the *artifact you can show to a friend the same evening*. The mini-project is the artifact you put on a portfolio. Both are public; the difference is polish and depth.
