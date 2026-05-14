# Week 6 Homework

Six problems, ~6 hours total. Commit each in your Week 6 repo. The exercises were guided drills on single methods (pattern matching, checklist, model); the homework is closer to the daily work of an application-security engineer who lives in the PR queue.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Every problem targets public open-source PRs or synthesised        │
│  diffs. Reviews are study artifacts; do not file them upstream      │
│  unless the maintainers welcome that input. If a problem surfaces   │
│  what you believe is a real exploitable finding, follow Week 3's    │
│  coordinated-disclosure process. Do not exercise findings against   │
│  any deployed service.                                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Problem 1 — Author your personal review checklist (45 min)

Create `notes/hw1-review-checklist/review-checklist.md`. The file is your *personal* security-review checklist, starting from the C6 short checklist (Lecture 3 § 6) and extended with items you have found useful in Exercises 1-3 and Challenge 1.

The deliverable:

- The C6 short checklist (copied verbatim), grouped by section as in Lecture 3.
- At least **five personal additions**, each with a short justification (1-2 sentences) and a CWE / CVE / audit-report reference.
- A **"how I use this"** section (200 words) describing the order you walk the items, the time-budget per PR, the rule for `N/A` markings, and how often you update the checklist.
- A version line at the top (`v1.0`, `2026-05-13`) and a `Changelog` section reserved at the bottom.

**Acceptance.** The personal additions cite real references (CWE, CVE, or a published audit report). The "how I use this" section is operational, not aspirational. The checklist fits on one to three printed pages.

---

## Problem 2 — Triage a backlog of 20 PRs by the threat-modeling shortcut (1 hour)

Pick any active OSS Python project's PR queue (`pypa/pip`, `pallets/flask`, `django/django`, `psf/requests`, `tiangolo/fastapi`, or similar). Pull the **20 most-recent open PRs** with `gh pr list --repo OWNER/REPO --state open --limit 20 --json number,title,labels`.

For each PR, in a CSV file `notes/hw2-triage.csv`:

| PR# | Title | Cue 1 (new input) | Cue 2 (new outbound) | Cue 3 (auth/crypto) | Cue 4 (manifest) | Action |
|-----|-------|---|---|---|---|---|

- Each Cue column is `Y`, `N`, or `?`.
- Action is one of: `fast review` (~5 min), `slow review` (~30 min), `escalate` (needs a domain expert).

Time-box this to one hour total. The discipline is fast triage, not deep reading.

Then write `notes/hw2-triage-reflection.md` (~300 words):

- How many of the 20 went into each bucket?
- Did you find cues you would not have spotted without the framework from Lecture 1?
- Did you find a PR that surprised you (looked routine, hit a cue you did not expect)?

**Acceptance.** 20 rows in the CSV. Reflection explicitly names at least one PR per bucket and one surprise.

---

## Problem 3 — Reproduce the model-based review for the same hash-with-key PR (1 hour)

Re-do Exercise 3's model-based pass on the *team-invite* PR, but with the following additional constraint:

- **Without** consulting the worked answer in Exercise 3.
- **Without** consulting Lecture 3 (close the file).
- Time-box to 45 minutes; the last 15 minutes are reflection.

Write `notes/hw3-redo-model.md`:

- Your fresh model paragraph (input / sink / trust / validators / failure modes / impact).
- The findings list derived from the model.
- The findings the worked answer surfaced that *your* fresh model did not.
- The findings *your* fresh model surfaced that the worked answer did not.

**Acceptance.** The reflection is honest. It is normal for the second attempt to miss one or two findings the first attempt caught and to surface one or two new ones; the *delta* is the lesson.

---

## Problem 4 — Write a comment-by-comment review of a historical CVE-fix PR (1.5 hours)

Pick one of the historical fall-back PRs from Exercise 1 (or any *merged* PR that closed a Python CVE in 2022-2025). The PR's purpose is *to fix* a documented vulnerability; the review you write is the review that *should have caught the underlying bug at PR time*.

Suggested PRs:

- The `requests` fix for **CVE-2018-18074** — Authorization on cross-host redirect.
- The `urllib3` fix for **CVE-2023-43804** — Cookie on cross-host redirect.
- The `aiohttp` fix for **CVE-2024-23334** — static-route path traversal.
- The `Pillow` fix for any of the recent ImageMagick-adjacent CVEs.
- The `Django` fix for any state-changing CVE you can locate the patch commit for (every Django advisory has the commit link).

Write `notes/hw4-historical-pr-review/`:

- `target.md` — the PR, the CVE, the upstream advisory link.
- `pre-review-model.md` — the model *of the codebase before the fix*. Imagine you are reviewing the PR that *introduced* the bug; would you have caught it?
- `would-have-caught.md` — your honest answer to the above, 200-400 words. Citing the exact pattern / checklist item / model step that would have surfaced the finding pre-merge.

**Acceptance.** The retrospective is honest. "I would not have caught this" is a perfectly acceptable answer if justified (some bugs are subtle); the value is in identifying the gap and adding to your personal checklist.

---

## Problem 5 — Read and summarise one Trail of Bits public audit (1 hour)

Pick one Trail of Bits public audit from <https://github.com/trailofbits/publications> that targets a Python project, or one Trail of Bits blog post that walks an audit-style finding.

Read it cover-to-cover (or skim the methodology and read the top three findings in detail; whichever fits in 40 minutes). Then write `notes/hw5-tob-summary.md` (~500-700 words):

- The audit target (project, version, scope).
- The methodology used (model-based, checklist-based, fuzzing, formal, mixed).
- The top three findings — what they are, the CWE, the severity, the fix.
- What you learned about *review register* — how the auditor phrased the finding, what citations they used, the structure of the write-up.
- One thing you will adopt from the report's style in your own reviews.

**Acceptance.** The summary cites the report URL and the finding IDs. The "style adoption" is concrete (e.g., "I will always include a 'Recommended fix' subsection with a code suggestion, like the auditors did in Finding TOB-PIP-3").

---

## Problem 6 — Read one Project Zero post and write a review-register study (45 min)

Pick one Google Project Zero blog post from the last 18 months — any post from <https://googleprojectzero.blogspot.com/>. The post does not need to be Python; the methodology is universal.

Read it. Then write `notes/hw6-p0-register.md` (~400-600 words):

- The bug class (use-after-free, type confusion, OOB read, etc.; not all P0 bugs map to web CWEs).
- The root-cause analysis — how did the researcher arrive at the bug?
- The *register* of the write-up — what is the tone? How precise is the language? How are claims hedged or unhedged?
- One paragraph: how does Project Zero's register differ from a typical PR review comment? What — if anything — would you import into your PR-review register?

**Acceptance.** The summary cites the post URL. The register study is reflective (not just a recap of the bug).

---

## Submission

Commit all six in your `c6-week-06` repo under `notes/hw1-...` through `notes/hw6-...`. Push.

The mini-project follows. It is the synthesis of everything in Week 6 against a real, current, security-relevant OSS PR.
