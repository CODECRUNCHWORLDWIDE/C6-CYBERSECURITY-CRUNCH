# Challenge 1 — Audit an OSS PR

**Estimated time:** ~2 hours. `gh` CLI configured. Python 3.11. Local-only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Target a public open-source PR. Review it as a study artifact      │
│  for your portfolio. Do not file the review upstream unless         │
│  maintainers welcome that input (read CONTRIBUTING.md and           │
│  SECURITY.md). If a finding looks genuinely exploitable, follow     │
│  Week 3's coordinated-disclosure process — file privately, do not   │
│  publish a public PoC, give the maintainer reasonable time. Do      │
│  not exercise the finding against any deployed service.             │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

The exercises taught the method in pieces; the challenge runs the *whole* method against a real public PR in a single ~2-hour session. The PR is recent (or recently-merged) and security-relevant. The artifact is a Markdown review document plus the raw evidence — sufficient for a hiring manager to read in fifteen minutes and conclude "this candidate can sit in a review queue tomorrow."

This challenge covers:

- The full **Lecture 1 → 2 → 3 method** applied end-to-end.
- A **time-boxed** review (the discipline matters as much as the depth).
- Producing the **portfolio-shaped** artifact.

The mini-project is the longer, deeper, public-grade version of this exact exercise. The challenge is the rehearsal.

---

## Step 1 — Pick the target (15 min)

The target satisfies all of:

- **Python project**, hosted on GitHub.
- **Open-source**, with a public PR queue.
- **Recent or recently-merged PR** — within the last 12 months for liveness, older if you are reviewing a historical security-relevant PR as a study.
- **50-500 changed lines.**
- **Touches at least one trust-boundary cue** (Lecture 1 § 2.1).
- **Not the same PR you used in Exercise 1** — the point is to extend your reading set, not to re-litigate one PR.

If you struggle to find a current candidate, the historical fallback list is fine:

- **`requests` PR #5878 / advisories family** (CVE-2018-18074, CVE-2023-32681, CVE-2024-35195).
- **`urllib3` advisories family** (CVE-2023-43804, CVE-2023-45803).
- **`aiohttp` PR #7124** (CVE-2024-23334).
- **`Pillow` security fixes** — Pillow has an active CVE history; pick a recent one with a discrete PR.
- **`SQLAlchemy` PRs touching `text()` escape hatches** or query-string handling.
- **`Django` security PR backports** — the Django team publishes the patch commit for every advisory; treat as a study target.
- **`pip-audit` PRs** — Trail of Bits-maintained; the review register is itself instructive.

Record in `target.md`:

```markdown
# Target

- **Repo:** OWNER/REPO
- **PR:** #NNNN — <title>
- **URL:** https://github.com/OWNER/REPO/pull/NNNN
- **Files changed:** N
- **Lines:** +N / -N
- **State:** open / merged / closed
- **Why I picked this PR (1-2 sentences):** which trust-boundary cue does it
  match, what makes it interesting beyond the cue.
```

---

## Step 2 — Pull and prepare (10 min)

```bash
gh repo clone OWNER/REPO
cd REPO
gh pr checkout NNNN
gh pr view NNNN --comments > notes/gh-pr-view.txt
gh pr diff NNNN > notes/gh-pr-diff.txt
mkdir -p notes

# Optional but recommended — run the Week 5 toolchain on the PR branch
python3.11 -m venv .venv
source .venv/bin/activate
pip install bandit semgrep pip-audit
pip install -e .  2>&1 || echo "(install errors are common on big projects; the SAST still runs)"
bandit -r . 2>&1 | tee notes/bandit-pr.txt
semgrep --config p/python --config p/security-audit . 2>&1 | tee notes/semgrep-pr.txt
```

The tool output is **a hint, not a verdict**. You will reconcile tool output with your manual model in `pre-review-model.md`.

---

## Step 3 — Pre-review model (20 min)

Open `pre-review-model.md`. Use the same template as Exercise 1:

```markdown
# Pre-review model

## PR description (1-2 sentences)

## Trust-boundary cues (Lecture 1 § 2.1)

- [ ] New input source:
- [ ] New outbound call:
- [ ] Auth/session/crypto change:
- [ ] Dependency-manifest change:

## File-tree groupings

## Highest-risk file

## Model — input / sink / trust

## Pattern hits

## Checklist hits

## Open questions for the author
```

The model is **part of the deliverable**, even if the upstream never sees it. The discipline is more valuable than the document.

---

## Step 4 — Write the review (60 min)

Open `review.md`. Write the cover summary placeholder at the top; then go file-by-file on the highest-risk files first; then write each comment in the five-anchor format (Lecture 1 § 4); then return and complete the cover summary.

The challenge asks for **between four and ten comments**:

- **At least one finding** *or* an explicit reasoned approval if the PR is clean.
- **At least one design / model-based finding** (a finding pattern alone would miss). If the PR is so clean that no design finding applies, justify it in the cover summary.
- **At least one positive observation** (something the PR does *right*).

Template:

```markdown
# Review of PR #NNNN — <title>

**Reviewer:** <your handle>
**Date:** YYYY-MM-DD
**Method:** pattern matching + C6 short checklist + input/sink/trust model
**Tooling on PR branch:** bandit, semgrep p/python + p/security-audit, pip-audit

## Summary

3-5 sentences. The diff does X. I reviewed it for Y. I found N findings:
A blocking, B major, C minor, D nits. Recommended state: <approve /
request-changes / comment>.

## Findings table

| ID | Severity | CWE | Title | Location |
|----|----------|-----|-------|----------|
| F-1 | ... | ... | ... | ... |
| ... | ... | ... | ... | ... |

## Comments

### F-1 — [blocking] CWE-NNN — <title>

**Location:** `path/to/file.py:LINE`

**Hazard:** one sentence.

**Reference:** CWE-NNN, OWASP A0N, CVE-... (if applicable), Trail of Bits
or Project Zero post (if applicable).

**Suggestion:**

```suggestion
<the inline fix; or prose if structural>
```

**Severity:** `[blocking]` / `[major]` / `[minor]` / `[nit]` / `[question]`

**Why this bucket:** one sentence.

### F-2 — ...

(...)

## Positive observations

(1-3 bullets — what the PR gets right.)

## References

- CWE: <url>
- OWASP: <url>
- Trail of Bits / Project Zero post (if cited): <url>
- Upstream advisory (if cited): <url>
```

---

## Step 5 — Decision (10 min)

`decision.md`:

```markdown
# Decision

## State

approve / request-changes / comment

## Justification (3-5 sentences)

If approve: name what you checked and what you did not.
If request-changes: list the blocking findings by ID and severity.
If comment: state the open questions and why they preclude approval but
do not block merge.

## Counterfactual

(What would have moved the decision one notch.)
```

---

## Step 6 — Reflection (15 min)

Add a `reflection.md` (optional but strongly encouraged):

```markdown
# Reflection on Challenge 1

## What the method caught that I would not have caught freehand

(1-3 bullets.)

## What the method missed

(1-3 bullets — be honest. Did you miss a finding the upstream's existing review caught?
Did you over-flag a non-issue?)

## What I will change in my method for the mini-project

(1-3 bullets.)
```

The reflection is your *own* feedback loop. The mini-project benefits from running this loop now.

---

## Acceptance criteria

The challenge is complete when:

- [ ] `target.md` records the PR.
- [ ] `pre-review-model.md` is filled in.
- [ ] `review.md` has a cover summary, findings table, four to ten five-anchor
      comments, positive observations, and references.
- [ ] `decision.md` has the state, the justification, the counterfactual.
- [ ] At least one comment is a design / model-based finding (or the cover
      summary explicitly justifies why no such finding applies).
- [ ] Raw evidence (`gh pr view`, `gh pr diff`, optionally `bandit` /
      `semgrep` output) is captured in `notes/`.

The challenge is *stronger* if:

- [ ] You read at least two existing reviewer comments on the same PR before
      writing yours and noted what you would have added or disagreed with.
- [ ] You added at least one item to your **personal review checklist** based
      on something you noticed in this PR that the C6 short checklist did
      not cover.
- [ ] You included a `reflection.md`.

---

## What this challenge is *not*

- A graded scoring of "did you find the same findings as the upstream's reviewers?"
  The method is the assessment, not the count.
- An invitation to file public PoCs upstream.
- A search for a CVE — if you find one, file it via coordinated disclosure.

It is a working dress rehearsal for the mini-project, which is the real artifact.
