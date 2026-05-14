# Exercise 1 — Review a Real Public PR

**Estimated time:** 90 minutes. `gh` CLI configured. Python 3.11. Local-only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The target PR is public. You clone it for local review only. The   │
│  review you produce in this exercise is a study artifact for your   │
│  portfolio. Do not file the review upstream unless the maintainers  │
│  explicitly welcome that contribution (read CONTRIBUTING.md and     │
│  SECURITY.md first). If you find what you believe is a real         │
│  vulnerability, follow Week 3's coordinated-disclosure path. Do     │
│  not run exploit code against any deployed service.                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You are the security reviewer on rotation for an open-source Python project. A pull request lands in your queue. You have approximately ninety minutes to read it, model it, comment on it, and decide approve / request-changes / comment.

This exercise covers:

- The **PR-level threat-modeling shortcut** (Lecture 1, § 2).
- The **two-pass review** (Lecture 1, § 3).
- The **five-anchor comment format** (Lecture 1, § 4).
- The **approve / request-changes / comment** decision (Lecture 1, § 5).
- All three of pattern matching (Lecture 2), checklist (Lecture 3), and model (Lecture 3) at appropriate depth.

---

## Step 1 — Pick the target (10 min)

The right target is a **medium-sized, recent, security-relevant PR** in a Python project you have at least passing familiarity with. Criteria:

- **Python.** The lectures and patterns are Python-flavoured; pick Python for this exercise.
- **Open-source, public.** Hosted on GitHub or GitLab, with public PR access.
- **Medium size.** Roughly 50–500 changed lines. Smaller and the exercise is too thin; larger and the budget will overrun.
- **Security-relevant or auth-adjacent.** Touches at least one of the trust-boundary cues from Lecture 1 § 2.1: a new input source, a new outbound call, a change to auth / session / crypto, or a dependency-manifest change.
- **Not already closed.** An open PR (in review) gives you the live state; a merged PR is acceptable if you treat it as an after-the-fact review.

Suggested project sources (no specific PR — you pick a current candidate from the queue):

- **PyPA / pip:** <https://github.com/pypa/pip/pulls> — packaging tools, supply-chain-relevant.
- **PyPA / pip-audit:** <https://github.com/pypa/pip-audit/pulls> — Trail of Bits-maintained.
- **PSF / requests:** <https://github.com/psf/requests/pulls> — HTTP client; SSRF / TLS history.
- **urllib3:** <https://github.com/urllib3/urllib3/pulls>.
- **pallets / flask:** <https://github.com/pallets/flask/pulls>.
- **pallets / werkzeug:** <https://github.com/pallets/werkzeug/pulls>.
- **encode / httpx:** <https://github.com/encode/httpx/pulls>.
- **tiangolo / fastapi:** <https://github.com/tiangolo/fastapi/pulls>.
- **django / django:** <https://github.com/django/django/pulls> — large, but you can scope to one PR.
- **aio-libs / aiohttp:** <https://github.com/aio-libs/aiohttp/pulls>.
- **psf / black:** <https://github.com/psf/black/pulls> — tooling; sometimes touches subprocess.
- **PyCQA / bandit:** <https://github.com/PyCQA/bandit/pulls> — meta-relevant.

Open the project's PR queue. Filter or search for `label:security`, recent activity, or PRs with a green checkmark next to security-relevant terms in the title (`auth`, `tls`, `cert`, `cookie`, `session`, `header`, `redirect`, `escape`, `sanitize`, `parse`).

If you cannot find a current PR that meets the criteria, use one of these *historical* PRs as a fallback (all merged; review them as after-the-fact study):

- **`requests` PR #5878** (CVE-2018-18074 fix family — Authorization header on redirect).
- **`urllib3` PR #2727** (CVE-2023-43804 family — Cookie leak on redirect).
- **`aiohttp` PR #7124** (CVE-2024-23334 — static-route path traversal).
- **`pip` PR #11099** (lockfile / install discipline).
- **`Flask` PR #5126** (session-cookie attribute fix).

Record in `target.md`:

```markdown
# Target

- **Repo:** OWNER/REPO
- **PR:** #NNNN — <title>
- **URL:** https://github.com/OWNER/REPO/pull/NNNN
- **Files changed:** N
- **Lines:** +N / -N
- **State:** open / merged / closed
- **Why this PR:** which trust-boundary cue from Lecture 1 § 2.1
   does it match, in one sentence.
```

---

## Step 2 — Clone and prepare (10 min)

```bash
# Authenticate gh if not done
gh auth status

# Pull the PR locally
gh repo clone OWNER/REPO
cd REPO
gh pr checkout NNNN

# Read the PR description
gh pr view NNNN --comments

# Pull the diff into a scratch file
gh pr diff NNNN > /tmp/pr-NNNN.diff
wc -l /tmp/pr-NNNN.diff

# Optional — run the Week 5 toolchain on the PR branch
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .                                    # if the project supports it
pip install bandit semgrep pip-audit
bandit -r . > /tmp/bandit-pr.txt 2>&1               # if applicable
semgrep --config p/python --config p/security-audit . > /tmp/semgrep-pr.txt 2>&1
```

The tool output goes in your `pre-review-model.md` notes; treat it as a *hint*, not a verdict.

---

## Step 3 — First pass: structure (10 min)

Write `pre-review-model.md` *before* writing any comments. The model is the spine of the review.

Cover, in order:

```markdown
# Pre-review model

## PR description (1-2 sentences)

What does the author say the PR does?

## Trust-boundary cues (Lecture 1 § 2.1)

- [ ] New input source: <yes/no, what>
- [ ] New outbound call: <yes/no, what>
- [ ] Auth/session/crypto change: <yes/no, what>
- [ ] Dependency-manifest change: <yes/no, what>

## File-tree groupings (1-3 sentences each)

- Auth subsystem: <which files>
- Parser / IO: <which files>
- Tests: <which files>
- Docs: <which files>

## Highest-risk file (1 sentence)

Which one file is most likely to contain the bug, and why.

## Model — input / sink / trust

In bullet form:

- **Input sources, post-diff:**
- **Output sinks, post-diff:**
- **Trust levels (untrusted / semi / trusted):**
- **Validators on the path:**
- **Failure modes of each validator:**

## Pattern hits

What pattern-matches fired on the second-pass read (Lecture 2 patterns).

## Checklist hits

Which checklist items (Lecture 3 § 6) flagged unchecked.

## Open questions for the author

Three bullet points maximum.
```

The pre-review model is **part of the submission**, even if you do not file it upstream. The discipline is the artifact.

---

## Step 4 — Second pass: write the comments (40 min)

Open `review.md`. Write the cover summary at the top (you will fill the findings list after the comments). Then go file-by-file on the highest-risk files first.

For each comment, use the five-anchor format:

```markdown
### F-NN — <severity tag> — <CWE or hazard name>

**Location:** `path/to/file.py:LINE` (link to the PR-anchored line)

**Hazard:** one sentence.

**Reference:** CWE-NNN, OWASP A0N, CVE-... (if applicable), Trail of
Bits / Project Zero / NCC post (if applicable).

**Suggestion:**

```suggestion
<the inline fix, or a prose description if the fix is structural>
```

**Severity:** `[blocking]` / `[major]` / `[minor]` / `[nit]` / `[question]`

**Why this bucket:** one sentence.
```

The exercise asks for **between three and eight comments**. Fewer than three suggests the PR is genuinely clean (which is a finding in itself — write the cover summary as "I found no security-relevant issues" with the model that justifies the conclusion); more than eight suggests you have not triaged the noise.

Comments must include at least one of each:

- **At least one design or model-based finding** (a finding pattern alone would not catch). If the PR is so clean that no design finding applies, explicitly justify in the cover summary.
- **At least one positive observation** (a thing the PR does *right* and the author should know is recognised). This is part of good-faith review.

---

## Step 5 — Decision (10 min)

Write `decision.md`:

```markdown
# Decision

## State

approve / request-changes / comment

## Justification

3-5 sentences. If approve: name what you checked and what you did not.
If request-changes: list the blocking findings. If comment: state the
open questions and why they preclude approval but do not block merge.

## Counterfactual

What would have moved the decision one notch in either direction. (If
you approved, what would have made you request changes? If you
requested changes, what minimal patch would let you re-review to
approve?)
```

The counterfactual is the discipline: it forces the reviewer to know *where the bar is*, not just that the PR passed or failed.

---

## Step 6 — Cover summary (10 min)

Open `review.md` and write the cover summary at the top:

```markdown
# Review of PR #NNNN — <title>

**Reviewer:** <your handle>
**Date:** YYYY-MM-DD
**Method:** pattern matching + checklist + model (see pre-review-model.md)
**Tooling run on PR branch:** bandit, semgrep `p/python` + `p/security-audit`, pip-audit

## Summary

3-5 sentences. The diff does X. I reviewed it for Y. I found N
findings: A blocking, B major, C minor. The state is: approve /
request-changes / comment.

## Findings

| ID | Severity | CWE | Title | Location |
|----|----------|-----|-------|----------|
| F-1 | blocking | CWE-... | ... | path/to/file.py:L |
| F-2 | ... | ... | ... | ... |
...

## Comments

(F-NN entries from Step 4, in order.)

## Positive observations

(1-3 bullets — what the PR gets right.)

## References

- CWE: <url>
- OWASP: <url>
- Trail of Bits / Project Zero post (if cited): <url>
- Upstream advisory (if cited): <url>
```

---

## Step 7 — Optional: replay the review with `gh` (10 min)

If the PR is open and the upstream welcomes external review (check CONTRIBUTING.md), you *may* post the review as comments via the GitHub web UI. **Do this only after** a final pass over your `review.md` looking for:

- Anything that names a specific person in a critical way (delete; reviews are about code).
- Anything that asserts a finding you are not confident on (downgrade to `[question]`).
- Anything that links to a CVE for emphasis when the cited CVE is *not* the same shape (remove).

The default — for the exercise — is to **not** file upstream. The local artifact is the deliverable.

If you do file, post the cover summary as the PR-level review body and each F-NN as a line-anchored comment via the "Files changed" tab.

---

## Acceptance criteria

The exercise is complete when:

- [ ] `target.md` records the PR (URL, files, lines, state, why).
- [ ] `pre-review-model.md` contains the pre-review model template, filled in.
- [ ] `review.md` contains a cover summary, a findings table, and three to eight five-anchor comments.
- [ ] `decision.md` contains the approve / request-changes / comment decision with justification and counterfactual.
- [ ] At least one finding is a design or model-based finding (a pattern-matcher alone would not surface).
- [ ] At least one positive observation is included.
- [ ] All four documents fit on one screen each when rendered (the discipline is brevity).

The exercise is *stronger* if:

- [ ] You ran `bandit` + `semgrep` on the PR branch and reconciled tool output with the model — flagging false positives and missing-from-tool findings explicitly.
- [ ] You read at least two other comments / reviews on the same PR before writing yours, and you note what you would have added or disagreed with.
- [ ] You picked a PR you genuinely care about (a project you depend on); the engagement compounds.

---

## What this exercise is *not*

- It is **not** an excuse to file low-quality reviews upstream.
- It is **not** a forum to argue with maintainers about style.
- It is **not** a search for a CVE — if you happen to find one, file it via coordinated disclosure, not via this exercise.

It is a study drill. The artifact is the deliverable.
