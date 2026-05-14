# Mini-Project — Full Security Code Review on a Real OSS PR

> Conduct a complete security code review of a real open-source pull request, comment-by-comment, with a public cover document, every finding in the five-anchor format, the input/sink/trust model written down, and the approve / request-changes / comment decision justified. The artifact, at the end, is the document a hiring manager reads alongside your Week 4 OWASP and Week 5 toolchain-audit outputs to answer the question "can this candidate sit in a PR-review queue tomorrow?"

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The mini-project target is a public open-source pull request.      │
│  The review is conducted on a local clone for portfolio purposes.   │
│                                                                     │
│  You may file the review upstream **only** if (a) the project's     │
│  CONTRIBUTING.md welcomes such input from non-maintainers, (b)      │
│  the review is constructive and respectful, and (c) you have read   │
│  the project's SECURITY.md and have routed any genuinely            │
│  exploitable finding via private coordinated disclosure instead     │
│  of via a public PR comment.                                        │
│                                                                     │
│  Do not exercise findings against any deployed service. Do not      │
│  publish public PoCs. If you discover a 0-day during this work,     │
│  follow the disclosure process from Week 3.                         │
└─────────────────────────────────────────────────────────────────────┘
```

This mini-project is the synthesis of Week 6. The lectures named the method (read, model, comment, decide). The exercises drilled each piece (real-PR review, pattern matching, checklist-vs-model). The challenge ran the whole method end-to-end at moderate depth. The mini-project does it at portfolio depth, on a real PR, with a public write-up that a future employer can read.

**Estimated time:** 7 hours, spread across Thursday-Saturday.

---

## 1. Pick the target PR

The target PR must satisfy all of:

- **Python project.** The method generalises, but Python is the lectures' baseline.
- **Open-source on GitHub.** Public repo, public PR queue.
- **Recent.** Open *or* merged within the last 6 months for liveness. Older is acceptable if you are reviewing a historical PR with a documented CVE outcome — that gives you a "ground truth" to compare against.
- **Security-relevant.** At least one of the trust-boundary cues from Lecture 1 § 2.1 (new input, new outbound, auth/session/crypto change, manifest change).
- **Medium-sized.** Roughly 100-1000 changed lines. Small PRs do not exercise the method; large PRs blow the budget.
- **Not previously reviewed in your portfolio.** Pick a PR you have not used in Exercises 1-3, Challenge 1, or Homework. The mini-project extends your reading set.

Strong candidate sources, in priority order:

1. **A PR in a project you depend on professionally** — the project you import in your day job, the framework you build on. Engagement compounds.
2. **A PR in a project you use personally** — the CLI tool you reach for, the library you love. Same reason.
3. **A recent security-related PR in a major project:**
    - `pypa/pip`, `pypa/pip-audit`
    - `psf/requests`, `urllib3/urllib3`, `encode/httpx`, `aio-libs/aiohttp`
    - `pallets/flask`, `pallets/werkzeug`, `tiangolo/fastapi`
    - `django/django`, `django/asgiref`
    - `cryptography/cryptography`, `pyca/pyca-cryptography`
    - `PyCQA/bandit`, `returntocorp/semgrep`
    - `python/cpython` (large but you can scope to one PR)
4. **A PR in a project you have audited in Week 5's mini-project** — meta-relevant, but be careful about double-counting.

If you have no internet access during the work, the historical fallback list is the same as Exercise 1 / Challenge 1; the methodology runs identically against a merged PR.

Record in `target.md`:

```markdown
# Target

- **Repo:** OWNER/REPO
- **PR:** #NNNN — <title>
- **URL:** https://github.com/OWNER/REPO/pull/NNNN
- **Author:** <handle>
- **Files changed:** N
- **Lines:** +N / -N
- **State:** open / merged / closed
- **Why I picked this PR (2-3 sentences):**
- **Trust-boundary cues triggered (Lecture 1 § 2.1):**
```

---

## 2. What you will produce

A public GitHub repo named `c6-week-06-pr-review-<yourhandle>` (or a subfolder of your portfolio repo) containing:

```
c6-week-06-pr-review-<yourhandle>/
    README.md                     # one-page intro: target, scope, summary, links
    target.md                     # PR identification (§ 1)
    pre-review-model.md           # the model, written down (§ 4)
    review.md                     # the comment-by-comment review (§ 5) — the centrepiece
    decision.md                   # approve / request-changes / comment + counterfactual (§ 6)
    review-checklist.md           # the personal checklist you used (your v1.0+)
    reflection.md                 # what you learned (§ 9)
    findings/
        F-01-<short-id>.md        # one file per finding (template in § 7)
        F-02-<short-id>.md
        ...
    notes/
        gh-pr-view.txt            # gh pr view NNNN raw
        gh-pr-diff.txt            # gh pr diff NNNN raw
        bandit-pr.txt             # bandit on PR branch (if applicable)
        semgrep-pr.txt            # semgrep on PR branch
        pip-audit-pr.txt          # pip-audit on PR branch (if applicable)
    LICENSE                       # GPL-3.0 (consistent with C6) or permissive
```

### The artifact shape

The centrepiece is `review.md` — the comment-by-comment review document. It should be **publishable as-is**: a reader who has the PR open in another tab can follow your review line-by-line and form an independent judgement.

The `findings/F-NN-*.md` files are the *audit trail* — one file per finding, in a standard format, citable from `review.md` and from your portfolio README.

---

## 3. The review method

### 3.1 Phase 0 — Setup (15 min)

```bash
gh auth status                                       # verify gh
gh repo clone OWNER/REPO
cd REPO
gh pr checkout NNNN
gh pr view NNNN --comments > notes/gh-pr-view.txt
gh pr diff NNNN              > notes/gh-pr-diff.txt
mkdir -p notes findings

python3.11 -m venv .venv
source .venv/bin/activate
pip install bandit semgrep pip-audit
pip install -e . 2>&1 || echo "(install errors common on large projects)"

bandit -r . 2>&1 | tee notes/bandit-pr.txt
semgrep --config p/python --config p/owasp-top-ten \
        --config p/security-audit --config p/secrets \
        . 2>&1 | tee notes/semgrep-pr.txt
pip-audit -r requirements.txt 2>&1 | tee notes/pip-audit-pr.txt  # if applicable
```

### 3.2 Phase 1 — Pre-review model (45 min)

Write `pre-review-model.md` *before* writing any comments. Use the Lecture 1 § 6.3 template (also in Exercise 1 § 3 and Challenge 1 § 3). The model is approximately 400-700 words.

The model is the spine of the review. Findings that do not appear in the model are findings you have not reasoned through; findings that appear in the model but not in the review document are findings you spotted and then forgot to write up.

### 3.3 Phase 2 — Checklist walk (30 min)

Open `review-checklist.md` (your personal version, evolved from Homework Problem 1). Walk every item. Record `✓` / `✗` / `N/A` with a one-sentence justification per ✗.

This phase produces the *omission* findings — the things the diff forgot to do that the checklist remembered.

### 3.4 Phase 3 — Pattern-matching pass (30 min)

Re-read the diff with Lecture 2's pattern catalogue in mind. Annotate hunks in `notes/diff-annotated.txt` (or in scratch margins on the GitHub UI). Flag every pattern hit, even ones the checklist already caught — the *redundancy* is the point.

This phase produces the *syntactic* findings.

### 3.5 Phase 4 — Model-based deep read (60 min)

Re-read the highest-risk files with the model open. For each input → sink path, trace the validators; for each validator, ask "what is its failure mode and what does the failure do?" (Lecture 3 § 2).

This phase produces the *design* findings — the ones a pattern-matcher and a checklist alone would miss.

### 3.6 Phase 5 — Reconcile (30 min)

Compare the three passes' findings. De-duplicate. Triage each finding into:

- **Confirmed finding** — write a `findings/F-NN-*.md` file.
- **False positive from a tool** — note it as such; if a `# nosec` / `# nosemgrep` would be the right response in the project, draft the annotation.
- **Open question** — write the finding as `[question]` for the author.

### 3.7 Phase 6 — Write the review (90 min)

Compose `review.md`:

1. Cover summary (250-500 words).
2. Findings table.
3. Per-finding comments in the five-anchor format, ordered by severity then by file location.
4. Positive observations (1-3 bullets).
5. References (CWE / OWASP / Trail of Bits / Project Zero links).

Compose each `findings/F-NN-*.md` (template in § 7 below) — one file per finding.

### 3.8 Phase 7 — Decision and reflection (30 min)

Write `decision.md` (template in § 8 below).

Write `reflection.md` (template in § 9 below).

### 3.9 Phase 8 — Polish and push (30 min)

Re-read the entire `review.md` once aloud (literally — read it out loud or in a TTS engine). Catch:

- Anything that names a specific person in a critical way (remove).
- Anything that asserts a finding you are not confident on (downgrade to `[question]`).
- Anything that links to a CVE for emphasis when the cited CVE is not the same shape (remove).
- Anything in the register "you should..." when it could be "the diff could..." (rephrase; the criticism is of code, not of the author).

Commit, push, link from your portfolio README.

---

## 4. Pre-review model template

`pre-review-model.md`:

```markdown
# Pre-review model — PR #NNNN

## PR description (1-2 sentences)

What the author says the PR does.

## Trust-boundary cues (Lecture 1 § 2.1)

- New input source: <yes/no/partial — describe>
- New outbound call: <yes/no/partial — describe>
- Auth/session/crypto change: <yes/no/partial — describe>
- Dependency-manifest change: <yes/no/partial — describe>

## File-tree groupings

- <Subsystem 1>: <which files, 1-2 sentences>
- <Subsystem 2>: ...
- Tests: <which files>
- Docs: <which files>

## Highest-risk file (1-2 sentences)

Which one file is most likely to contain the bug, and why.

## Model — input / sink / trust

### Input sources (post-diff)

(bulleted list — every place data enters the program after this diff lands)

### Output sinks (post-diff)

(bulleted list — every place data leaves the program or causes effects)

### Trust levels of each input

(bulleted list — fully untrusted / partly trusted / trusted, with justification)

### Validators on each input → sink path

(bulleted list — every validator that runs between input and sink)

### Failure modes of each validator

(bulleted list — for each validator, what bypasses it)

### Impact of each failure

(bulleted list — what an attacker achieves if a validator fails)

## Pattern hits (from Lecture 2 pass)

(bulleted list — every pattern that fired, with file:line)

## Checklist hits (from C6 short checklist + your personal additions)

(bulleted list — every ✗ item, with file:line)

## Open questions for the author

(1-5 bullets — questions you would like answered before approving)
```

The model should be **400-800 words**. Longer is fine if the diff is large; shorter is a sign you are not modelling.

---

## 5. The review document — the centrepiece

`review.md`:

```markdown
# Review of PR #NNNN — <title>

**Reviewer:** <your handle>
**Date:** YYYY-MM-DD
**Method:** pattern matching + personal checklist (vX.X) + input/sink/trust model
**Tooling on PR branch:** bandit vX.X, semgrep (p/python, p/owasp-top-ten,
                          p/security-audit, p/secrets), pip-audit vX.X

## Summary

(250-500 words. The diff does X. I reviewed it for Y. I found N findings —
A blocking, B major, C minor, D nits. My recommended state is:
approve / request-changes / comment.)

The summary should mention:
- The top finding by severity and its CWE.
- The most-interesting model-based finding (the one a pattern-matcher
  would miss).
- The PR's strongest aspect (positive observation).
- The counterfactual for the decision (what would have moved it one notch).

## Findings table

| ID | Severity | CWE | Title | Location | Status |
|----|----------|-----|-------|----------|--------|
| F-01 | blocking | CWE-... | ... | path/to/file.py:LINE | Open |
| F-02 | major | CWE-... | ... | path/to/file.py:LINE | Open |
| ... | ... | ... | ... | ... | ... |

## Comments

(Per-finding five-anchor blocks in order of severity then file location;
see template below.)

### F-01 — [blocking] CWE-NNN — <Short title>

**Location:** `path/to/file.py:LINE` ([anchor link to the PR-blamed line](https://github.com/OWNER/REPO/pull/NNNN/files#diff-...-LNN))

**Hazard:** one to two sentences naming the vulnerability class and the
exploitation path.

**Reference:**
- CWE-NNN: <https://cwe.mitre.org/data/definitions/NNN.html>
- OWASP A0N:2021 (if applicable): <url>
- CVE-YYYY-NNNN (if same-shape precedent): <NVD url>
- Trail of Bits / Project Zero / NCC / Cure53 post (if applicable): <url>

**Evidence:**

```python
# 3-8 lines of the offending code with file:LINE annotation.
```

**Suggestion:**

```suggestion
<the inline fix; or prose if structural>
```

**Severity:** `[blocking]` — one sentence on why this bucket.

**See also:** `findings/F-01-<short-id>.md` for the full record.

### F-02 — ...

(...)

## Positive observations

1. <One thing the PR gets right — e.g., uses `pydantic` for input
   validation throughout, ships tests for the negative paths,
   correctly applies `hmac.compare_digest`, etc.>
2. <...>
3. <...>

## References

- OWASP Code Review Guide v2: <https://owasp.org/www-project-code-review-guide/>
- OWASP Top 10 (2021): <https://owasp.org/Top10/>
- CWE Top 25 (2024): <https://cwe.mitre.org/top25/>
- Trail of Bits public audits: <https://github.com/trailofbits/publications>
- Google Project Zero: <https://googleprojectzero.blogspot.com/>
- (Any project-specific references — the upstream's CONTRIBUTING.md,
  SECURITY.md, prior advisories.)
```

The review document is **the artifact** for the portfolio. It must be readable in fifteen minutes by an unfamiliar reader and convey:

1. What the PR does.
2. What you found.
3. Why the decision is what it is.

Short, dense, citation-heavy. The five-anchor format does the work.

---

## 6. The decision document

`decision.md`:

```markdown
# Decision on PR #NNNN

## State

approve / request-changes / comment

## Justification

3-6 sentences. If approve: name what you checked and what you did not.
If request-changes: list the blocking findings by ID. If comment:
state the open questions and why they preclude approval but do not
block merge.

## Counterfactual

What would have moved the decision one notch in either direction.

- "If I approved, what would have made me request changes?"
- "If I requested changes, what minimal patch would let me re-review
  to approve?"
- "If I commented, what additional information from the author would
  flip the decision?"

## Disclosure routing (if applicable)

If a finding here is potentially a 0-day, *the public review document
does not contain it*. The disclosure path is:

- File privately with the project's `SECURITY.md` reporting channel.
- Note in this file: "Finding F-NN was routed via private disclosure on
   YYYY-MM-DD; details withheld from the public review pending the
   project's disclosure timeline."
- Do not publish a PoC.

If no finding qualifies for private disclosure, write "N/A" here.

## Sign-off

I have reviewed PR #NNNN end-to-end against the method documented in
Week 6 of C6 Cybersecurity Crunch. This review is a public study
artifact; it represents my opinion based on the diff as of commit
<HASH>, and does not constitute professional security advice.

— <handle>, YYYY-MM-DD
```

The disclosure-routing paragraph is the most important non-obvious item. It is the difference between a portfolio that hiring managers can publish without legal risk and one they cannot.

---

## 7. The finding template

Every file in `findings/` follows the template below. Numbered `F-01` through `F-NN`, sorted by severity then by location.

```markdown
# F-NN — <Short, specific title>

| Field | Value |
|---|---|
| Hazard class | <e.g. Server-side Request Forgery> |
| CWE | CWE-NNN |
| OWASP 2021 | A0N — <name> |
| CVE precedent | CVE-YYYY-NNNN (if applicable) |
| Reporter | <your handle> |
| Date | YYYY-MM-DD |
| PR | OWNER/REPO#NNNN |
| Commit reviewed | <hash> |
| Severity (reviewer) | Low / Medium / High / Critical |
| Confidence | Low / Medium / High |
| Location | `path/to/file.py:LINE-LINE` |
| Tool that flagged (if any) | bandit BNNN / semgrep <rule-id> / manual |
| Status | Open / In progress / Fixed (#NNN) / Won't fix / Disclosed privately |

## Description

One-to-three paragraphs. What the bug is, anchored to the line.
Cite the relevant Week 6 lecture section. State the assumption
the diff makes that does not hold under attack.

## Evidence

```python
# 3-8 lines of the offending code with file:LINE annotation.
```

## Trust model

Where does the input come from? Where does it reach a sink? Which
trust boundary is crossed without validation?

## Proof-of-concept (if applicable; local only)

If the bug is exploitable end-to-end in a local clone, describe the
PoC in prose. Do **not** provide a working exploit string against a
deployed service.

```
# A safe PoC against a local instance:
curl -X POST http://127.0.0.1:5000/... -d '<payload>'
```

If the finding is "supply-chain CVE in a transitive dep," no PoC is
needed — cite the upstream OSV / GHSA entry.

## Remediation

The patch, anchored to lines. Either a diff snippet or a prose
description of the fix shape (allow-list / parameterised / HMAC /
schema / etc.).

```python
# Suggested fix:
...
```

## References

- Week 6 Lecture N, Section X.
- CWE-NNN: <url>
- OWASP cheat sheet (if applicable): <url>
- CVE-YYYY-NNNN: <url>
- Trail of Bits / Project Zero (if applicable): <url>
- Upstream advisory / fix commit (if applicable): <url>

## History

- YYYY-MM-DD — found via <method: model / checklist / pattern / tool>.
- YYYY-MM-DD — triaged: <bucket>.
- YYYY-MM-DD — communicated upstream: <channel> (if applicable).
- YYYY-MM-DD — fixed in <commit/PR>.
```

The finding file is the audit-trail artifact. A reader can pick *one* finding and read its full record without having to also read the cover review.

---

## 8. Audit-report (cover) structure

The cover for the mini-project is `review.md` (§ 5 above), supplemented by `README.md` at the repo root:

```markdown
# C6 Week 6 — Security Review of PR #NNNN

**Target:** [OWNER/REPO#NNNN](https://github.com/OWNER/REPO/pull/NNNN)
**Reviewer:** <your handle>
**Date:** YYYY-MM-DD
**State recommended:** approve / request-changes / comment

## Summary

3-5 sentences. The headline finding. The count by severity. The
decision.

## How to navigate

- [target.md](./target.md) — the PR identification.
- [pre-review-model.md](./pre-review-model.md) — the input/sink/trust
  model.
- [review.md](./review.md) — **the comment-by-comment review (start here)**.
- [decision.md](./decision.md) — the approve / request-changes / comment
  decision and counterfactual.
- [review-checklist.md](./review-checklist.md) — the personal checklist used.
- [reflection.md](./reflection.md) — what I learned.
- [findings/](./findings/) — one file per finding (audit trail).
- [notes/](./notes/) — raw `gh pr view` / `gh pr diff` / tool output.

## Method

This review applied:

1. The Lecture 1 four-cue threat-modeling shortcut for pre-review triage.
2. The Lecture 2 pattern catalogue for the syntactic-cue pass.
3. The Lecture 3 C6 short checklist (extended with my personal additions).
4. A written input/sink/trust model (Lecture 3 § 2) for the design pass.

Each finding is in the five-anchor format (Lecture 1 § 4).

## Disclosures

(N/A if no private disclosure; otherwise: "Finding F-NN was routed
privately on YYYY-MM-DD; details are withheld from this public document
pending the project's disclosure timeline.")

## License

The review text is GPL-3.0 (consistent with C6). The PR contents
remain under the upstream project's license.
```

---

## 9. Reflection

`reflection.md` (300-500 words):

```markdown
# Reflection

## What the method caught

(What did the four-step method — cues + pattern + checklist + model —
catch that you would not have caught freehand? Be specific; cite
finding IDs.)

## What the method missed

(What did the method miss? Did an upstream reviewer flag something
you did not? Did a test in the PR cover a behaviour your model did
not consider? Be honest.)

## What I will change in my method

(For the next PR review, what one to three changes will you make to
your personal checklist, your model framing, or your time budget?)

## What I will change about my own code

(Did reading this PR reveal a pattern *you* use in your own code that
you now want to revisit? This is often the highest-leverage outcome of
review work.)

## Citations

(Any specific Trail of Bits / Project Zero / NCC / Cure53 / OWASP / CVE
references that informed the review beyond what review.md already cited.)
```

The reflection is the most-cited section in a hiring-manager skim. It demonstrates the *meta*-skill: the ability to evaluate your own review work and improve it.

---

## 10. Acceptance criteria

The mini-project is complete when **all** of the following are true:

- [ ] Target PR identified in `target.md` with URL, files, lines, state, and the trust-boundary cues triggered.
- [ ] `pre-review-model.md` filled in following § 4 template, 400-800 words.
- [ ] `review.md` (the centrepiece) contains:
   - Cover summary (250-500 words).
   - Findings table.
   - At least **three** five-anchor comments — **or** an explicit reasoned approval if the PR is clean (the cover summary must justify the absence of findings).
   - At least **one** design or model-based finding (a finding pattern-matching alone would miss).
   - At least **one** positive observation.
- [ ] `findings/F-NN-*.md` files exist for every confirmed finding, in the standard template (§ 7).
- [ ] `decision.md` filled in with state, justification, counterfactual, disclosure routing.
- [ ] `review-checklist.md` (personal) committed at the version used.
- [ ] `reflection.md` filled in following § 9 template, 300-500 words.
- [ ] `notes/` contains the raw tool output and `gh` output.
- [ ] The repo (or portfolio subfolder) is public.
- [ ] The portfolio README links the review.

The mini-project is *stronger* if additionally:

- [ ] The review was *also* filed upstream (only if the project welcomes external review and you respected CONTRIBUTING.md / SECURITY.md), and the upstream's reply is captured in `notes/upstream-response.txt`.
- [ ] At least one finding was disclosed privately via the project's `SECURITY.md` channel because it appeared genuinely exploitable, and the public review document elides the detail per the disclosure protocol.
- [ ] You compared your findings against another C6 learner's review of the same PR; the disagreement set is documented in a `pair-review.md` file.
- [ ] You added at least two items to your `review-checklist.md` based on patterns observed in this PR that were not in your previous checklist.

---

## 11. Submission

1. Push the public repo (or portfolio subfolder).
2. Add a link to `review.md` from your portfolio README's Week 6 entry.
3. Link the four artifacts side by side in your portfolio:
    - Week 4 — OWASP Top 10 patch artifact.
    - Week 5 — Toolchain audit of your own code.
    - Week 6 — Security review of a real OSS PR (this artifact).
    - Together, they are *the* Python application-security portfolio piece a hiring manager wants to read in their lunch break.

---

## 12. Common pitfalls

- **Approve to clear the queue.** Do not. Comment if you are not certain. Use Request changes the moment one blocking finding exists.
- **Too many comments.** A review with twenty `[nit]` comments and zero `[blocking]` comments is a *bad* review. Triage your time.
- **Citation-free comments.** Every security comment cites a CWE or a CVE or an audit-report finding. "I think this is bad" is not a comment.
- **Pattern-match without context.** Some `pickle.loads` calls are correct. Read the surrounding ten lines before commenting.
- **Skip the model.** On any PR that touches auth, crypto, deserialisation, or trust boundaries, build the model. The design findings live there.
- **Public PoC of a private bug.** If a finding is potentially a 0-day, file it via `SECURITY.md` first; the public review elides the detail.
- **Tone-attack the author.** The review is of the code, not the author. Use the passive voice or refer to the diff, not the developer.

---

## 13. Stretch — once the core is shipped

- **Pair-review.** Coordinate with another C6 learner; both review the same PR independently, then meet to compare. The disagreement set is the most valuable artifact of the exercise.
- **Replay the review against a Trail of Bits public audit.** Pick a Trail of Bits public report covering a Python project, write a review using the *Week 6 method*, and compare against the *Trail of Bits findings*. The delta is your gap.
- **Build a `semgrep` custom rule** for any pattern you found in this PR that was not in the registry. Commit to `.semgrep/rules/<rule-id>.yml` with a justification. Open-source the rule.
- **Run the review against a *historical* fix-PR for a known CVE.** "Would my review have caught this CVE at PR time?" is the most useful retrospective an early-career security engineer can do; do it ten times across a year and your method is calibrated.
- **Annotate the upstream's existing review comments** with your own assessment in a `notes/upstream-review-annotation.md` file. Where did the upstream reviewers see what you missed? Where would you have added a comment they did not? This is meta-review; it is how senior security engineers grow.
- **Configure a `semgrep` CI workflow** for a repo of your own that mirrors the rules you wished the upstream had. Commit `.github/workflows/security-review.yml` to your portfolio with a justification.

---

## 14. Why this is the artifact

A working-quality application-security engineer can take an unfamiliar Python pull request on Monday morning and, by lunch, produce: a written model of the diff's trust boundaries, a triaged finding list with CWE citations, a structured review document with a clear decision, and a private disclosure if warranted. The Week 6 mini-project is *that exact deliverable*, on a real public PR, with the artifact a hiring manager can read alongside your Week 4 OWASP and Week 5 toolchain-audit outputs. Together, the three documents answer the only question that matters in a job-interview review:

> "Can this candidate sit in our PR-review queue tomorrow morning and not approve a `pickle.loads` to production?"

Build the artifact. Push it. Link it from your portfolio. Move on to Week 7.
