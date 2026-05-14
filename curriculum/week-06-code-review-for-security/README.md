# Week 6 — Code Review for Security

> *Week 5 pointed three scanners at your own code and asked you to triage every finding. Week 6 takes the next step: another engineer opens a pull request, asks you for an approval, and you have ten to thirty minutes to decide whether the diff is safe to ship. That is the daily work of an application-security engineer at a team scale — pattern matching for vulnerability classes on code you did not write, reasoning about the diff in the context of the system, and writing the comment that gets the bug fixed before it merges. This week is about that skill, and only that skill.*

Welcome to Week 6 of **C6 · Cybersecurity Crunch**. Weeks 1, 2, 3 gave you the security mindset, the network, and the threat model. Week 4 walked the OWASP Top 10 against Python web apps. Week 5 ran the full Python static-analysis toolchain against code you wrote. Week 6 takes the auditor's lens off your own commits and points it at someone else's pull request — the canonical AppSec moment where the cost of catching a bug drops by an order of magnitude versus catching it in production. By Sunday you will have reviewed a real open-source PR comment-by-comment, you will know which vulnerability classes you can spot in a thirty-line diff and which you cannot, you will have a personal review checklist you can paste into any `CODEOWNERS` workflow on Monday morning, and you will have read the same public audit reports the working security engineers cite to each other.

This week is reading-heavy and writing-heavy. You will read more code than you write. You will write more review comments than commits. The defensive payoff is a discipline that compounds: every PR you review well teaches the author what to look for next time, and the team's median patch quality drifts upward over the next six months.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Practice the techniques in this module only on:                    │
│  - real open-source pull requests you have a local clone of,        │
│    where you write your review as a study artifact and *do not*     │
│    file the review upstream unless the maintainers welcome that     │
│    contribution (check CONTRIBUTING.md and SECURITY.md first)       │
│  - your own past pull requests (the C1 / C16 portfolio repos        │
│    have plenty)                                                     │
│  - pull requests on repositories you maintain                       │
│  - synthetic PRs we publish in this curriculum's exercise set       │
│                                                                     │
│  If during a review you discover a finding you believe is a real    │
│  vulnerability in upstream code, follow Week 3's coordinated-       │
│  disclosure process: read SECURITY.md, file privately, give the     │
│  maintainer reasonable time. Do not file a public PoC. Do not       │
│  exercise the finding against any deployed service.                 │
│                                                                     │
│  Unauthorized testing is a crime. C6 does not teach crime.          │
└─────────────────────────────────────────────────────────────────────┘
```

The banner is mandatory on every page this week. The week's posture is *defensive review of code others wrote*, and the rule from Weeks 4 and 5 holds: read the source, reason about attacks, do not run them against systems you do not own. The targets for the exercises and the mini-project are public PRs and your own past code; the comments you write are study artifacts unless and until you have read the upstream project's contribution norms and decided the upstream wants the input.

---

## Learning objectives

By the end of this week, you will be able to:

- **Read** a pull request with a security lens — separating *what the diff does to the system* from *what the diff says*. Distinguish the four review modes (correctness, style, design, security) and apply each on a per-hunk basis.
- **Spot** the canonical vulnerability classes in a diff under five minutes: input boundary changes (new HTTP route, new CLI flag, new IPC message), trust boundary changes (a value crossing from untrusted to trusted context), crypto and secret handling changes, authentication and authorization changes, deserialization, query construction, file path construction, subprocess construction, and dependency manifest changes.
- **Apply** *pattern matching for vulnerability classes* — the technique of recognising hazard shapes by syntactic and structural cues (a `request.args[...]` flowing into a regex, a new `subprocess.run` argument list with a user-controlled element, a `pickle.loads` near any I/O, a `requests.get` on a user-supplied URL, a `bcrypt.checkpw` whose result is compared with `==` instead of constant-time). Cite the matching CWE for each pattern.
- **Distinguish** the *checklist-based* review approach from the *model-based* review approach. Use the checklist when you have a known, bounded surface (`OWASP Code Review Guide` items, your team's secure-coding checklist) and use the model when the diff changes the system's trust boundaries (you re-derive a small mental model of the data flow before approving). Know when each fails.
- **Write** a review comment that the author can act on without a second back-and-forth: explicit location, explicit hazard, explicit CWE or CVE reference, explicit suggestion (often a one-line code suggestion via GitHub's `suggestion` block), explicit severity, explicit "blocking" or "non-blocking" tag.
- **Read** public audit reports as primary sources — **Trail of Bits** ([publicaudits.org](https://publicaudits.org/), [github.com/trailofbits/publications](https://github.com/trailofbits/publications)), **NCC Group** ([research.nccgroup.com](https://research.nccgroup.com/)), **Google Project Zero** ([googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com/)), **Cure53** ([cure53.de/#publications](https://cure53.de/#publications)), and **PSF / pip-audit** advisories. Recognise the standard audit-report structure, the severity language, and the *finding* artifact you will be asked to write at work.
- **Triage** a PR-level review into three outcomes: *approve* (no security concerns this engineer can see), *request changes* (one or more blocking findings, cite each), *comment* (questions or non-blocking observations). Know which of the three to use when, and when to escalate to a separate AppSec review track instead of holding up the PR.
- **Produce** a security code review of a real open-source pull request, comment-by-comment, including at least one blocking finding (or an explicit reasoned approval if the PR is clean) and a follow-up summary the author can paste into their next PR description.

---

## Prerequisites

- **Weeks 1, 2, 3, 4, and 5 completed.** You should be comfortable threat-modeling a small system, walking the OWASP Top 10 on Python web code, and triaging the output of `bandit`, `semgrep`, and `pip-audit`.
- **A GitHub account, with `gh` CLI configured.** You will be reading PRs from real projects. `gh pr view`, `gh pr diff`, `gh pr checkout` are the basic verbs.
- **A local clone of at least one public Python project** you respect. The mini-project will ask you to review a real PR from such a project; pick the project this week.
- **An IDE with diff-friendly chrome.** VS Code's PR review panel, the GitHub web UI, `delta` or `diff-so-fancy` for terminal-based review, or `git difftool` set up. Any of these is fine; you will pick one and stick with it.
- **The Week 5 toolchain installed** (`bandit`, `semgrep`, `pip-audit`). You will run them *on PR branches* — `gh pr checkout NNN && semgrep --config p/python .` is the pattern.

---

## Topics covered

- **The four review modes** — correctness (does it do what the PR says it does?), style (does it match the project's conventions?), design (is the abstraction right?), security (is the diff safe to ship?). The point is not "do all four every time" — you will not have the time — but to know which mode each comment belongs to and to *flag* the security comments as security comments so the author and other reviewers can find them.
- **The PR-level threat-modeling shortcut** — a one-minute pre-review to identify which trust boundaries the diff crosses. The four cues that should immediately raise the security temperature: a new input source (route, flag, file, message), a new outbound call (HTTP, subprocess, file write outside a known dir), a change to authentication / authorization / session / cookie / token handling, a change to the dependency manifest. If any one of these is present, slow down.
- **Pattern matching for vulnerability classes** — the syntactic and structural cues for the canonical bugs. Input-shaped patterns (`request.args[...]`, `request.json`, `argv[...]`, `os.environ[...]`), sink-shaped patterns (`subprocess.run`, `os.system`, `eval`, `exec`, `pickle.loads`, `yaml.load`, `requests.get`, `cursor.execute`), trust-boundary patterns (a deserialised value used without validation, a path joined to a base without normalisation, an HTML string built by concatenation), crypto patterns (`md5`, `sha1`, `random.randint`, `==` on secrets, `verify=False`, hardcoded keys), and the dependency-manifest patterns (new package, version bump, removed pin).
- **Model-based review** — the alternative to checklist review. Before commenting, build a small mental model: where does user input enter, where does it leave, what changes between the two. The model lives in your head (or in a scratch note); the comments come from the model. The technique is necessary when the diff is large or when the diff touches the security-critical core (auth, crypto, deserialisation, trust boundary). It is overkill on a typo-fix PR.
- **Checklist-based review** — the alternative to model-based review. A bounded set of items you walk through every time. The classic source is the **OWASP Code Review Guide v2** (free PDF, ~200 pages); the canonical short list is the OWASP *Secure Coding Practices Quick Reference* (~10 pages, 100 items). The point of the checklist is to *not miss the obvious thing* when you are tired or rushed. The trade-off is that no checklist covers a novel design flaw.
- **The two-pass review** — first pass for *structure* (read the PR description, the file tree, the test diff, the manifest diff, in that order), second pass for *content* (line-by-line on the highest-risk hunks first). Most reviewers reverse the order, which is why most reviews miss the design-level findings.
- **Writing the review comment** — the *five-anchor* format. Location (file:line). Hazard (one short sentence). Reference (CWE / CVE / OWASP / a citation from the team's secure-coding doc). Suggestion (the fix, ideally as a `suggestion` block). Severity tag (`[blocking]`, `[major]`, `[minor]`, `[nit]`, `[question]`). The five anchors make the comment auditable in retrospect and acted-on without further round-trips.
- **The "approve / request changes / comment" decision** — when each is correct. The default in security review is *request changes* the moment one blocking finding exists; *comment* is the right state when you are not certain but want the discussion logged; *approve* is the right state only when you have walked the diff and found nothing security-relevant.
- **Reading public audit reports** — Trail of Bits and Google Project Zero are the two cleanest practitioner bodies of work for Python and systems software respectively. **Their reports are free, primary, and recent.** You will read at least two complete reports this week; the lecture notes index the specific reports to start with.
- **The portfolio artifact** — a *public* security review of a real OSS PR, written as a Markdown document with line-anchored comments and a cover summary. It is the document a hiring manager reads first; it answers "can this candidate sit in a PR-review queue tomorrow?"

---

## Weekly schedule

The schedule below adds up to approximately **36 hours**. Treat it as a target.

| Day       | Focus                                                       | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|-------------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | L1 — Reviewing PRs with a security lens                     |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Tuesday   | L2 — Pattern matching for vulnerability classes             |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Wednesday | L3 — Model-based vs. checklist-based review                 |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0.5h     |    0.5h    |    5.5h     |
| Thursday  | Exercises polished; challenge launch                        |    0h    |    2h     |     1.5h   |    0.5h   |   1h     |     1h       |    0.5h    |    6.5h     |
| Friday    | Mini-project: pick the PR, write the model                  |    0h    |    1h     |     0.5h   |    0.5h   |   1h     |     2.5h     |    0.5h    |     6h      |
| Saturday  | Mini-project: comment-by-comment, cover summary             |    0h    |    0h     |     0h     |    0h     |   1h     |     3h       |    0h      |     4h      |
| Sunday    | Quiz, review, polish, push                                  |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    0.5h    |     1h      |
| **Total** |                                                             | **6h**   | **7h**    | **2h**     | **3h**    | **6h**   |   **7h**     |   **3h**   |  **36h**    |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | Trail of Bits and Project Zero audit indexes, OWASP Code Review Guide, public PR-review checklists, the `gh` CLI cookbook |
| [lecture-notes/01-reviewing-prs-with-a-security-lens.md](./lecture-notes/01-reviewing-prs-with-a-security-lens.md) | The four review modes, the PR-level threat-modeling shortcut, the two-pass review, the five-anchor comment format |
| [lecture-notes/02-pattern-matching-for-vulnerability-classes.md](./lecture-notes/02-pattern-matching-for-vulnerability-classes.md) | The syntactic / structural cues for the canonical hazards, with grep-style and `semgrep` patterns and CWE-to-pattern map |
| [lecture-notes/03-model-based-vs-checklist-based-review.md](./lecture-notes/03-model-based-vs-checklist-based-review.md) | When to use each method, the OWASP Code Review Guide v2 walkthrough, the team-checklist template |
| [exercises/README.md](./exercises/README.md) | Index of three exercises |
| [exercises/exercise-01-review-a-real-pr.md](./exercises/exercise-01-review-a-real-pr.md) | Pick a real public PR, review it comment-by-comment, write the cover summary |
| [exercises/exercise-02-spot-the-pattern.md](./exercises/exercise-02-spot-the-pattern.md) | Twelve diff hunks, twelve hazards (or non-hazards) to identify by pattern alone |
| [exercises/exercise-03-checklist-vs-model.md](./exercises/exercise-03-checklist-vs-model.md) | Same PR reviewed two ways; write up which method caught which finding |
| [challenges/README.md](./challenges/README.md) | Index of weekly challenges |
| [challenges/challenge-01-audit-an-OSS-PR.md](./challenges/challenge-01-audit-an-OSS-PR.md) | A scoped, ~2-hour review of a real public PR, intermediate difficulty |
| [quiz.md](./quiz.md) | 10 multiple-choice questions |
| [homework.md](./homework.md) | Six practice problems, six hours total |
| [mini-project/README.md](./mini-project/README.md) | Full security code review of a real OSS PR, comment-by-comment, with a public cover document — the Week 6 portfolio artifact |

---

## Stretch goals

If you finish early, push further:

- Read the **Trail of Bits "Audit Manual"** (their public methodology document), and compare it to your own review notes for the mini-project. Where the Manual is more disciplined than you were, write down the delta and apply it to your next review.
- Read three consecutive **Google Project Zero "0day-in-the-wild"** blog posts from the last twelve months. The vulnerability classes there are not Python — they are Chrome, iOS, Windows, Android — but the *review reasoning* (root-cause analysis, patch-gap analysis, exploit primitives) is the deepest practitioner writing in the public domain.
- Configure a **GitHub Actions workflow on a repo of your own** that runs `bandit`, `semgrep`, and `pip-audit` against every PR and posts a SARIF-backed Code Scanning result. The Week 5 workflow plus the Week 6 review discipline together are the toolchain side of "PR-time security review."
- Write a **personal review checklist** (one page, your idiosyncratic version) and commit it to your portfolio repo as `review-checklist.md`. Iterate it after every real review you do for the rest of C6. The checklist is the thing other engineers will ask to borrow.
- Pair-review a PR with another C6 learner: each of you reviews the same PR independently, then compares findings. The disagreement set is the most valuable artifact in the exercise; that is the same exercise red-team vs. blue-team table-tops use.
- Read the **OpenSSF Scorecard** documentation and run `scorecard` against three Python projects you depend on. The intersection of Scorecard's automated signals (branch-protection, signed releases, code-review coverage) and your manual PR review is the OSS supply-chain attack surface in 2025.
- Sit in on (or replay) a real maintainer's PR-review queue — many large projects (CPython, NumPy, Django, FastAPI) have public PR queues where you can observe the *cadence* and *register* of upstream review. Read fifteen consecutive merged PRs and note the review style.

---

## Up next

Continue to [Week 7 — Recon & Scanning (Authorized Only)](../week-07/) once your mini-project review is pushed and your portfolio README links to all six weeks. Week 7 shifts modes — from defensive AppSec at PR time to authorized offensive recon in a lab — but the discipline carries: read first, model second, act third, document everything.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
