# Lecture 3 — Model-Based vs. Checklist-Based Review

> *Lecture 2's pattern catalogue is necessary and insufficient. A reviewer who knows every pattern in Lecture 2 will still miss the design flaw that lets an attacker delete other users' files by guessing IDs, because no pattern fires on "the diff forgot to check ownership." This lecture is about the two methods that complement pattern matching — the checklist (cheap, bounded, catches obvious omissions) and the model (expensive, unbounded, catches design flaws). Knowing which to apply when, and how to combine them, is the difference between the reviewer who finds the easy bugs and the reviewer who finds the bugs that matter.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The methods in this lecture are taught with synthesised diffs and  │
│  citations to public audit reports (Trail of Bits, NCC, Project     │
│  Zero, Cure53). Do not exercise findings against deployed services. │
│  When a method surfaces a finding in upstream OSS that you believe  │
│  is exploitable, follow Week 3's coordinated-disclosure process.    │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers:

- The **checklist-based** review method — what it is, what it catches, what it misses.
- The **model-based** review method — what it is, what it catches, what it misses.
- The **decision rule** — when each method applies.
- A **worked side-by-side** — the same PR reviewed both ways, finding by finding.
- The **OWASP Code Review Guide v2** walkthrough — the canonical published checklist, condensed.
- A **team-checklist template** you can take to your day job.

---

## 1. What a checklist actually is

A checklist is a bounded set of items you walk through, in order, every time. Each item is phrased as a question with a yes / no / not-applicable answer. The point of the checklist is *not* to think; the point of the checklist is to *not skip*. Aviation, surgery, and security review all converge on the same insight: humans are unreliable at remembering to do every step in a long sequence, especially when under time pressure or fatigue.

A good checklist has the following properties:

- **Short.** Twenty to fifty items. Anything longer becomes a document people pretend to walk and do not.
- **Concrete.** "Is there a `@login_required` on every state-changing route?" — not "is authentication appropriate?"
- **Falsifiable.** Each item has an answer derivable from the diff plus a constant lookup. "Does the new HTTP route accept a URL parameter without an allow-list?" — not "is the route designed well?"
- **Versioned.** The checklist drifts. New hazard classes appear; old ones go out of fashion. The team's checklist is a living document.
- **Self-suppressing.** If an item does not apply (the PR does not touch routes), the reviewer marks it N/A and moves on. The checklist is not an obstacle; it is a memory aid.

### 1.1 What a checklist catches

The boring stuff. The omissions. The "I forgot to add `@login_required` to the new route" bugs. The "I changed the cookie attribute but forgot `httponly`" bugs. The "I bumped `requests` but didn't read the changelog" bugs.

In other words: the bugs that come from *not thinking about a thing at all*. The checklist forces the question. The reviewer answers yes / no; if no, they comment.

### 1.2 What a checklist does not catch

Anything not on the checklist. By construction. This is the limitation: a checklist that does not include "does this endpoint expose IDOR by ID-guessing?" will not catch an IDOR.

Worse: a checklist that *does* include "does this endpoint expose IDOR" can still be defeated by the diff that *looks* like it adds a check (`if user.is_authenticated:`) but actually checks the wrong thing. The reviewer ticks the checkbox; the bug ships.

The trap is that a checklist gives the reviewer the *feeling* of having reviewed the PR. The feeling is useful when the bug is on the list; the feeling is dangerous when the bug is not.

---

## 2. What a model is

A "model" in this lecture means a small, in-your-head representation of *what the diff does to the system's state and trust boundaries*. It is the same thing as a threat model (Week 3), scoped to the PR.

To build the model, the reviewer asks:

1. **Where does data enter, after this diff?** (Old input sources plus new input sources.)
2. **Where does data leave, after this diff?** (Old sinks plus new sinks.)
3. **What is the trust level of each input, after this diff?** (Did the diff change who can produce data on this input? Did it add a new auth check or remove one?)
4. **What validates the path from input to sink?** (Schemas, allow-lists, parameterised queries, output-encoding.)
5. **What is the failure mode of each validator?** (Bypass via encoding, via Unicode normalisation, via case-folding, via type confusion, via partial parse.)
6. **What does the failure of the validator do?** (RCE? data leak? auth bypass? availability hit?)

The model is *not written down* in most reviews. It is held in the reviewer's head for the duration of the second pass. For high-stakes PRs (auth, crypto, payment, PII, multi-tenant boundaries), the reviewer *does* write the model down — three to ten bullet points in a scratch file — and the model becomes the spine of the review summary.

### 2.1 What a model catches

The interesting stuff. The design flaws. The logic flaws. The "this looks fine if you only look at the diff but breaks when you consider the existing rate-limit middleware was scoped to a different path prefix" bugs.

Specifically, the model catches:

- **Authorization gaps.** "User A can reset User B's password" — the diff adds a route, no pattern fires, but the model surfaces the missing ownership check.
- **State-machine flaws.** "The order goes `pending → paid → shipped`, but the new diff allows `pending → shipped` directly, skipping `paid`."
- **Trust-boundary confusion.** "This worker treats `account_id` as trusted because it came off our queue, but the queue is populated from a web handler that doesn't validate `account_id` belongs to the requesting user."
- **Validator bypass.** "The new validator strips `..` from the path, but `....//` becomes `..` after the strip and bypasses the check."
- **Defence-in-depth absence.** "The signed-pickle scheme works for an external attacker, but if the signing key leaks, the diff has no second line of defence."

These bugs are the ones that matter. They are also the ones a checklist by itself does not catch.

### 2.2 What a model does not catch

The cheap stuff. The omissions a checklist would have caught. The reviewer who only builds a model often misses the "you forgot `httponly` on this cookie" finding because they were busy thinking about the state machine.

This is why the methods are complementary, not alternative.

---

## 3. The decision rule

> **Default to checklist. Switch to model when the diff crosses a security-critical boundary.**

The "security-critical boundary" set is the same as the cues from Lecture 1, § 2.1:

- New input source.
- New outbound call.
- Auth / authz / session / cookie / token / password change.
- Dependency-manifest change.

If any of those cues is present, build the model *before* walking the checklist. The model frames the checklist: which items are most relevant, which items can be skipped as N/A.

If none of the cues is present (the diff is a refactor, a type-hint pass, a docstring fix, a `pytest` bump), the checklist alone is enough. Build the model only if the checklist surfaces a question you cannot answer without it.

### 3.1 Time budget

In a real review queue:

- **Checklist-only review:** ~5 minutes for a small diff, ~15 minutes for a medium diff. Most PRs.
- **Checklist + model review:** ~20 minutes for a small security-relevant diff, ~60 minutes for a medium one, ~2 hours for a large one. Maybe 1 in 5 PRs.
- **Model-only review:** rarely the right answer in isolation; the checklist is too cheap to skip.

The time budget is *yours*, not the author's. If you do not have the budget to build a model on a PR that needs one, the right answer is `[question]` plus a request for a second reviewer. Approving a security-critical PR you did not have time to model is the *worst* outcome — it gives the team a false signal of having been reviewed.

---

## 4. A worked example — same PR, both methods

We re-use the synthesised PR from Lecture 1 § 6 (the `/account/import` endpoint with the pickled snapshot and the "hash check"). We review it once with the checklist alone and once with the model alone, then compare findings.

### 4.1 The PR (recap)

```python
# app/routes/account.py, lines 28-46
@account_bp.route("/account/import", methods=["POST"])
@login_required
def account_import():
    body = request.get_data()
    if len(body) < 32:
        abort(400, "snapshot too short")
    payload, expected_hash = body[:-32], body[-32:]
    actual_hash = hashlib.sha256(payload).digest()
    if actual_hash != expected_hash:
        abort(400, "hash mismatch")
    account = pickle.loads(payload)  # nosec B301 — hash-verified
    db.session.merge(account)
    db.session.commit()
    return jsonify({"ok": True, "id": account.id})
```

### 4.2 Checklist-only review

We walk the C6 short checklist (§ 6 below). Items relevant to this PR:

- **C-1 Authentication present?** Yes — `@login_required`. ✓
- **C-2 Authorization scoped to the right object?** *Not on this checklist as a yes/no item.* (This is the checklist's blind spot; it catches "auth present" but not "auth correct.")
- **C-3 Input validated against a schema?** No — body is read as raw bytes, parsed as a pickle. ✗ → comment.
- **C-4 Output encoded?** N/A — the response is JSON.
- **C-5 Crypto primitive appropriate?** No — SHA-256 is being used as a "signature" but is a checksum without a key. ✗ → comment.
- **C-6 Secret comparison constant-time?** No — `!=` not `hmac.compare_digest`. ✗ → comment.
- **C-7 Deserialisation safe?** No — `pickle.loads` on body. ✗ → comment.
- **C-8 SQL parameterised?** N/A — no raw SQL.
- **C-9 Subprocess safe?** N/A — no subprocess.
- **C-10 File path safe?** N/A — no file write.
- **C-11 HTTP client safe?** N/A — no outbound call.
- **C-12 Cookie attributes set correctly?** N/A — no cookies.
- **C-13 Logging avoids PII?** N/A — no log call.
- **C-14 Error messages don't leak?** ✓ — generic "snapshot too short" / "hash mismatch."
- **C-15 Tests cover the negative path?** Partially — the PR has a test for happy path; the comment thread would ask about the hash-mismatch path.

**Checklist findings:** C-3, C-5, C-6, C-7 — four items. Three of the four are the same finding (the pickle-deserialisation-with-checksum hazard), seen at different granularities. The checklist catches the *shape* of the bug.

**What the checklist missed:** the authorization gap (C-2 is not phrased to catch it). The reviewer who only walked the checklist would write three comments about the pickle / hash / constant-time issues and would *miss* the more interesting finding: even with the pickle replaced and the HMAC added, the endpoint allows User A to import User B's snapshot.

### 4.3 Model-only review

We build the model in our heads:

- **Input sources, post-diff:** the new `/account/import` route accepts a raw bytestring from any authenticated user.
- **Output sinks, post-diff:** the body is parsed via `pickle.loads`, the resulting object is `db.session.merge`'d, and the response includes `account.id`.
- **Trust levels:** the bytestring is *fully attacker-controlled* (it came from `request.get_data()`). The "hash check" does not change the trust level — it is a checksum, not a signature. The deserialised `account` object is therefore also fully attacker-controlled.
- **Validators:** none. The hash-check is a checksum and gives no integrity guarantee. The pickle deserialiser is not a validator; it is a code-execution primitive (CWE-502).
- **Failure modes of the validators:** N/A — there are no validators.
- **What the failure does:** any authenticated user gets pickle RCE in the worker process *and* can write arbitrary fields into the `Account` row indexed by the snapshot's `id` (CWE-639 / CWE-863).

**Model findings:** 
- **F-Model-1:** pickle RCE via attacker-controlled bytestring. CWE-502.
- **F-Model-2:** no signature / authentication on the snapshot — any authenticated user can import any snapshot. CWE-345 / CWE-639 / CWE-863.

**What the model missed:** the timing-channel finding on `!=` (CWE-208). The model focused on the *trust chain* and noted "no validators"; it did not zoom in on the specific primitives used inside the (broken) check.

### 4.4 The two methods compared

| Finding | Checklist | Model |
|---|---|---|
| pickle.loads (CWE-502) | Yes | Yes |
| hash-not-signature (CWE-345) | Yes (as "weak crypto") | Yes (as "no validator") |
| timing channel on `!=` (CWE-208) | Yes | Missed |
| ownership / IDOR (CWE-639 / CWE-863) | Missed | Yes |
| missing payload-size cap | Partial (covered by C-3 if checklist includes resource limits) | Missed |

Neither method alone catches everything. The full review combines them — checklist first (or in parallel), then model — and produces the union of findings.

### 4.5 What this means in practice

A reviewer who only knows pattern matching (Lecture 2) catches the pickle and the `verify=False` patterns. A reviewer who adds the checklist (this lecture) catches the missing `httponly`, the missing CSRF, the unparameterised SQL, the weak crypto. A reviewer who adds the model catches the design flaws — the ones that ship to production and become CVEs.

The mini-project this week is a real PR review. You will combine all three methods.

---

## 5. The OWASP Code Review Guide v2 — the canonical reference

The OWASP Code Review Guide v2 (2017, still current; ~200 pages) is the public-domain reference for security code review. It is free and primary. Read it; do not just cite it.

**URL:** <https://owasp.org/www-project-code-review-guide/>

The sections most worth reading:

### 5.1 Section 4 — Methodology

The Guide describes a six-step method:

1. **Application threat modelling** — high-level review of trust boundaries and assets before opening any code.
2. **Source-code review** — the line-by-line work.
3. **Identification of vulnerabilities** — naming each finding with a CWE.
4. **Reporting** — the standardised finding-write-up format the Guide promotes.
5. **Re-testing** — confirming each fix landed and did not introduce a regression.
6. **Lessons learned** — the team-level retrospective.

Steps 1, 2, 3, and 4 happen on every PR. Step 5 happens after merge. Step 6 happens quarterly at most.

### 5.2 Section 5 — A list of vulnerabilities to check

The Guide enumerates the canonical web hazards class-by-class with code snippets per language. For Python, it covers most of the patterns from Lecture 2 plus a few additional shapes around frameworks (Django, Flask) and ORMs.

**Use this section as the source for your team checklist.** Pick the 30-50 most-relevant items, phrase each as a yes/no question, version the result.

### 5.3 Section 6 — Review by technology

A per-technology cheat sheet — what to look for in Django, what to look for in Flask, what to look for in Spring, what to look for in Rails, etc. The Python-relevant subsections are worth a focused half-hour read.

### 5.4 What the OWASP Guide does not give you

A *running list of new hazards* introduced after 2017. The Guide's last major revision predates the post-2017 wave of Python supply-chain attacks (PyPI dependency confusion, typosquatting, the Trail of Bits research on `pip` and `pip-audit`), the rise of FastAPI as a major framework, the maturation of `pydantic` validation, and the 2024–2025 wave of ML-supply-chain CVEs in `transformers` / `torch` / `tensorflow`. Your team checklist needs to *extend* the Guide with the post-2017 hazards.

---

## 6. A team-checklist template

What follows is a 30-item checklist scoped for a typical Python web project. It is **not** a complete OWASP ASVS walk; it is the *short list* a working reviewer can run in their head on every PR. Adapt it to your team's stack.

```markdown
# Team security-review checklist (C6 short form, v1.0)

Walk every yes/no on every PR that crosses a trust boundary
(Lecture 1, § 2.1). Mark N/A liberally; the goal is to not skip
the items that apply, not to apply every item.

## Input

- [ ] C-1 Every new input source (route, flag, file, queue) has a
      schema-validated entry point. Pydantic / dataclasses /
      `argparse` with `type=` count; raw `request.args[...]` does not.
- [ ] C-2 Every untrusted value is bounded in size before any
      expensive operation (regex, allocation, JSON parse).
- [ ] C-3 No new use of `pickle.loads`, `yaml.load`,
      `marshal.loads`, `dill.loads`, `torch.load` on attacker-
      influenced data. (`yaml.safe_load` allowed; cite when used.)

## Output

- [ ] C-4 Every new HTML output is auto-escaped. No new
      `Markup`, `mark_safe`, `\|safe`, `{% autoescape off %}` without
      a written justification.
- [ ] C-5 Every new SQL query is parameterised. No f-string SQL,
      no `%`-format SQL, no `.format()` SQL.
- [ ] C-6 Every new shell invocation passes args as a list with
      `shell=False`. No `subprocess.run("..." + x, shell=True)`,
      no `os.system`, no `os.popen`.
- [ ] C-7 Every new file write uses a `Path.resolve()` + prefix
      check to prevent path traversal.
- [ ] C-8 Every new outbound HTTP call has an allow-list of hosts
      (or refuses private / loopback / link-local IPs).
      `requests.get(...)` on user-supplied URLs is a finding.

## Authentication and authorization

- [ ] C-9 Every new state-changing route has `@login_required`
      (or equivalent) and an explicit authorization check against
      the object being mutated (not just "the user is logged in"
      but "the user owns this object").
- [ ] C-10 Every new POST / PUT / PATCH / DELETE has CSRF
       protection (token, SameSite cookie, or framework default).
- [ ] C-11 Every new password-handling code uses `bcrypt` /
       `argon2` with current OWASP cost factors. No `hashlib`
       near a password.
- [ ] C-12 Every new JWT or session-token verification specifies
       `algorithms=[...]` explicitly and uses constant-time
       comparison.
- [ ] C-13 Every secret comparison uses `hmac.compare_digest`,
       not `==`.

## Crypto

- [ ] C-14 No new `hashlib.md5` or `hashlib.sha1` for any
       security use. (Non-security uses — file dedup, cache
       keys — require a `# nosec B303 — non-security` annotation.)
- [ ] C-15 No new `random.random`, `random.randint`,
       `random.choice` for any token / nonce / ID. Use `secrets`.
- [ ] C-16 No new `verify=False` on `requests` / `httpx` / TLS
       sockets. No new `ssl.CERT_NONE`.
- [ ] C-17 No new AES-ECB. AES-GCM, ChaCha20-Poly1305, or
       a vetted high-level API (`Fernet`).

## Session and cookies

- [ ] C-18 Every new `response.set_cookie` has `httponly=True`,
       `secure=True`, `samesite="Lax"` (or `"Strict"`).
- [ ] C-19 Session lifetime and idle-timeout are explicit.

## Errors and logging

- [ ] C-20 Error messages do not leak stack traces, file paths,
       database internals, or other infrastructure cues to the
       client.
- [ ] C-21 Logs do not contain passwords, tokens, cookies, API
       keys, or PII (email, phone, name in user-identifying
       contexts).
- [ ] C-22 `print(...)` for debugging in route code is removed.

## Resource and rate

- [ ] C-23 Unbounded loops / unbounded allocations / unbounded
       regexes on user input are absent.
- [ ] C-24 New endpoints have rate-limiting (or a documented
       reason why not).
- [ ] C-25 Uploaded files have size limits, content-type checks,
       extension validation, and storage outside the web root.

## Supply chain

- [ ] C-26 Every new dependency is pinned with an exact version.
- [ ] C-27 Lockfile is committed (`requirements.txt` with hashes,
       `poetry.lock`, `Pipfile.lock`).
- [ ] C-28 No `git+https://` or `git+ssh://` sources without a
       written justification.
- [ ] C-29 No `pip install` of unpinned packages in Dockerfile
       or CI.

## Tests

- [ ] C-30 The PR includes tests for at least one negative path
       per new public function. Auth tests for new auth paths,
       deserialiser tests for new deserialisers, etc.

---

If any item is unchecked and N/A is not justified, comment.
If three or more items are unchecked, set "Request changes."
```

The checklist is meant to be **printed and pinned** above your monitor for the first month. After that, the items become muscle memory.

### 6.1 How to extend the checklist for your team

The checklist is generic. Each team will have idioms a generic checklist cannot catch:

- "Every new database migration runs under a transaction" — your team's discipline, codify it.
- "Every new feature flag has an explicit default for the disabled state" — your team's discipline.
- "Every new API endpoint has a corresponding OpenAPI entry" — your team's discipline.
- "Every new metric has a label that matches the cardinality budget" — your team's discipline.

Add team-specific items at the bottom, version the file (`v1.0`, `v1.1`), and review the checklist quarterly. Items that have not fired in a year are candidates for removal; new hazard classes that have surfaced in postmortems are candidates for addition.

### 6.2 How to commit the checklist

Commit `review-checklist.md` to a known location in the repo. Reference it in `CONTRIBUTING.md`. Reference it from PR templates. Some teams put the checklist directly in the PR template as a series of `- [ ]` items the *author* checks before requesting review; this front-loads the discipline.

The Week 6 mini-project asks you to author exactly this artifact for your portfolio.

---

## 7. When the model catches what the checklist cannot

The case studies below are *patterns of design flaw* that no syntactic pattern and no checklist catches. They are caught by the model. Read each; the next time you see the shape in a diff, the model will fire.

### 7.1 The "ownership check on the wrong object" pattern

A diff adds:

```python
@app.route("/document/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    doc = Document.query.get(doc_id)
    if not doc:
        abort(404)
    if current_user.is_authenticated:        # the check is "is the user logged in"
        db.session.delete(doc)
        db.session.commit()
    return redirect("/documents")
```

No pattern fires. No checklist item directly catches this — C-9 says "auth + ownership check," but the diff *appears* to have both (`@login_required` + `if current_user.is_authenticated`). The bug is that `current_user.is_authenticated` is *always* true inside a `@login_required` route, so the check is a tautology, and the real authorization check (`doc.owner_id == current_user.id`) is missing.

The model catches this: in step 4 ("what validates the path from input to sink"), the reviewer asks "is the validator semantically correct?" and the tautology surfaces.

CWE-863 Incorrect Authorization.

### 7.2 The "validator runs after the sink" pattern

A diff adds:

```python
def import_data(filename: str) -> None:
    with open(filename, "rb") as f:
        data = pickle.load(f)
    if not filename.startswith("/data/imports/"):
        raise PermissionError("invalid import path")
    process(data)
```

The validator runs *after* the deserialiser. By then the pickle has executed. The bug is the *ordering*: the validator must run before the sink, not after.

Pattern matching catches the `pickle.load`; the *checklist* may not catch the ordering. The model does: in step 5 ("what is the failure mode of each validator"), "the validator runs too late" is a recognised failure mode.

CWE-696 Incorrect Behavior Order.

### 7.3 The "second-order injection" pattern

A diff adds a SQL query that uses a value stored from a *previous* request:

```python
# in models.py
class Account:
    @classmethod
    def find_by_alias(cls, alias):
        # parameterised — looks safe
        return cls.query.filter_by(alias=alias).first()

# in routes.py
@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    current_user.alias = request.form["alias"]   # no validation
    db.session.commit()
    return redirect("/profile")

# elsewhere, in admin.py
@app.route("/admin/find", methods=["GET"])
@admin_required
def admin_find():
    alias = request.args["alias"]
    # this is parameterised…
    user = Account.find_by_alias(alias)
    # …but this is not:
    return render_template_string(f"<p>Found: {user.alias}</p>")
```

The bug chain: the user sets `alias` to `{{ config }}` on their own profile (no validation at write time). The admin views the user, the template-string renders `{{ config }}`, and the admin's session leaks every config value via SSTI (server-side template injection).

Pattern matching catches the `render_template_string(f"...")`. The checklist may not catch the second-order chain because no single item is violated *at write time*. The model catches it: in step 3 ("what is the trust level of each input"), the answer "the alias is fully attacker-controlled and is later used in a template" is the finding.

CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine.

### 7.4 The "rate-limit scoped to the wrong key" pattern

A diff adds rate-limiting:

```python
@app.route("/login", methods=["POST"])
@rate_limit(by="ip", limit="5 per minute")
def login():
    ...
```

The rate-limit is by IP. The bug is that a single attacker behind CGNAT (mobile carriers, large NATs) shares an IP with hundreds of legitimate users, *or* the attacker uses a botnet and trivially defeats the per-IP cap.

The correct rate-limit is by *user identifier* on the login form (`by="username"` if known, falling back to IP for the unknown-user case) — sometimes paired with progressive backoff and captcha.

Pattern matching does not catch this. The checklist item C-24 ("new endpoints have rate-limiting") is *satisfied*. The model catches it: in step 6 ("what does failure of the validator do"), the failure of "per-IP rate-limit under CGNAT" is "legitimate users locked out *and* attacker not stopped," and the trade-off surfaces.

---

## 8. The cost of model-based review

Model-based review is the most expensive part of the reviewer's day. Building the model for a 500-line auth-change PR takes 30-60 minutes. There is no shortcut.

The mitigations:

- **Pair the work.** Two reviewers, twenty minutes each, modelling separately, then comparing. The disagreement set is exactly the bugs to look at.
- **Document the model.** Write three to ten bullet points in the review summary. The next reviewer of the next PR on the same subsystem inherits the model.
- **Update the model as the system evolves.** A team that reviews the *same subsystem* across many PRs accumulates a shared mental model in the team's review-doc folder. Investment, not waste.
- **Reserve model-based review for the PRs that need it.** The threat-modeling shortcut from Lecture 1 § 2.1 is the gate.

The teams that get this discipline right ship fewer post-deploy security incidents per quarter. The teams that do not, ship more.

---

## 9. Reading other people's reviews

The fastest way to internalise model-based review is to read other people's model-based reviews. The public-domain corpus:

- **Trail of Bits public audits.** Every Trail of Bits report has a *threat-model* section and a *findings* section; the threat-model section is the model the auditors built. Read it, then read the findings, and notice which findings could only have come from the model.
- **Google Project Zero blog.** Every post is a model-based review of a single vulnerability or vulnerability class. The root-cause analysis is the model.
- **NCC Group whitepapers.** Often longer-form. The methodology sections explicitly call out the model.
- **Major OSS security advisories.** Read the upstream `SECURITY` advisory, then the patch commit, then the discussion thread. The discussion thread is the reviewers' model unfolding in public.
- **CPython security advisories with PR comments.** <https://github.com/python/cpython/security/advisories>. The fix PR plus the review comments is a complete worked example.

Pick two of these per week for the next quarter. After a quarter you will have read forty examples of expert review. The expertise transfers.

---

## 10. Where this leads

You now have the three methods:

- **Pattern matching** (Lecture 2) — fast, cheap, catches the canonical hazards, misses design flaws.
- **Checklist** (this lecture) — bounded, thorough, catches omissions, misses things not on the list.
- **Model** (this lecture) — slow, deep, catches design flaws, misses cheap omissions.

Real review uses all three, in this order:

1. **Triage** the PR against the cues (Lecture 1 § 2).
2. **Pattern-match** the diff in the second pass (Lecture 2).
3. **Walk the checklist** for items that apply (this lecture § 6).
4. **Build a model** if the diff crosses a security-critical boundary (this lecture § 2).
5. **Write the comments** using the five-anchor format (Lecture 1 § 4).
6. **Decide** approve / request-changes / comment (Lecture 1 § 5).

The exercises and the mini-project chain the six steps together against real OSS PRs.

---

## 11. Self-test

- A PR adds a route that returns `{user.email}` to anyone with a valid session cookie. The checklist item "auth present" is checked. Build the model. What is the finding?
- A PR adds a feature flag with a `default=True` for "enable_legacy_pickle_loading." The checklist item "no new `pickle.loads`" is satisfied (no new call; the existing one is gated). Build the model. What is the finding?
- A PR replaces `bcrypt(rounds=12)` with `bcrypt(rounds=10)` for "performance." The checklist item "bcrypt with current cost factors" is partially satisfied (10 is below the current recommendation but not by much). Build the model. What is the finding? What is the severity tag?
- A PR adds a `pre-commit` hook that runs `bandit -r .` locally. Pattern matching, checklist, and model all say *good*. Why does this PR still earn a comment, and what is it?

Answer in your scratch notes, then start Exercise 3.
