# Lecture 1 — Reviewing PRs with a Security Lens

> *In a working engineering team, you will be asked to review three to ten PRs per week from people whose code you did not write, whose threat model you did not build, and whose tests you did not design. The median PR is unrelated to security; ten or fifteen percent of them are. Your job — as the security-trained reviewer on the rotation — is to spot the ten-or-fifteen percent in the first sixty seconds and to escalate your review depth on those alone. The other PRs get a normal correctness review. The discipline this lecture teaches is that triage.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  This lecture covers reading and reviewing pull requests. All       │
│  examples are public OSS PRs you have a local clone of, your own    │
│  past PRs, or synthetic diffs published with this curriculum. Do    │
│  not exercise findings against deployed services. If a finding     │
│  in upstream OSS appears genuinely exploitable, follow Week 3's     │
│  coordinated-disclosure process; do not publish a public PoC.       │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers:

- The **four review modes** and why the mode matters more than the comment count.
- The **PR-level threat-modeling shortcut** — the one-minute pre-review that decides whether the PR needs five minutes of attention or fifty.
- The **two-pass review** — structure first, content second, in that order.
- The **five-anchor comment format** — every comment has Location, Hazard, Reference, Suggestion, Severity.
- The **approve / request-changes / comment** decision.
- A **worked example** on a public OSS PR — the kind of review you will produce in this week's mini-project.

---

## 1. The four review modes

Every comment you write in a code review is operating in one of four registers. Naming the register is the first piece of discipline; tagging the comment as the register is the second.

### 1.1 Correctness review

*Does the code do what the PR description says it does?* This is the universal-floor mode. Tests should cover the new behaviour; the diff should match the description; the failure cases should be handled. A correctness comment looks like:

> The new `parse_iso8601` rejects timezone-naive strings, but the PR description says timezone-naive should default to UTC. Either update the description or update the function to default to UTC; the two are out of sync.

Correctness comments are non-security. They are also the most common comments in any review queue.

### 1.2 Style review

*Does the code match the project's conventions?* Indentation, naming, file layout, module structure, the choice of `f"..."` vs `.format()`. Style review is the easiest review to give and the easiest review to over-give. Most modern projects have automated style tools (`ruff`, `black`, `isort`); your style comments should be only where the tool does not reach.

Style comments are non-security; they are usually `[nit]`-tagged.

### 1.3 Design review

*Is the abstraction right?* Should this be one function or two? Should this be in this module or that one? Should this be a class or a dictionary? Is the new API consistent with the existing API? Design review is the most expensive mode — it requires holding the whole subsystem in your head — and the highest-leverage. A design comment can save twenty future PRs of "this turned out to be in the wrong place."

Design comments are *occasionally* security: an abstraction that puts trusted and untrusted data in the same shape is a security-design comment. But the majority of design comments are non-security.

### 1.4 Security review

*Is the diff safe to ship?* Does it widen the attack surface? Does it weaken an existing defence? Does it introduce a new untrusted input source without a validator? Does it introduce a new outbound call without an allow-list? Does it touch crypto, auth, sessions, cookies, deserialisation, file paths, subprocess invocation, query construction? Does it bump a dependency to a version with a known CVE?

Security comments are the subject of this week. *The most-frequent failure mode is not "the security comment was wrong" — it is "the security comment was a correctness comment in disguise, and the reader processed it as correctness."* The five-anchor format (§ 4) fixes this: a security comment is *labelled* a security comment.

### 1.5 Why the mode matters more than the count

A review with twenty style nits and zero security comments on a diff that adds a new `subprocess.run(shell=True)` is a bad review. A review with one well-formed security comment is a good review. The reviewer who internalises the mode hierarchy — security > design > correctness > style — and *triages their time* accordingly is the reviewer the team comes to depend on.

The rest of this lecture is about *making time for the security pass on the PRs that need it*, by being efficient on the PRs that do not.

---

## 2. The PR-level threat-modeling shortcut

You have between five and thirty minutes per PR in a typical review queue. You do not have time to threat-model every PR. You do have time, for every PR, to ask a one-minute question:

> Does this diff change the system's trust boundaries?

If the answer is *no*, the PR gets a normal correctness-and-style review and a routine approval (or a routine request-changes on a correctness issue). If the answer is *yes*, the PR gets the slow security review.

### 2.1 The four cues

A diff is **changing trust boundaries** if any one of the following is present:

1. **A new input source.** New HTTP route. New CLI flag. New IPC message handler. New file format the project will read. New environment variable. New webhook. New queue consumer. New deserialisation entry point. *Any* new place the program accepts data from outside its own process.

2. **A new outbound call.** New `requests.get` / `httpx.get` / `urllib.urlopen`. New `subprocess.run` / `os.system`. New file write to a path partly derived from input. New SQL query construction. New `eval` / `exec`. New shell pipeline. *Any* new place the program acts on the world.

3. **A change to authentication, authorization, session, cookie, token, or password handling.** New `@login_required` decorator on a route, *or its removal*. New `Flask-Login` / `django.contrib.auth` / `fastapi.security` / `authlib` import. New password-hashing call. New JWT signing or verification. New cookie attribute. New CORS origin. New CSRF exemption. New rate-limit. *Any* change to who is allowed to do what.

4. **A change to the dependency manifest.** New package in `requirements.txt` / `pyproject.toml` / `Pipfile`. Version bump (especially across major versions). Removed pin. New `git+https://...` source. New private index URL. New `pip install` in `Dockerfile` or CI.

### 2.2 The thirty-second check

Open the PR. Look at:

1. The **file tree** (the "Files changed" tab on GitHub). Are there `.py` files under `auth/`, `crypto/`, `security/`, `session/`, `tokens/`? Are there changes to `requirements.txt` / `pyproject.toml` / `Pipfile.lock` / `poetry.lock`? Are there new routes (`routes.py`, `views.py`, `urls.py`, `api/`)? Are there changes to `Dockerfile` or `.github/workflows/`?

2. The **PR description**. Does the author mention security? Does the author mention "fixes CVE-..."? Does the description say "no test included because..."? Does the description say "this is a hotfix"? Each of these is a cue to slow down.

3. The **diff size**. A 30-line diff that touches `auth.py` is high-risk despite its size; a 3000-line diff that adds a typed-API client (with most lines being tests) is lower-risk despite its size. Diff size alone is not a signal; *what the diff touches* is.

If any of (1) or (2) above is positive, the diff crosses a trust boundary, and the next sections — pattern matching, model-based review, checklist review — apply.

### 2.3 What "no" looks like

A typical *no* PR:

- "Add type hints to `parse_csv`."
- "Fix typo in error message."
- "Bump `pytest` from 7.4.0 to 7.4.1 (no security advisories)."
- "Refactor: extract `_normalise_header` from `parse_request`."

Each of these *can* in pathological cases be security-relevant (a refactor can change a validator's behaviour; a type hint can mask a runtime check; a `pytest` bump can pull in a dependency tree change). But on the median such PR, the right review is a correctness review and a routine approval.

A typical *yes* PR:

- "Add `/admin/reset-password` endpoint."
- "Switch session backend from `itsdangerous` to a custom signer."
- "Accept a `webhook_url` field on the user-settings form."
- "Bump `cryptography` from 41.0.0 to 42.0.0 across major version."
- "Add support for SAML SSO."

Each of these crosses a trust boundary and earns the full security review.

---

## 3. The two-pass review

Once the PR is in the "yes, security review" bucket, the review proceeds in two passes.

### 3.1 First pass — structure (5-10 minutes)

The first pass reads the PR *as a whole* without commenting line-by-line. Read in this order:

1. **The PR description.** What does the author claim the PR does? What does the author claim the PR does *not* do? Authors are usually accurate on the former and sometimes silent on the latter.

2. **The file tree.** Which files are touched, which directories, which subsystems? Group the changes mentally: "this is the auth subsystem, this is the parser, this is tests, this is docs."

3. **The test diff.** What new tests? What removed tests? *What modified tests?* A modified test is more interesting than a new one — modified tests often indicate behaviour change, which is the bug class for security regressions. A test deletion is highly interesting.

4. **The dependency-manifest diff.** What was added, what was removed, what was bumped? Note the version numbers. If a package was bumped, check its `CHANGELOG` and its open security advisories.

5. **The highest-risk file diff.** Identify which one file is most likely to contain the bug — the file that touches the trust boundary you flagged in § 2.1 — and read it first, in isolation, *before* reading the rest.

The first pass produces *no comments yet*. It produces a *mental model* of what the PR is trying to do and where the risk lives.

### 3.2 Second pass — content (10-30 minutes)

The second pass goes line-by-line on the high-risk hunks. Use the patterns from Lecture 2 to spot hazard classes. Use the checklist (Lecture 3) on the auth / crypto / deserialisation diffs. Take notes in a scratch buffer; do not write the review comments in the GitHub UI yet.

Then, *after* the second pass, write the comments. Writing comments in the UI as you read invites two failure modes: (a) you write a comment, then keep reading, then realise the comment is wrong but it is already drafted and harder to discard than to ship; (b) you spread your attention across writing and reading and miss the third-order hazard that requires holding the whole diff in your head.

### 3.3 Why this order matters

Most reviewers reverse the order: they go line-by-line *first* and never form a model of the whole diff. The result is reviews full of style nits and zero design-level findings. The design-level findings are where the high-impact bugs live. A two-pass review costs maybe ten extra minutes; it more than pays for itself in the bugs caught.

---

## 4. The five-anchor comment format

Every security comment you write has five anchors. Missing any one of them shifts cost back to the author or to a future reviewer.

### 4.1 The five anchors

1. **Location.** `path/to/file.py:LINE` (or `LINE-LINE` for a range). GitHub's UI gives you this for free when you click a line; if you are writing the review as a Markdown document (the recommended habit), put the location at the top of the comment.

2. **Hazard.** One sentence naming the vulnerability class. Not "this looks suspicious" — *what is it*. "This is a SQL injection," "This is an SSRF," "This is a deserialisation of untrusted input."

3. **Reference.** One link or one identifier. A CWE number (`CWE-89`), an OWASP category (`A03:2021 - Injection`), a CVE (`CVE-2018-18074`), a Trail of Bits / Project Zero post, an internal secure-coding doc, the project's own past advisory. *Some* citation. A comment without a reference is "trust me," which is the wrong register for a security comment.

4. **Suggestion.** A concrete fix. Where possible, use GitHub's `suggestion` Markdown block — the four-backtick fenced block tagged `suggestion` that the author can apply with one click. Where the fix is too large for a suggestion block, a prose description of the fix shape. *Never* "please fix" without saying how.

5. **Severity.** A tag at the start of the comment: `[blocking]`, `[major]`, `[minor]`, `[nit]`, `[question]`. The tag is the metadata that tells the author whether to address this before merge, after merge, or never.

### 4.2 The format, illustrated

A well-formed security comment:

> **[blocking] CWE-918 SSRF in `proxy_fetch`** — `app/proxy.py:42`
>
> The new `proxy_fetch` accepts a user-supplied URL and calls `requests.get(url)` without an allow-list. An attacker can request `http://169.254.169.254/latest/meta-data/iam/security-credentials/` on AWS EC2, or `http://localhost:6379/` to reach an internal Redis, or `file:///etc/passwd` via the `file://` scheme.
>
> Reference: [OWASP A10:2021 SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), CWE-918, CVE-2018-18074 (`requests` Authorization leak on cross-host redirect) as a same-shape precedent.
>
> ```suggestion
>     parsed = urlparse(url)
>     if parsed.scheme not in {"https"}:
>         abort(400, "only https is permitted")
>     ip = socket.gethostbyname(parsed.hostname)
>     if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
>         abort(400, "private IPs are not permitted")
>     return requests.get(f"{parsed.scheme}://{ip}{parsed.path}",
>                         headers={"Host": parsed.hostname},
>                         allow_redirects=False, timeout=5).text[:1000]
> ```
>
> Severity: blocking. The endpoint is reachable from any authenticated user; the cloud-metadata exfiltration class is straightforwardly exploitable.

That comment has every anchor: location (`app/proxy.py:42`), hazard (SSRF), reference (the OWASP cheat sheet, the CWE, a same-shape CVE), suggestion (the inline code block), severity (blocking). The author can act on it without a round-trip.

### 4.3 What a *bad* security comment looks like

> This looks like SSRF. Please fix.

No location (the line anchor on GitHub is implicit but not surfaced in the prose). No specific hazard (which SSRF — DNS rebinding? scheme-smuggling? cloud metadata?). No reference. No suggestion. No severity. The author either ignores it, asks "what do you mean?", or files a follow-up issue. Cost has shifted from reviewer to author, which is the opposite of what the review is supposed to do.

### 4.4 Severity tagging — the discipline

The severity tags are not opinions; they are *decisions about merge gating*.

- **[blocking]** — the PR cannot merge until this is addressed. Use sparingly. A typical reviewer writes maybe one `[blocking]` per ten reviews. Misuse desensitises authors.
- **[major]** — should be addressed before merge, but the reviewer is open to "land and follow up in a separate PR with a tracking issue." The author has the option.
- **[minor]** — should be addressed before merge if convenient; can be deferred.
- **[nit]** — opinion; no action required. Pure style register.
- **[question]** — the reviewer is uncertain and asking for clarification. No action required from the author beyond a reply.

The discipline is to *never* upgrade a tag to manipulate the author into compliance and *never* downgrade a tag because the author is senior. The severity is the assessment of the *finding*, not of the *relationship*.

---

## 5. Approve / Request changes / Comment

After the second pass and the comments, you have three buttons in the GitHub UI:

- **Approve** — you have reviewed the PR and you find no blocking issues. You are vouching for the diff. Future reviewers can rely on your name as one of the approvers.
- **Request changes** — at least one blocking finding exists. The PR cannot merge (on most projects' branch-protection rules) until you (or another reviewer) clears the requested changes.
- **Comment** — you have observations or questions but you are not blocking the merge.

### 5.1 The default

The default for a security-trained reviewer on a security-relevant PR is **Comment**, *not* Approve. Use Approve only when you have actually reviewed every changed file and found nothing security-relevant. Use Request changes the moment you have one `[blocking]` finding.

The most-common reviewer mistake is to Approve a PR after looking only at one file. The Approve button is not "I read this file"; it is "I have reviewed this PR end-to-end." If you did not review end-to-end, leave a Comment.

### 5.2 Escalation

For PRs that touch security-critical surface (auth, crypto, deserialisation, session, payment, PII) but where you do not have the depth to give a complete review, the right action is to **explicitly request a second reviewer** in the comment thread:

> [question] This touches the JWT signing path. I have read it and it looks correct to me, but I want a second pair of eyes from someone who has reviewed this subsystem before. Tagging @<security-team-handle> for a second review.

The mistake is to Approve "to keep the queue moving." A PR queue is supposed to be a quality gate, not a throughput metric.

### 5.3 What "request changes" costs and why to use it anyway

`Request changes` is interpersonally expensive — the author has to revisit the PR, the merge slips by hours or days, and on small teams it can feel adversarial. Many reviewers therefore avoid it. The result, over a year, is a steady drift of medium-severity findings into production.

The fix is to *match the severity tag to the button*: one or more `[blocking]` findings means `Request changes`. The tag does the social work; the button does the merge-gating work. Both are necessary.

---

## 6. A worked example — a real PR

What follows is a synthesised PR shaped after several real ones from public Python projects. The pattern is the point; do not file this exact review upstream anywhere.

### 6.1 The PR (as the author wrote it)

> **PR #1234 — Add `/account/import` endpoint for re-importing account snapshots**
>
> *This adds a new endpoint that lets logged-in users re-import an account snapshot from a previous export. The export endpoint exists already; this is the symmetric import side. The snapshot is a pickled `Account` object plus a SHA-256 hash. We verify the hash before deserialising.*
>
> Files changed:
> - `app/routes/account.py` (+58 / -2)
> - `app/models/account.py` (+12 / -0)
> - `tests/test_account_import.py` (+34 / -0)
> - `docs/api.md` (+18 / -0)
>
> Tests: `pytest` passes. `bandit` shows one new High finding (`B301 pickle.loads`); I added a `# nosec B301 — hash-verified` comment.

### 6.2 The thirty-second pre-review

- **Cue 1 — new input source?** Yes. New HTTP route. *Flag.*
- **Cue 2 — new outbound call?** No.
- **Cue 3 — auth/session/crypto change?** Indirectly. The PR uses a hash to "verify" a payload that is then deserialised. *Flag.*
- **Cue 4 — dependency change?** No.

Two cues. Full security review.

### 6.3 First pass — structure

Read the description: "verify the hash before deserialising." This is a *signed-pickle* attempt, and the standard problem with signed pickle is the verification can be confused (timing-attacks, hash-truncation, wrong-keying) and the *defence in depth* is missing (even a verified pickle has the `__reduce__` RCE surface if the key ever leaks; replace with a typed format). The PR uses `B301 # nosec — hash-verified`, which is exactly the wrong move.

Note: the `B301 # nosec` annotation already gives away the position. The author has seen the warning and chosen to suppress it on the strength of the hash check. That position is reviewable.

### 6.4 Second pass — the relevant hunk

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
    if actual_hash != expected_hash:                              # 35
        abort(400, "hash mismatch")
    account = pickle.loads(payload)  # nosec B301 — hash-verified  # 37
    db.session.merge(account)
    db.session.commit()
    return jsonify({"ok": True, "id": account.id})
```

### 6.5 The review comments

Three security comments and one design comment.

**Comment 1 — Hash is not a signature (CWE-345)**

> **[blocking] CWE-345 Insufficient Verification of Data Authenticity** — `app/routes/account.py:35`
>
> The "hash check" compares the SHA-256 of the payload to a SHA-256 the *client* sent in the same body. An attacker who can craft a payload can also compute and append the SHA-256 of that payload; the check passes for every payload. This is not authentication — it is a checksum.
>
> The correct primitive is an HMAC keyed by a server-side secret the client does not have access to. `hmac.new(SERVER_KEY, payload, hashlib.sha256).digest()` produces a tag the server can verify but the client cannot forge.
>
> Even with HMAC, the deeper finding (see Comment 2) is that pickle should not be deserialised on a route reachable from the network at all; HMAC defends only against the unauthenticated attacker, not against the post-compromise scenario where the HMAC key leaks (Heartbleed-shape, log-leak, CI-secret-leak).
>
> Reference: CWE-345, CWE-353 (Missing Support for Integrity Check), OWASP Deserialization Cheat Sheet (§ "Whitelisting Allowed Classes").
>
> ```suggestion
>     actual_tag = hmac.new(current_app.config["SNAPSHOT_HMAC_KEY"],
>                           payload, hashlib.sha256).digest()
>     if not hmac.compare_digest(actual_tag, expected_hash):
>         abort(400, "tag mismatch")
> ```
>
> Note `hmac.compare_digest` for constant-time comparison; the current `actual_hash != expected_hash` is also a CWE-208 timing-channel finding even if the primitive were correct.
>
> Severity: blocking. The current code is *trivially* exploitable end-to-end into pickle RCE by any authenticated user.

**Comment 2 — Pickle should not be on a route, even with HMAC (CWE-502)**

> **[blocking] CWE-502 Deserialization of Untrusted Data** — `app/routes/account.py:37`
>
> Even with the HMAC fix from Comment 1, `pickle.loads` on a network-reachable route is the canonical CWE-502 hazard. The defence-in-depth recommendation in every Python deserialisation cheat sheet (Python docs warning admonition, OWASP, Trail of Bits, Project Zero) is to never call `pickle.loads` on data that crosses a process boundary. The HMAC keeps an external attacker out; it does not keep a future compromise from chaining into a full RCE.
>
> Replace with a typed serialisation format:
>
> - **Recommended:** `pydantic` schema validated against JSON. Define `class AccountSnapshot(BaseModel): ...` and parse with `AccountSnapshot.model_validate_json(payload)`. The schema is enforced; no callable references are decodable.
> - **Alternative:** `cbor2` with `tag_hook=None` and a schema, or `msgpack` with `strict_map_key=True, raw=False` and a schema.
>
> The `# nosec B301 — hash-verified` annotation should be removed; "hash-verified" is not a sufficient justification for suppressing `B301` (see Lecture 3 of Week 5 on the suppression discipline).
>
> Reference: CWE-502, OWASP Deserialization Cheat Sheet, Python docs `pickle` Warning, CVE-2022-29216 (TensorFlow Keras pickle RCE) and CVE-2024-3568 (`transformers` `trust_remote_code` pickle RCE) as recent same-shape precedents.
>
> Severity: blocking. This is a defence-in-depth finding; even after Comment 1 is fixed, this should be addressed before merge.

**Comment 3 — Constant-time comparison missing (CWE-208)**

> **[minor] CWE-208 Observable Timing Discrepancy** — `app/routes/account.py:35`
>
> Subsumed by the suggestion in Comment 1: replace `actual_hash != expected_hash` with `hmac.compare_digest(actual_tag, expected_hash)`. Flagging separately because it is a recurring class of bug worth its own line in the audit trail.
>
> Reference: CWE-208, `hmac.compare_digest` Python docs.
>
> Severity: minor. The timing attack is academic given the HMAC fix supersedes it; left here for the audit log.

**Comment 4 — Design: snapshots should be re-importable into a new account, not merged into the caller's session (design)**

> **[major] Design — `account_import` performs `db.session.merge(account)` without checking ownership** — `app/routes/account.py:38`
>
> The `@login_required` decorator confirms a user is logged in but does not confirm the snapshot the user is importing was *originally exported by that user*. The current code allows any authenticated user A to import a snapshot exported by user B (perhaps obtained via an export endpoint, a backup leak, or social engineering) into user A's account, mixing the two accounts' state. Worse: `db.session.merge` will *overwrite* fields by primary key, so a snapshot with `id=A.id` will overwrite A with B's data.
>
> The fix is an ownership check on the snapshot itself: the snapshot should include the originating `user_id` as a *signed* field, and the import endpoint should refuse mismatches. The HMAC from Comment 1 (the *server*'s key) makes this enforceable.
>
> Reference: CWE-639 IDOR, CWE-863 Incorrect Authorization, OWASP API4:2023 Unrestricted Resource Consumption (also relevant for the missing payload-size cap).
>
> Severity: major. This is the design-level finding the line-by-line review is most likely to miss; flagging at design register.

### 6.6 The cover summary

```markdown
## Review summary

I have reviewed PR #1234 end-to-end. There are four findings; two are
blocking. The PR cannot be merged in its current state. Specifically:

- **F-1 (blocking, CWE-345):** the "hash check" is not authentication;
  an attacker can compute the hash of any payload they craft. Replace
  with HMAC keyed by a server-side secret. Use `hmac.compare_digest`.
- **F-2 (blocking, CWE-502):** `pickle.loads` on a network-reachable
  route is the canonical Python deserialisation hazard. Replace with a
  pydantic-validated JSON schema or with `cbor2` / `msgpack` plus a
  schema. The "hash-verified" suppression of `bandit B301` is not a
  sufficient justification under the Week 5 suppression discipline.
- **F-3 (minor, CWE-208):** the byte-string comparison is not
  constant-time. Subsumed by the suggested fix to F-1.
- **F-4 (major, CWE-639/CWE-863):** the import endpoint does not check
  that the snapshot was originally exported by the current user.
  `db.session.merge` will silently mix two accounts' state.

Setting "Request changes." Happy to re-review once F-1 and F-2 are
addressed; F-3 and F-4 can be follow-up PRs with tracking issues if the
team prefers.

Citations:
- OWASP Deserialization Cheat Sheet
- CWE-345, CWE-502, CWE-208, CWE-639, CWE-863
- Python docs `pickle` Warning admonition
- CVE-2022-29216 (TensorFlow Keras), CVE-2024-3568 (transformers)
  as same-shape precedents
```

That summary, with the four comment threads, is the artifact. The author can act on every finding without a back-and-forth.

---

## 7. Common reviewer pitfalls

The patterns below are the failure modes the lecture is designed to suppress.

### 7.1 The "everything is a security comment" reviewer

The reviewer who tags every comment `[security]` desensitises the author. After two or three rounds the author cannot tell which comments are blocking and which are nits. The fix is the severity-tag discipline: most comments are not security; tag accordingly.

### 7.2 The "I'll just leave a question" reviewer

The reviewer who systematically uses `[question]` to avoid taking a position. Some questions are honest; many are passive aggression. If you have spotted a hazard, *call it*. Use `[question]` when you genuinely do not know, not as a hedge.

### 7.3 The "approved without reading" reviewer

The reviewer who approves the PR after reading the description and the test diff. The bug class this enables is *exactly* the bug class the test does not cover (because the author would have written a test if they had thought of it). Use `Comment` until you have actually read the diff.

### 7.4 The "request-changes for style" reviewer

The reviewer who uses `Request changes` for `[nit]` comments. This dilutes the meaning of `Request changes`; over time the team learns to ignore it. Reserve the button for `[blocking]`.

### 7.5 The "missing the manifest" reviewer

The reviewer who reads every `.py` file in the diff and skips `requirements.txt`. The most-exploited Python-security class in 2024–2025 is supply-chain. Read the manifest *first*.

### 7.6 The "context-free pattern matcher" reviewer

The reviewer who sees `pickle.loads` and writes "CWE-502 blocking" without reading the surrounding code. Sometimes `pickle.loads` is correct (loading a serialised model from a path the deployer controls, with no network involvement). The pattern is a *cue*; the comment requires the context.

---

## 8. Where this leads

This lecture gave you the framework: four modes, the threat-modeling shortcut, the two-pass review, the five-anchor comment, the three buttons.

Lecture 2 gives you the *patterns* you will pattern-match against in the second pass — the syntactic and structural cues for the canonical hazard classes.

Lecture 3 gives you the *method choice* — when to checklist (cheap, bounded, misses novel design flaws) and when to model (expensive, unbounded, catches what the checklist cannot).

The exercises and the mini-project chain the three together against real, public OSS PRs.

---

## 9. Self-test

- You have ten PRs to review in two hours. Walk through the triage. How long do you spend on each, on average? Which ones get the slow review and why?
- The PR description says "no security implications, just a refactor." The diff touches `auth.py`. Do you trust the description?
- The diff is one line: `requests.get(user_url, verify=False)`. Write the review comment.
- The PR bumps `Pillow` from 9.3.0 to 10.0.0. What do you check before approving?
- A junior reviewer has already approved the PR. You see a `[blocking]` finding. How do you handle the social dynamics without softening the technical content?

Answer in your scratch notes, then start Exercise 1.
