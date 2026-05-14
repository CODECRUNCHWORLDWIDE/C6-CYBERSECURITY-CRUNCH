# Week 6 — Quiz

Ten questions. Lectures closed. Aim for 9/10. The questions are written to be unambiguous; if a question seems to allow more than one answer, re-read the lecture.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Quiz questions about review and exploitation techniques refer to   │
│  published CVEs, public audit reports, and synthesised diffs.       │
│  Do not exercise any technique against a service you do not         │
│  operate.                                                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

**Q1.** Lecture 1 describes a one-minute pre-review check. Which of the following is **not** one of the four cues that should trigger a slower security review?

- A) A new HTTP route or CLI flag is added.
- B) A new outbound call (`requests.get`, `subprocess.run`, file write outside a known dir) is added.
- C) The PR modifies, removes, or relocates any function decorated with `@login_required`, `@requires_auth`, or similar.
- D) The PR description contains the word "refactor."

---

**Q2.** The five-anchor comment format requires five elements. Which of the following is **not** one of them?

- A) Location (`path/to/file.py:LINE`).
- B) Hazard (one-sentence vulnerability class name).
- C) The author's GitHub handle and seniority level.
- D) Reference (a CWE / CVE / OWASP / audit-report citation).

---

**Q3.** A PR adds the following diff. Which is the most accurate review comment?

```python
@app.route("/account/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_account(user_id):
    user = User.query.get(user_id)
    if not user:
        abort(404)
    db.session.delete(user)
    db.session.commit()
    return redirect("/")
```

- A) `[nit]` — consider using `get_or_404` for brevity.
- B) `[blocking]` CWE-863 — `@login_required` confirms a user is logged in but does not check that `user_id == current_user.id`; any authenticated user can delete any other user's account by guessing IDs.
- C) `[major]` CWE-89 — SQL injection via `user_id`.
- D) `[blocking]` CWE-918 — SSRF via the `/account/<int:user_id>/delete` route.

---

**Q4.** A reviewer says: "I walked the C6 short checklist; every applicable item is `✓`." On a PR that adds a signed-token mechanism using `hashlib.sha256(payload + key)`, what is missing from this review?

- A) Nothing; if every checklist item passes, the PR is clean.
- B) A model-based check — the hash-with-key construction is length-extensible and is not HMAC; this finding is not on a generic short checklist and surfaces only from a model of the trust chain through the signing primitive.
- C) A pattern-match for `pickle.loads`, which the checklist does not cover.
- D) The reviewer should `Request changes` regardless because the checklist is incomplete.

---

**Q5.** A PR adds `requests.get(user_url)` on a new authenticated route. The reviewer comments `[blocking] CWE-918 SSRF`. The author replies "the route is behind `@login_required`, so it is not exposed publicly." What is the correct counter-reply?

- A) "Agreed; downgrade to `[minor]`."
- B) "Authentication does not mitigate SSRF — the attacker is the authenticated user. SSRF lets *that* user reach internal services (cloud metadata, RFC1918, loopback) the user could not otherwise reach. The fix is the allow-list / literal-IP / no-redirects pattern."
- C) "Authentication adds a CSRF token; the SSRF is therefore not exploitable."
- D) "Accept the risk and add a `# nosec` annotation."

---

**Q6.** Which of the following is the best canonical primary source for *how to read a security audit report*?

- A) The OWASP Top 10 PDF.
- B) The published reports at `publicaudits.org` / Trail of Bits publications and the Google Project Zero blog.
- C) The CWE Top 25 list.
- D) Any security-themed Twitter / X thread.

---

**Q7.** The diff bumps `requests` from `2.31.0` to `2.32.3`. Which is the most useful review comment?

- A) `[nit]` — version bump.
- B) `[blocking]` — never bump dependencies.
- C) `[minor]` — confirm the changelog and the project's security advisories for `requests` 2.32.x do not regress against the project's TLS configuration; check `pip-audit` is happy on the bumped version; check that any pinned indirect dependencies still resolve.
- D) `[question]` — why is the team using `requests` at all?

---

**Q8.** A PR contains the line:

```python
sig = hashlib.sha256(payload + current_app.config["SIGNING_KEY"]).hexdigest()
```

Which is correct?

- A) Safe; SHA-256 is a strong hash, and the secret is included in the input.
- B) Unsafe; this construction is vulnerable to length-extension. Use `hmac.new(key, payload, hashlib.sha256).digest()` instead. CWE-345 / CWE-916.
- C) Safe but slow; switch to MD5 for performance.
- D) Unsafe; use `random.choice` for the signature instead.

---

**Q9.** Which of the following best describes the *decision rule* between checklist-based and model-based review?

- A) Always use the checklist; the model is a luxury.
- B) Always use the model; the checklist is for juniors.
- C) Default to checklist; switch to model when the diff crosses a security-critical boundary (new input source, new outbound call, auth/session/crypto change, dependency-manifest change).
- D) Use whichever takes less time on a given PR.

---

**Q10.** Which of the following is the appropriate `gh` CLI invocation to pull PR #1234 from the current repo onto a local branch?

- A) `gh pr fetch 1234`
- B) `gh pr checkout 1234`
- C) `gh fork 1234`
- D) `gh pr merge 1234`

---

## Answer key

(For instructors only; learners should self-mark after submitting.)

| Q | Answer | Why |
|---|---|---|
| 1 | D | The word "refactor" in the description is not a cue; in fact a refactor that touches auth or parsing should still trigger the slow review. The four cues are: new input source, new outbound call, auth/session/crypto change, dependency-manifest change. |
| 2 | C | The five anchors are: Location, Hazard, Reference, Suggestion, Severity. The author's handle and seniority are explicitly *not* part of the format (the severity is about the finding, not the author). |
| 3 | B | The auth check confirms login; it does not confirm ownership. Classic IDOR + missing authorization. |
| 4 | B | The checklist catches omissions; it misses subtle cryptographic constructions like hash-with-key length-extension. The model surfaces this finding. |
| 5 | B | Authentication is not an SSRF mitigation; SSRF defends against the authenticated user, not against the unauthenticated public. The fix is the OWASP SSRF Cheat Sheet pattern. |
| 6 | B | Trail of Bits public audits and Project Zero are the canonical primary sources for *audit-report shape* in the public domain. |
| 7 | C | Version bumps require changelog reading and `pip-audit` verification; never approve a bump without those checks. |
| 8 | B | `hashlib.sha256(payload + key)` is length-extensible. Use `hmac.new(key, payload, hashlib.sha256)`. CWE-345 / CWE-916. |
| 9 | C | The decision rule is "default to checklist, switch to model when the diff crosses a security-critical boundary." See Lecture 3 § 3. |
| 10 | B | `gh pr checkout NNNN` is the verb. The others are not real `gh` subcommands or do something else. |

---

*If you scored ≤ 6, re-read Lectures 1-3 and Exercises 1-3 before starting the mini-project. If you scored ≥ 9, you are calibrated.*
