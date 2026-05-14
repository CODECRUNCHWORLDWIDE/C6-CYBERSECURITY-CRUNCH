# Exercise 2 — Spot the Pattern

**Estimated time:** 60 minutes. Pen and paper, or a scratch text file. No tooling required.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Every diff hunk below is a synthesised example, derived from       │
│  patterns documented in public CVEs and public audit reports. Do    │
│  not run any snippet against a deployed service. The exercise is    │
│  reading-only; the goal is pattern recognition, not exploitation.   │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

Twelve small diff hunks follow. For each one, you have **sixty seconds** to:

1. Decide whether the hunk contains a security-relevant hazard (yes / no).
2. If yes: name the **CWE** (or the OWASP category), and write a **one-sentence comment** in the five-anchor style (location, hazard, reference, suggestion shape, severity).
3. If no: write one sentence explaining what *would* have made it a hazard.

The exercise tests pattern matching alone (Lecture 2). It is the warm-up for the fuller method-comparison in Exercise 3.

The drill is **time-boxed**. The point is to see how fast the patterns surface from memory. After all twelve are done, score yourself against the answer key in § 4.

---

## The diffs

Treat each as a hunk added to an existing Python file in a Flask or FastAPI project. Filenames are illustrative.

### Diff 1

```python
# app/routes/preview.py
+@app.route("/preview")
+@login_required
+def preview():
+    url = request.args["url"]
+    return requests.get(url, timeout=5).text[:1000]
```

### Diff 2

```python
# app/services/account.py
+def authenticate(api_key: str) -> bool:
+    expected = os.environ["API_KEY"]
+    return api_key == expected
```

### Diff 3

```python
# app/util/hash.py
+def file_fingerprint(path: str) -> str:
+    with open(path, "rb") as f:
+        return hashlib.md5(f.read()).hexdigest()
```

### Diff 4

```python
# app/services/import_user.py
+def import_user(blob: bytes) -> User:
+    raw = base64.b64decode(blob)
+    return pickle.loads(raw)
```

### Diff 5

```python
# app/routes/files.py
+@app.route("/files/<filename>")
+@login_required
+def serve_file(filename):
+    base = "/var/app/uploads/"
+    return send_file(os.path.join(base, filename))
```

### Diff 6

```python
# app/routes/login.py
+@app.route("/login", methods=["POST"])
+def login():
+    user = User.query.filter_by(name=request.form["name"]).first()
+    if not user:
+        abort(401)
+    if bcrypt.checkpw(request.form["password"].encode(), user.password_hash):
+        login_user(user)
+        return redirect("/dashboard")
+    abort(401)
```

### Diff 7

```python
# app/routes/profile.py
-    return render_template("profile.html", bio=user.bio)
+    return render_template_string(f"<p>{user.bio}</p>")
```

### Diff 8

```python
# requirements.txt
- requests==2.31.0
+ requests
```

### Diff 9

```python
# app/routes/account.py
+@app.route("/account/<int:user_id>/delete", methods=["POST"])
+@login_required
+def delete_account(user_id):
+    user = User.query.get(user_id)
+    if not user:
+        abort(404)
+    db.session.delete(user)
+    db.session.commit()
+    return redirect("/")
```

### Diff 10

```python
# app/cli/admin.py
+def run_diagnostic(target: str) -> str:
+    return subprocess.run(
+        ["ping", "-c", "1", target],
+        capture_output=True, text=True, timeout=2,
+    ).stdout
```

### Diff 11

```python
# app/routes/reset.py
+@app.route("/reset", methods=["GET"])
+def reset():
+    next_url = request.args.get("next", "/")
+    return redirect(next_url)
```

### Diff 12

```python
# tests/conftest.py
+@pytest.fixture
+def loaded_model():
+    blob = open("tests/fixtures/model.pkl", "rb").read()
+    return pickle.loads(blob)
```

---

## How to record your answers

Open `findings.md`. For each diff, write:

```markdown
## Diff 1

- **Hazard? (Y/N):**
- **CWE:**
- **One-sentence comment:**
- **Severity:** [blocking] / [major] / [minor] / [nit] / [question]
```

Time yourself. Sixty seconds per diff. Total: twelve minutes for the drill, the rest of the hour for the write-up and self-scoring.

---

## Answer key

(Hidden until you finish. Self-mark.)

### Diff 1 — SSRF (CWE-918)

- **Hazard? Y.**
- **CWE-918** SSRF.
- **Comment:** `app/routes/preview.py:4` — `requests.get(user_url)` on an authenticated route is CWE-918. Attacker can request cloud-metadata IPs (`169.254.169.254` on AWS), internal services (`127.0.0.1`, RFC1918), or `file://` schemes. Apply allow-list of schemes, resolve to literal IP, refuse private / loopback / link-local, disable redirects.
- **Severity:** `[blocking]`.

### Diff 2 — Timing channel on API-key comparison (CWE-208)

- **Hazard? Y.**
- **CWE-208** Observable Timing Discrepancy.
- **Comment:** `app/services/account.py:3` — `api_key == expected` is not constant-time. Use `hmac.compare_digest(api_key, expected)`. Encode both sides to bytes first.
- **Severity:** `[major]`.

### Diff 3 — MD5 used for non-security file fingerprinting (CWE-327 candidate, often false positive)

- **Hazard? Conditional.** This pattern fires `bandit B303` but is often *correct*: file dedup, cache keys, ETags do not require collision resistance against an adversary. The finding is a `[question]`: is this for security (collision-resistance required → use SHA-256) or non-security (cache key → keep MD5 but annotate)?
- **CWE-327** *if* security.
- **Comment:** `app/util/hash.py:3` — MD5 fingerprint; clarify whether this is content-addressing for caching (acceptable; annotate `# nosec B303 — non-security`) or for security (replace with SHA-256). Pattern is a `bandit B303` hit.
- **Severity:** `[question]`.

### Diff 4 — Pickle on input (CWE-502)

- **Hazard? Y.**
- **CWE-502** Deserialization of Untrusted Data.
- **Comment:** `app/services/import_user.py:3` — `pickle.loads` on any caller-supplied `blob` is CWE-502 RCE. Replace with `pydantic` schema validated against JSON, or with `cbor2`/`msgpack` plus a schema. Cite `bandit B301`, Python docs `pickle` Warning, CVE-2022-29216 / CVE-2024-3568 as same-shape precedents.
- **Severity:** `[blocking]`.

### Diff 5 — Path traversal (CWE-22)

- **Hazard? Y.**
- **CWE-22** Path Traversal.
- **Comment:** `app/routes/files.py:5` — `os.path.join(base, filename)` does not prevent `../` traversal; `serve_file("../../etc/passwd")` reads outside the upload dir. Use `Path(base).resolve()` + `target.resolve()` + `target.is_relative_to(base)` (Python 3.9+) and refuse on mismatch.
- **Severity:** `[blocking]`.

### Diff 6 — Username enumeration (CWE-204) plus missing rate-limit (CWE-307)

- **Hazard? Y.**
- **CWE-204** / **CWE-307**.
- **Comment:** `app/routes/login.py:4-8` — distinct error paths for "user not found" vs. "password wrong" are a username-enumeration channel; the route also has no rate-limit. Return identical responses (same status, same body, same timing) on both failure modes; add per-username and per-IP rate-limiting (e.g., `Flask-Limiter`).
- **Severity:** `[major]`.

### Diff 7 — SSTI / XSS via `render_template_string` (CWE-1336 / CWE-79)

- **Hazard? Y.**
- **CWE-1336** Improper Neutralization of Special Elements Used in a Template Engine (SSTI), plus CWE-79 XSS.
- **Comment:** `app/routes/profile.py` — `render_template_string(f"<p>{user.bio}</p>")` is SSTI: `user.bio` is interpreted as Jinja, allowing `{{ config.SECRET_KEY }}` or worse. Use a real template file (`render_template("profile.html", bio=user.bio)`) with auto-escaping, or `Markup.escape(user.bio)` inline.
- **Severity:** `[blocking]`.

### Diff 8 — Unpinned dependency (supply chain)

- **Hazard? Y.**
- **No CWE (supply-chain hygiene), OWASP A06:2021** Vulnerable and Outdated Components.
- **Comment:** `requirements.txt` — `requests` without a pin allows transitive resolution to drift on every install. Re-pin to a specific version (`requests==2.32.3` as of 2025-Q1) and commit a lockfile (`pip-compile` produces `requirements.txt` with hashes).
- **Severity:** `[major]`.

### Diff 9 — Missing authorization / IDOR (CWE-639 / CWE-863)

- **Hazard? Y.**
- **CWE-639** IDOR / **CWE-863** Incorrect Authorization.
- **Comment:** `app/routes/account.py:1-8` — `@login_required` confirms a user is logged in but the route deletes the account specified by `user_id` from the URL, with no check that `user_id == current_user.id`. Any authenticated user can delete any other user's account by guessing IDs. Add `if user_id != current_user.id and not current_user.is_admin: abort(403)`.
- **Severity:** `[blocking]`.

### Diff 10 — Subprocess with user input, list-form (potentially safe)

- **Hazard? N (likely false positive), but `[question]` worth asking.**
- **Notes:** `subprocess.run(["ping", "-c", "1", target])` with `shell=False` (default) is *generally* safe against command injection because args are not shell-parsed. The residual hazard is `target` containing flags (`-f` to flood) or being a hostname `target = "-c"` that confuses `ping`'s arg parser. Validate `target` against an IP/hostname regex; refuse anything starting with `-`.
- **Severity:** `[minor]` or `[question]`.

### Diff 11 — Open redirect (CWE-601)

- **Hazard? Y.**
- **CWE-601** URL Redirection to Untrusted Site.
- **Comment:** `app/routes/reset.py:3` — `redirect(request.args["next"])` redirects to any URL the client supplies. Attacker crafts `/reset?next=https://evil.example/` and uses the trusted domain as a phishing pivot. Allow-list relative paths only (`if not next_url.startswith("/") or next_url.startswith("//"): next_url = "/"`).
- **Severity:** `[major]`.

### Diff 12 — Pickle in a *test fixture* (likely false positive)

- **Hazard? N.**
- **Notes:** `pickle.loads` of a file in `tests/fixtures/` that ships with the repo is *not* CWE-502 — the file is trusted by definition (it is part of the source tree under version control). `bandit B301` will fire; the correct response is a `# nosec B301 — test fixture from tests/fixtures/; never network input` annotation. If the fixture is generated from `pickle.dumps` of trusted data at test-setup time, the test is fine.
- **Severity:** `[nit]` (suggest the annotation) or no comment.

---

## Self-scoring

| Score | Interpretation |
|-------|----------------|
| 11-12 | Pattern shelf is loaded. Move on to Exercise 3. |
| 9-10  | Good. Re-read Lecture 2 § 7 (the diff patterns you missed). |
| 6-8   | Re-read Lecture 2 fully; re-run the drill in 24-48 hours with new examples. |
| ≤ 5   | Re-read Lecture 2 and the Week 5 lectures (the pattern catalogue overlaps); re-run. |

Pattern matching is the *cheapest* of the three review methods. Speed and accuracy here free up budget for the model-based review in Exercise 3 and the mini-project.

---

## Submission

Commit `exercise-02-spot-the-pattern/findings.md` with all twelve entries and your self-score at the bottom.

The honest self-score is the artifact. A score of 7/12 with a clear note ("missed Diff 6 — did not see the enum side-channel without prompt; missed Diff 11 — forgot CWE-601") is *more* valuable for your portfolio than a claimed 12/12 with no reflection.
