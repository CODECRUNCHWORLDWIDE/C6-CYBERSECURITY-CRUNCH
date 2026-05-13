# Week 5 — Quiz

Ten questions. Lectures closed. Aim for 9/10. The questions are written to be unambiguous; if a question seems to allow more than one answer, re-read the lecture.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Quiz questions about offensive techniques refer to lab demos and   │
│  CVE references. Do not exercise any technique against a service    │
│  you do not operate.                                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

**Q1.** Which CWE describes the canonical hazard of `pickle.load` on untrusted input?

- A) CWE-78 OS Command Injection
- B) CWE-502 Deserialization of Untrusted Data
- C) CWE-918 Server-Side Request Forgery
- D) CWE-330 Use of Insufficiently Random Values

---

**Q2.** A PyYAML call:

```python
data = yaml.load(stream)
```

Which is the minimal correct fix and which CVE drove the API change?

- A) `data = yaml.load(stream, Loader=yaml.UnsafeLoader)` — no CVE was relevant.
- B) `data = yaml.safe_load(stream)` — **CVE-2017-18342** drove PyYAML 5.1's deprecation of the unsafe default.
- C) `data = json.loads(stream.read())` — no CVE, just a format swap.
- D) `data = yaml.load(stream, Loader=yaml.Loader)` — **CVE-2019-20907**.

---

**Q3.** A Flask route:

```python
@app.route("/preview")
def preview():
    url = request.args["url"]
    return requests.get(url, timeout=5).text[:1000]
```

Which OWASP / CWE / fix is correct?

- A) A03 / CWE-89 — parameterise the URL.
- B) A07 / CWE-287 — add `@login_required`.
- C) A10 / CWE-918 — allow-list URLs, refuse private / link-local / loopback IPs, fetch by literal IP, disable redirects.
- D) A05 / CWE-16 — set `DEBUG=False`.

---

**Q4.** Which regular-expression shape is the textbook **catastrophic-backtracking** example?

- A) `^[a-z]+$`
- B) `^(a|b|c)+$`
- C) `^(a+)+$`
- D) `^a{1,100}$`

---

**Q5.** You have a regex you cannot rewrite, the input is partially user-controlled, and `re2` does not support a feature your pattern needs. What is the best partial mitigation, and what is its limitation?

- A) Cap the input length before the regex runs — bounded worst case, but does not address the *cost* of the worst case within the cap.
- B) Add `re.DOTALL` — has no effect on backtracking.
- C) Compile the regex once — has no effect on backtracking.
- D) Catch the `TimeoutError` — stock CPython `re` does not raise on timeout (the engine cannot be interrupted in pure Python).

---

**Q6.** Which Python call is **safe** for generating a session ID?

- A) `random.randint(0, 2**64)`
- B) `hashlib.md5(str(time.time()).encode()).hexdigest()`
- C) `secrets.token_urlsafe(32)`
- D) `uuid.uuid1()`

---

**Q7.** Which `bandit` rule ID flags a `subprocess.run(cmd, shell=True)` call, and at what default severity?

- A) `B301` — Low.
- B) `B501` — Medium.
- C) `B602` — High.
- D) `B602` — Low.

---

**Q8.** You are configuring `pip-audit` in CI. The recommended workflow for a deterministic, auditable supply chain is:

- A) `pip install -r requirements.txt` then `pip-audit` against the live environment.
- B) Hand-edit `requirements.txt` with exact pins, no hashes, commit, audit on every push.
- C) Maintain `requirements.in` with loose pins; `pip-compile` to a hash-pinned `requirements.txt`; commit both; `pip-audit -r requirements.txt --strict` in CI.
- D) Skip lockfiles; rely on Dependabot.

---

**Q9.** You see this line in a Python codebase:

```python
return pickle.loads(redis.get(f"cart:{user_id}"))
```

Which is the most accurate assessment?

- A) Safe — Redis values are controlled by us; pickle is fine because the data is internal.
- B) Conditionally unsafe — if any other code path writes attacker-influenced data into the `cart:{user_id}` key (registration form, import endpoint, admin tool), this is a pickle RCE. Replace with JSON + a schema regardless of the current write paths.
- C) Safe — `pickle.loads` validates the byte stream against the Python type system.
- D) Unsafe but not exploitable — the byte stream comes from Redis, not from the network.

---

**Q10.** Which of the following is a `# nosec` or `# nosemgrep` line that follows the discipline from Lecture 3?

- A) `data = pickle.loads(blob)  # nosec`
- B) `data = pickle.loads(blob)  # nosec B301 — fixture from our own conftest; never network input. See test_fixtures.md.`
- C) `data = pickle.loads(blob)  # we know what we're doing`
- D) `data = pickle.loads(blob)  # noqa`

---

## Answer key

(For instructors only; learners should self-mark after submitting.)

| Q | Answer | Why |
|---|---|---|
| 1 | B | CWE-502 is the standard mapping for `pickle` / `yaml.load` / Java-serialisation hazards. |
| 2 | B | `yaml.safe_load` is the recommended replacement; **CVE-2017-18342** drove the PyYAML 5.1 API split. |
| 3 | C | Allow-list + literal-IP resolution + redirect refusal is the canonical SSRF fix. |
| 4 | C | `(a+)+$` is shape 1 — nested quantifiers over overlapping charclass. |
| 5 | A | Size cap is the partial mitigation when rewrite and `re2` are not options. Limitation: bounded worst-case, not constant-time. |
| 6 | C | `secrets.token_urlsafe(32)` is the only entry that uses the kernel CSPRNG. |
| 7 | C | `B602` flags `subprocess` with `shell=True` at High severity. |
| 8 | C | `pip-compile` lockfile + `pip-audit -r --strict` is the recommended PyPA workflow. |
| 9 | B | The fix is "replace pickle regardless of the current write paths," because trust boundaries grow over time. |
| 10 | B | The discipline is: every suppression cites the rule ID *and* a written reason reviewable in a PR. |

---

*If you scored ≤ 6, re-read Lectures 1-3 and Exercises 1-3 before starting the mini-project. If you scored ≥ 9, you are calibrated.*
