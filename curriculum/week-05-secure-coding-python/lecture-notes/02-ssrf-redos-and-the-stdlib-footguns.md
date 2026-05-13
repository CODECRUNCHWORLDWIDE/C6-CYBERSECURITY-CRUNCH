# Lecture 2 — SSRF, ReDoS, and the Stdlib Footguns

> *Three classes of Python-specific hazard that share a property: the dangerous call looks like the safe call. `requests.get(url)` reads like a fetch; on the wrong URL it is an exfiltration vector. `re.match(pattern, text)` reads like a parse; on the wrong pattern it is a denial of service. `subprocess.run(cmd, shell=True)` reads like a shell-out; it is an injection sink. This lecture covers all three and then catalogues the smaller standard-library traps so you have the full surface in one place.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Every payload below is for a server you ran on your own machine,   │
│  on 127.0.0.1, on a non-default port. Do not fetch a URL you do     │
│  not control; do not exercise a ReDoS payload against any service   │
│  you do not operate.                                                │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers:

- **SSRF in Python HTTP clients** — `requests`, `urllib.request`, `httpx`, `aiohttp`. The default behaviours, the cloud-metadata exfiltration class, the allow-list / literal-IP-resolution fix pattern.
- **Regular-expression denial of service (ReDoS)** — Python's `re` is a backtracking engine. The catastrophic shapes. The detection. The three documented fixes.
- **The standard-library footgun catalogue** — `subprocess`, `os.system`, `eval` / `exec`, `tempfile.mktemp`, `xml.etree`, `random` for security, `time.time()` for tokens.

---

## 1. Server-Side Request Forgery in Python HTTP clients

### 1.1 The vulnerability

Week 4's `A10` lecture covered SSRF at the OWASP-category level. This lecture is the *Python-language* zoom — what each HTTP client in the standard library and the popular third-party ecosystem does and does not protect against by default, and what the fix looks like.

The vulnerability is: an HTTP client running inside your service makes an outbound request to a URL the *attacker* chose. The cloud-metadata case is the most famous (`http://169.254.169.254/latest/meta-data/iam/security-credentials/` on EC2 leaks IAM creds), but the class is broader. Any of these is an SSRF:

- Fetching `http://internal-admin.corp.local/healthz` from inside the VPC.
- Fetching `file:///etc/passwd` because `urllib` honours `file://`.
- Fetching `gopher://localhost:6379/_FLUSHALL` to talk to a co-located Redis.
- Fetching `http://localhost:5000/admin/delete-all-users` because your own management endpoint is bound to localhost and trusts localhost.

The bug is in *trusting the URL*. The bug is the same bug whether the URL came from a query parameter, a form field, a JSON body, a webhook payload, or a YAML config that was fetched from a registry.

### 1.2 The vulnerable shape

```python
# ssrf_bad.py — DO NOT DEPLOY.
import requests
from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/preview")
def preview():
    url = request.args.get("url")
    if not url:
        abort(400)
    # VULNERABLE — A10 SSRF. CWE-918.
    r = requests.get(url, timeout=5)
    return r.text[:1000]

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002)
```

An attacker calls `/preview?url=http://169.254.169.254/latest/meta-data/` and the service returns the cloud-metadata response. **CVE-2018-18074** (`requests` sent the `Authorization` header through cross-host redirects) and **CVE-2023-32681** (`requests` proxy-auth leak on redirect) are the two `requests`-library CVEs every Python developer should know in this space; both are receipts of "redirects make SSRF worse than the static URL case suggests."

### 1.3 What each client does by default

Behaviour differs between clients and matters a great deal.

- **`urllib.request.urlopen`** (stdlib): honours `file://`, `http://`, `https://`, `ftp://`. Will happily open `file:///etc/passwd`. Redirects followed by default to a configurable cap. *No* allow-list, *no* IP-literal filtering.
- **`requests.get`**: honours `http://`, `https://`, and `file://` only with explicit local-file adapter (default: no). Redirects followed by default to 30 hops. Honours environment proxies. `verify=True` by default. No IP-literal filtering by default.
- **`httpx.get`**: very similar to `requests`. Redirects *not* followed by default — you have to pass `follow_redirects=True`. This default is friendlier.
- **`aiohttp`**: redirects followed by default. Honours env proxies.
- **`urllib3.PoolManager().request`**: redirects followed by default; lower-level.

None of these clients has a built-in deny-list for RFC1918 / link-local / loopback addresses. That filter must be added by you.

### 1.4 The fix shape — allow-list + literal-IP resolution

The correct fix has two parts:

**Part A: allow-list the hostnames.** "URL preview can only fetch from this list of explicitly approved hosts." This is the strongest fix and it is the right fix when the use case allows it (webhooks from a small set of partners, image proxies for a known CDN, etc.).

```python
ALLOW = {"example.com", "images.example.com", "cdn.example.org"}

from urllib.parse import urlparse
def url_ok(url: str) -> bool:
    p = urlparse(url)
    return p.scheme in {"http", "https"} and p.hostname in ALLOW
```

**Part B: resolve hostnames to IPs first; refuse private / link-local IPs.** When you cannot allow-list, you must defend against attacker-chosen DNS records resolving to private space. The fix is *resolve once, fetch the IP literally*, and refuse private IPs.

```python
import ipaddress
import socket
from urllib.parse import urlparse

import requests

DENY_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),     # link-local incl. AWS metadata.
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT.
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def safe_get(user_url: str, timeout: float = 5.0) -> requests.Response:
    p = urlparse(user_url)
    if p.scheme not in {"http", "https"}:
        raise ValueError("scheme not allowed")
    if not p.hostname:
        raise ValueError("no host")
    # Resolve once, refuse private IPs, fetch by literal IP with Host header.
    infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    for fam, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if any(ip in net for net in DENY_NETS):
            raise ValueError(f"refusing private IP: {ip}")
    # Disable redirects (each redirect is a fresh SSRF opportunity).
    return requests.get(user_url, timeout=timeout, allow_redirects=False)
```

This is not subtle and it is not optional. Every Python SSRF advisory of the last five years could have been prevented by the above pattern. CWE-918 maps directly here; ASVS v4.0.3 §10.3.1 codifies the requirement.

### 1.5 Residual hazards

Even with the fix above, two residuals remain:

- **DNS rebinding.** The attacker resolves `evil.example.com` to a public IP for your DNS check, then re-resolves it to `169.254.169.254` for the actual fetch. The fix above mitigates this by resolving *once* and fetching the literal IP; if your `requests` re-resolves between the check and the fetch (default behaviour of stock `getaddrinfo` plus stock `requests`), you have a window. The complete fix uses a `socket`-level adapter that does the literal-IP fetch yourself.
- **Egress network policy as a backstop.** The above is an application-layer defence. In an AWS / GCP / Azure deployment, enforce the same allow-list at the network layer (security group, VPC firewall, egress proxy). Defence in depth.

---

## 2. Regular-expression denial of service (ReDoS)

### 2.1 The hazard

Python's `re` module uses a backtracking regex engine (NFA with backtracking). For *most* patterns, the engine is fast and well-behaved. For a small but stable set of pattern shapes, adversarial input causes the engine to explore an exponentially-growing tree of alternative matches before failing. Wall-clock time grows as 2^n in the input length; "n=30" can take days.

That is regular-expression denial of service. The hazard is a CWE-1333 finding and shows up under OWASP A06 (vulnerable components) when the bad regex is in a dependency, and under "secure coding" when it is in your own.

### 2.2 The pattern catalogue

Three shapes account for the overwhelming majority of catastrophic regexes:

**Shape 1: Nested quantifiers — `(a+)+$`.** The outer `+` and the inner `+` both match the same character class; on an input that *almost matches* (e.g., `"aaaaaaaa!"`), the engine tries every partition of the `a`s between the inner and outer group.

```python
import re
import time

PAT = re.compile(r"(a+)+$")
for n in (10, 15, 20, 22, 24, 26):
    s = "a" * n + "!"
    t0 = time.time()
    PAT.match(s)
    print(n, time.time() - t0)
# 10  ~0
# 15  ~0
# 20  ~0.05
# 22  ~0.2
# 24  ~0.8
# 26  ~3.2
```

The doubling pattern (each `n` doubles the time) is the diagnostic. If your regex doubles, you have catastrophic backtracking.

**Shape 2: Alternation with overlap — `(a|aa)+$`.** Two alternatives can match the same prefix; the engine tries every split.

**Shape 3: Lookaround with user input — `(?=.*X)(?=.*Y)(?=.*Z).*` on a long string.** Each lookahead is a fresh scan; combined with backtracking elsewhere, the cost compounds.

The CVE catalogue is long. A few examples to ground the abstraction:

- **CVE-2020-7720** — NLTK's `word_tokenize` regex was catastrophic on certain Unicode inputs.
- **CVE-2022-40898** — `wheel` (the Python packaging tool) had a ReDoS in its tag-parsing regex; `pip install` of a malicious wheel could DoS the installer.
- **CVE-2023-37920** — `certifi` follow-up.

If `pip install` itself shipped a ReDoS, your application's regexes deserve a second look.

### 2.3 The doubling test — how to detect a candidate

For any regex over user input, write a quick benchmark:

```python
# redos_check.py
import re
import time

def doubling_test(pat: str, base: str, repeats=(10, 15, 20, 25, 30)) -> list[tuple[int, float]]:
    compiled = re.compile(pat)
    results = []
    for n in repeats:
        s = base * n + "!"
        t0 = time.time()
        try:
            compiled.match(s)
        except Exception:
            pass
        results.append((n, time.time() - t0))
    return results

print(doubling_test(r"(a+)+$", "a"))
```

A linear or constant-time growth: regex is fine. A doubling growth (each row is ~2x the last): catastrophic backtracking; rewrite.

### 2.4 The three fixes

**Fix 1: Rewrite as a linear pattern.** Most catastrophic regexes have a linear equivalent. `(a+)+$` is equivalent to `a+$` (both match "one or more `a`s at end of line"); the latter has no nested quantifier. `[a-z]+@[a-z]+\.[a-z]+` is linear; `([a-z]+)*@[a-z]+\.[a-z]+` is catastrophic. Read the regex; remove the redundant nesting.

For email validation specifically: do **not** write your own regex. Use `email-validator` (`pip install email-validator`) and read its source for the right shape.

**Fix 2: Switch the engine to `re2`.** Google's `re2` is a linear-time regex engine (Thompson NFA construction; no backtracking). It does not support all the features of the Python `re` module (no backreferences, no lookaround), but it covers the safe subset. The `google-re2` Python binding (`pip install google-re2`) is the drop-in.

```python
import re2 as re   # drop-in alias for the safe subset of features

PAT = re.compile(r"(a+)+$")     # still compiles; runs in linear time.
```

`re2` is what you want when (a) the regex is unavoidable and (b) the input is adversarial. Performance against benign input is similar; performance against adversarial input is *thousands* of times better.

**Fix 3: Impose a budget.** Cap the input size; cap the wall-clock. Python 3.11+ exposes `re.match(..., timeout=...)` is *not* available in stock CPython (the engine cannot be interrupted mid-match); but you can wrap the call in a `signal.alarm` (Unix) or run it in a subprocess with a timeout. The simpler fix is to cap input size:

```python
MAX_LEN = 1024
if len(user_input) > MAX_LEN:
    raise ValueError("input too long")
match = PAT.match(user_input)
```

A regex with O(2^n) worst case is still O(2^MAX_LEN) — at `MAX_LEN=1024` that is still useless as a hard bound, but it makes the *practical* worst case manageable when combined with rate limits.

### 2.5 Defender side

- `semgrep` ships a `python.lang.security.audit.dangerous-regex` set of rules that flags common catastrophic shapes.
- CodeQL ships `py/redos` and `py/polynomial-redos` for Python.
- For findings discovered in dependencies, the response is "upgrade past the CVE" — which is `pip-audit`'s job (Lecture 3).

---

## 3. The standard-library footgun catalogue

These are not novel attack classes; they are the standard-library calls that are dangerous-by-default and you need to recognise on sight. `bandit` flags each one with a specific rule ID; the table below cross-references.

### 3.1 `subprocess.run(args, shell=True)` and `os.system(cmd)`

**Hazard.** Either of these passes the string to `/bin/sh -c`, which is an injection sink for any string built from user input. **CWE-78**. The classic bug:

```python
# subproc_bad.py
import subprocess
host = request.args["host"]
subprocess.run(f"ping -c 1 {host}", shell=True)
# host="evil.local; rm -rf /" → executed.
```

**Fix.** Pass `args` as a list and never `shell=True`:

```python
import subprocess
import shlex
host = request.args["host"]
# Validate first (the regex is anchored and *not* catastrophic):
if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
    abort(400)
subprocess.run(["ping", "-c", "1", host], check=True, timeout=5)
```

`bandit` `B602` (subprocess with `shell=True`), `B605` (`os.system`), `B607` (start_process_with_partial_path).

### 3.2 `eval`, `exec`, `compile` on tainted input

**Hazard.** Self-evident. **CWE-94**. Any `eval(user_input)` is an RCE. So is `exec(user_input)`. So is `compile(user_input, ...)` if you then run the bytecode.

**Fix.** Do not use these on tainted input. If you need to evaluate expressions, use `ast.literal_eval` (which only evaluates *literals* — numbers, strings, tuples, lists, dicts, booleans, `None` — and refuses everything else). For expression languages, use a real expression-language library (`asteval`, `simpleeval`, or a domain-specific parser).

```python
import ast
ast.literal_eval("1 + 1")          # ValueError — not a literal.
ast.literal_eval("'1' + '1'")      # ValueError — not a literal.
ast.literal_eval("{'a': 1}")       # {'a': 1} — fine.
```

`bandit` `B102` (`exec`), `B307` (`eval`).

### 3.3 `tempfile.mktemp` — TOCTOU

**Hazard.** `mktemp` returns a name that "is suitable for use" — i.e., the function does not create the file. Between the function returning the name and your code opening it, another process can create that path as a symlink and your write goes wherever the symlink points. **CWE-377**. The CPython docs deprecated `mktemp` in Python 2.3.

**Fix.** `tempfile.NamedTemporaryFile`, `tempfile.mkstemp`, or `tempfile.mkdtemp`. All three open-or-create the file/directory atomically.

```python
import tempfile

# Wrong:
path = tempfile.mktemp()
with open(path, "w") as f:   # <-- TOCTOU window between mktemp and open.
    f.write("...")

# Right:
with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
    f.write("...")
    path = f.name
```

`bandit` `B306` (`mktemp_q`).

### 3.4 `xml.etree.ElementTree.parse` — XXE / billion-laughs

**Hazard.** The CPython XML libraries are vulnerable by default to external-entity references, billion-laughs entity expansion, external-DTD fetches, and quadratic-blowup attacks. The CPython docs themselves recommend `defusedxml`. **CWE-611**, **CWE-776**.

**Fix.** `pip install defusedxml`. Drop-in replacement.

```python
# Vulnerable:
import xml.etree.ElementTree as ET
tree = ET.parse(stream)

# Patched:
import defusedxml.ElementTree as ET
tree = ET.parse(stream)
```

`bandit` `B313` through `B320` cover the various XML APIs. `semgrep` `python.lang.security.audit.xml` rules.

### 3.5 `random` for security; `time.time()` for tokens

**Hazard.** `random` uses Mersenne Twister; the state can be reconstructed from ~624 consecutive outputs. *Anything* an attacker ever sees that came out of `random` leaks the seed and the future outputs. **CWE-330**. `time.time()` is even worse — it has no entropy at all.

**Fix.** `secrets.token_urlsafe(32)`, `secrets.token_bytes(32)`, `secrets.choice(...)`. These wrap `os.urandom`, which reads from the kernel CSPRNG (`/dev/urandom` or `getrandom(2)` on Linux).

```python
# Wrong:
import random, time, hashlib
session_id = hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()

# Right:
import secrets
session_id = secrets.token_urlsafe(32)
```

The MD5 / SHA1 / SHA256 wrapping above is *worse than nothing* because it suggests cryptography is happening when in fact the entropy at the input is ~30 bits. `bandit` `B311` (`random` use; default severity is low, **raise it**), `B324` (`hashlib` MD5/SHA1).

### 3.6 The full table

| Footgun                                 | CWE     | `bandit`     | Idiomatic fix                                          |
|-----------------------------------------|---------|--------------|--------------------------------------------------------|
| `pickle.load(untrusted)`                | CWE-502 | `B301`       | JSON + pydantic, msgpack + HMAC, safetensors           |
| `yaml.load(untrusted)`                  | CWE-502 | `B506`       | `yaml.safe_load`                                       |
| `subprocess(shell=True)`, `os.system`   | CWE-78  | `B602/B605`  | `subprocess.run([...], shell=False)`                   |
| `eval`, `exec` on tainted               | CWE-94  | `B307/B102`  | `ast.literal_eval` or a real parser                    |
| `tempfile.mktemp`                       | CWE-377 | `B306`       | `NamedTemporaryFile` / `mkstemp`                       |
| `xml.etree.ElementTree.parse`           | CWE-611 | `B313-B320`  | `defusedxml`                                           |
| `random` for security                   | CWE-330 | `B311`       | `secrets`                                              |
| `hashlib.md5/sha1` for passwords        | CWE-327 | `B324`       | `argon2-cffi`                                          |
| `requests.get(user_url)` no filter      | CWE-918 | (semgrep)    | allow-list + literal-IP resolution                     |
| Catastrophic regex on user input        | CWE-1333| (semgrep)    | rewrite / `re2` / input cap                            |
| `tarfile.extractall` no filter          | CWE-22  | `B202`       | `extractall(filter="data")` (Py ≥ 3.12)                |
| `assert` for security checks            | CWE-617 | `B101`       | raise an explicit error                                |
| `Flask(debug=True)` in prod             | CWE-489 | `B201`       | `DEBUG=False`, env-driven                              |
| Hardcoded credentials                   | CWE-798 | `B105/B106`  | env vars + a secret store                              |

The `bandit` rule numbers are stable; cite them in your audit reports.

---

## 4. The audit method

Given a Python codebase you do not know:

1. **Search for the dangerous import surface.**
   ```bash
   grep -rE "import pickle|import yaml|import subprocess|import xml\.etree|from xml\." .
   grep -rE "\\beval\\(|\\bexec\\(|tempfile\\.mktemp|shell=True|os\\.system" .
   grep -rE "random\\.|time\\.time\\(\\)" . | grep -iE "token|session|nonce|password"
   ```
2. **For each `pickle.load` / `yaml.load`,** trace upstream: where does the input come from?
3. **For each `subprocess(shell=True)` / `os.system`,** trace the command string upstream: is any part of it user-controlled?
4. **For each `requests.get` / `urlopen` / `httpx.get`,** is the URL user-controlled?
5. **For each `re.compile(...)`,** is the *input* user-controlled? Then run the doubling test on the *pattern*.

The audit is mechanical and that is the point. The categories are stable; the call sites are stable; the test for each is a one-liner. The *triage* (true positive / accept risk / false positive) is the work.

---

## 5. Summary

- **SSRF** in Python HTTP clients is the same SSRF as anywhere else; the Python flavour is that *none* of the popular clients filters private / link-local / loopback IPs by default. The fix is allow-list-or-literal-IP. **CVE-2018-18074**, **CVE-2023-32681** are the receipts of even the library itself getting cross-host redirect handling wrong.
- **ReDoS** is the algorithmic class. Python's `re` is a backtracking engine; nested quantifiers and overlapping alternations go catastrophic on adversarial input. The doubling test is the diagnostic. Rewrite to linear, switch to `re2`, or cap the input — pick the one that matches the use case. **CVE-2022-40898** is `pip install` itself shipping the bug.
- **The stdlib footguns** — `subprocess(shell=True)`, `eval`, `tempfile.mktemp`, `xml.etree`, `random`-for-security — are not novel; they are the stable set you must recognise on sight. The `bandit` rule numbers are the index.
- The audit method is mechanical: grep for the dangerous surface, walk taint upstream, score the findings.

Lecture 3 takes you from "I can find these by hand" to "I have CI that finds these on every PR."

---

*End of Lecture 2.*
