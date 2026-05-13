# Lecture 1 — The Deserialization Trap: pickle, yaml, and Friends

> *Deserialisation is the canonical "looks innocuous, is RCE" hazard class in Python. Two characters of standard-library API — `pickle.load` — turn a network byte stream into arbitrary Python execution. The fix is not subtle and has been documented for two decades; the bug nonetheless ships, weekly, in production code. This lecture covers why the trap is shaped the way it is, the equivalent trap in `yaml.load`, the smaller traps in `tarfile`, `shelve`, and `numpy.load`, and the patterns that actually work to replace them.*

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Every payload in this lecture is for local lab use only. The       │
│  pickle RCE shown here pops a calculator (or a `touch` to /tmp)     │
│  on your own machine; do not run a pickle payload of any shape      │
│  against a service you do not operate.                              │
└─────────────────────────────────────────────────────────────────────┘
```

This lecture covers:

- **`pickle`** — the canonical Python deserialisation-trap module. Why it is unsafe by design, what `__reduce__` is, how the RCE one-liner is constructed, and what the fix landscape looks like.
- **`yaml`** — the YAML deserialiser, the `yaml.load` vs `yaml.safe_load` distinction, the **CVE-2017-18342** that drove the API split, and the residual hazards of even the safe loader.
- **The smaller traps** — `tarfile.extract`, `zipfile.extractall`, `shelve.open`, `dill`, `numpy.load`, `joblib.load`, `torch.load`, `tensorflow.keras.models.load_model`. Every one of these has shipped a "we deserialise pickle" or "we extract without path checks" CVE.
- **The replacement patterns** — JSON + `pydantic`, signed-and-typed binary (`msgpack` + HMAC, `cbor2` + strict schema, `protobuf` + registry), and the design principle behind all of them: *the deserialiser may not invoke arbitrary callables*.

---

## 1. Why deserialisation is the trap shape it is

A deserialiser, by definition, reads a byte stream and reconstructs an in-memory object graph. The danger is not the *reading* — that part is mechanical — it is the *reconstruction*. To reconstruct a `datetime.datetime(2025, 5, 13)`, the deserialiser needs to call `datetime.datetime(2025, 5, 13)`. To reconstruct an instance of an application class `User(name="alice")`, it needs to call `User(name="alice")`. The deserialiser is, in other words, a *programmable function caller*. The byte stream is *the program*.

In a typed format with a schema (Protobuf, Cap'n Proto, FlatBuffers), the program is constrained: only the constructors registered in the schema may be called, with only the field types the schema declared. In an untyped format that allows arbitrary callable references (`pickle`, untrusted `yaml`, untrusted Java serialisation), the program is *unconstrained*. The byte stream gets to choose the function, gets to choose the arguments, gets to choose the order.

The lecture's central claim, restated: **a deserialiser that allows the byte stream to choose which callable to invoke is, by construction, a programming language interpreter that the attacker provides the program for**. The mitigation is not to "sandbox" the interpreter (every Python sandbox has fallen; see PEP 432 history); the mitigation is not to use that shape of deserialiser on untrusted input.

This is *one* hazard class with *one* design fix. The work, once you see it, is to enumerate the places in your codebase where the byte stream is untrusted and the deserialiser is unconstrained, and to replace one of those two facts.

---

## 2. `pickle` — the canonical case

### 2.1 What CPython itself says

The CPython docs open `pickle`'s page with a `Warning` admonition (<https://docs.python.org/3/library/pickle.html>):

> **Warning:** The `pickle` module **is not secure**. Only unpickle data you trust.
> It is possible to construct malicious pickle data which will **execute arbitrary code during unpickling**. Never unpickle data that could have come from an untrusted source, or that could have been tampered with.

This is the upstream maintainer telling you, in their own documentation, that the module is not safe. The Python core developers have proposed and rejected multiple "safe pickle" PEPs (PEP 307 reviewed the design; the conclusion was that *the format itself* permits the hazard and no amount of restriction at the unpickler level is sufficient against motivated input). The warning has been in the docs since at least Python 2.3.

You will, even so, find production Python code that loads pickle from Redis, from S3, from a Kafka topic, from a web form. The job of an application-security engineer is to find it before someone else does.

### 2.2 The `__reduce__` protocol — the one-line RCE

`pickle` allows a class to control its own serialisation via the `__reduce__` magic method. When called during pickling, `__reduce__` returns a tuple `(callable, args_tuple)` that tells the unpickler: "to reconstruct me, call `callable(*args_tuple)`." The unpickler then *literally calls that callable*. The callable is referenced by name (its fully-qualified import path is in the pickle stream).

Which means: if I can write the pickle stream, I can put any callable I want into the `__reduce__` tuple — including `os.system`, `subprocess.run`, `eval`, `compile`, `builtins.exec`, anything importable. The unpickler will dutifully import it and call it with the arguments I chose.

The proof-of-concept is six lines:

```python
# Vulnerable consumer — pickle_bad.py
# AUTHORIZED USE ONLY — local lab.
import pickle
import sys

with open(sys.argv[1], "rb") as f:
    obj = pickle.load(f)   # <-- this line is the RCE.
print(obj)
```

And the attacker's payload-builder:

```python
# Attacker side — make_payload.py
# AUTHORIZED USE ONLY — pops a calc/touch on YOUR OWN machine.
import os
import pickle

class RCE:
    def __reduce__(self):
        # On unpickle, the unpickler will literally call os.system("touch /tmp/pwned").
        return (os.system, ("touch /tmp/pwned",))

with open("payload.pkl", "wb") as f:
    pickle.dump(RCE(), f)
```

Run the attacker side to produce `payload.pkl`, then run the consumer:

```bash
python make_payload.py
python pickle_bad.py payload.pkl
ls -l /tmp/pwned   # <-- file exists. The consumer just executed os.system.
```

Six lines of attack code, against six lines of victim code. The victim does nothing wrong from the standpoint of *Python*; the victim does everything wrong from the standpoint of *security*. The error is in the trust model: the consumer trusted the byte stream.

CVE references for this exact pattern shipping in mainstream libraries:

- **CVE-2019-6446** — `numpy.load` allowed pickle deserialisation by default before NumPy 1.16.3. The default flipped to `allow_pickle=False`; the parameter still exists, and you will find code that passes `allow_pickle=True` to load adversary-controlled `.npy` files.
- **CVE-2022-29216** — TensorFlow Keras `load_model` deserialises arbitrary Python via Lambda layers (the Keras `.h5` and `SavedModel` formats embed callable references). The ML supply chain is a pickle supply chain.
- **CVE-2024-3568** — `transformers` ChatGLM `trust_remote_code` allowed remote pickle execution. The "trust remote code" parameter name is at least honest.
- **PyTorch `torch.load`** — historically pickle-backed; the default has only recently moved toward `weights_only=True` (2024-era PyTorch), and *every* legacy `.pt` checkpoint loader is a pickle consumer.

The lesson is that "pickle" is not a single Python module's problem; it is a *format* used across the ML ecosystem (NumPy, PyTorch, TensorFlow, scikit-learn, joblib, transformers, Hugging Face's `safetensors` was created precisely to escape this trap). Every model you download is a pickle stream the publisher chose. If you do not trust the publisher, you do not run the model.

### 2.3 What does *not* work as a fix

Three "fixes" that fail and the reason each one fails.

**Failed fix 1: "I'll restrict `find_class`."** The `Unpickler` subclass can override `find_class(module, name)` to refuse to import dangerous callables. This is real and CPython documents it; the catch is that the set of "dangerous" callables is open. The unpickler can still invoke `__reduce__` chains that compose innocuous-looking calls into harmful ones. The CPython documentation itself warns: "the unpickler must … decide which classes/functions to allow … but even then there are still many classes that, on their own, are allowable, but which can be composed to perform an attack." Real-world Python applications have been written with `find_class` allow-lists; real-world attackers have escaped them.

**Failed fix 2: "I'll sign the pickle." **Signing the pickle is necessary if you are sending pickle across a trust boundary at all (and only acceptable if you cannot avoid pickle), but it is **not** a fix for "I am loading untrusted data." Signing protects integrity; it does not constrain the program embedded in the bytes. A signed pickle from a *compromised* signer is a pickle from an attacker. Signed pickle is appropriate for "I am sending a pickle between two services I operate, both behind the same trust boundary, and I want tamper-evidence in transit." It is **not** appropriate for "users upload pickle files."

**Failed fix 3: "I'll use `dill` / `cloudpickle` / `pickle5`." **These extend `pickle`'s capability; they do not constrain it. `dill` in particular pickles *more* of the Python runtime (including lambdas, generators, modules) and therefore presents a *larger* attack surface, not a smaller one.

### 2.4 What does work — replace the deserialiser

The fix is to replace `pickle` with a deserialiser that does not invoke arbitrary callables. The shape of the replacement depends on your data:

**Option A: JSON + Pydantic (or `dataclass` + a typed loader).** For most "I have a dict and a few lists" cases, JSON is the right format and Pydantic validates the schema at load time.

```python
# pickle_good_json.py
import json
import sys
from pydantic import BaseModel

class Cart(BaseModel):
    user_id: int
    items: list[str]
    total_cents: int

with open(sys.argv[1], "rb") as f:
    raw = json.load(f)
cart = Cart.model_validate(raw)  # raises if the shape is wrong; no callable invoked.
print(cart)
```

JSON cannot encode arbitrary callables — there is no `__reduce__` analogue in the JSON grammar. Pydantic enforces the schema. The only ways this code path causes trouble are (a) DoS via gigantic input, mitigated with a size cap, and (b) "JSON injection" upstream, which is a producer-side problem, not a consumer-side one.

**Option B: `msgpack` + HMAC** for binary efficiency + tamper-evidence between *services you both operate*.

```python
# pickle_good_msgpack.py
import hmac, hashlib, msgpack, os, sys

KEY = os.environ["MSGPACK_HMAC_KEY"].encode()

def load_signed(payload: bytes) -> dict:
    body, sig = payload[:-32], payload[-32:]
    expected = hmac.new(KEY, body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("bad signature")
    data = msgpack.unpackb(body, raw=False, strict_map_key=True)
    if not isinstance(data, dict):
        raise ValueError("bad shape")
    return data
```

`msgpack` is structurally similar to JSON — primitives, lists, maps — but more compact. The HMAC step is necessary because *we are explicitly trusting the byte stream's structure*; if the sender is compromised, all bets are off, but at least we know "the sender as configured signed this exact payload."

**Option C: Protobuf or Cap'n Proto** when you have a schema you want to enforce across services in multiple languages. The schema is the type system; the deserialiser only constructs types the schema declares.

**Option D: For ML model weights — `safetensors`.** Hugging Face's `safetensors` format (`pip install safetensors`) is precisely "pickle but only floats and shapes." For NumPy, prefer `np.save(allow_pickle=False)`; for PyTorch, prefer `torch.save(weights_only=True)` and `torch.load(weights_only=True)` (available 2024+).

---

## 3. `yaml.load` — pickle for the YAML world

YAML supports tags — `!python/object:foo.bar` is a YAML tag that PyYAML's default loader (the historical `yaml.load(stream)` with no `Loader` argument) interprets as "import `foo.bar` and call it." That is the same hazard class as pickle.

### 3.1 CVE-2017-18342 and the API split

Before this CVE, `yaml.load(stream)` defaulted to the unsafe `Loader`. The CVE write-up was substantial because PyYAML is a dependency of thousands of Python packages (Ansible's playbooks load YAML; Kubernetes manifests are YAML; every CI tool loads YAML). The remediation in PyYAML was a *deprecation warning* on the bare `yaml.load(stream)` call (PyYAML 5.1, 2019) and a recommendation to use `yaml.safe_load`.

The current correct API call is one of:

```python
import yaml

# Idiomatic and short:
data = yaml.safe_load(stream)

# Explicit (what safe_load shortcuts to):
data = yaml.load(stream, Loader=yaml.SafeLoader)
```

`SafeLoader` understands the YAML core schema (strings, ints, floats, bools, nulls, lists, maps) and refuses tags it does not know. There is no `!python/object` tag in its registry; there is no path from `SafeLoader` to a `__reduce__`-like surface.

### 3.2 The PoC

A vulnerable consumer:

```python
# yaml_bad.py
import yaml
import sys

with open(sys.argv[1]) as f:
    obj = yaml.load(f)        # <-- the default Loader before PyYAML 5.1 was unsafe.
print(obj)
```

A payload:

```yaml
# payload.yml
!!python/object/apply:os.system
- "touch /tmp/yaml-pwned"
```

```bash
python yaml_bad.py payload.yml
ls -l /tmp/yaml-pwned   # <-- file exists.
```

The fix is to call `yaml.safe_load(f)`. There is no semantic difference for *valid YAML configs*; there is total difference for *adversarial inputs*.

### 3.3 What `safe_load` still does not solve

`safe_load` is safe against the `__reduce__`-equivalent hazard. It is *not* safe against:

- **Billion-laughs (entity expansion)** — a YAML anchor + reference can expand exponentially. The same hazard exists in XML and is the same fix shape: cap depth, cap memory, cap time.
- **Anchor-bombs (deep nesting)** — recursive YAML structures that exhaust the parser stack.
- **Resource exhaustion via gigantic inputs** — size the input first.

For untrusted YAML, the defensive shape is:

```python
import io
import yaml

MAX_BYTES = 1_000_000      # 1 MB.

def load_untrusted(stream) -> dict:
    raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("yaml too large")
    return yaml.safe_load(io.BytesIO(raw))
```

For YAML with comment / merge-key fidelity (configuration files you intend to round-trip), `ruamel.yaml` (<https://yaml.readthedocs.io/>) is the maintained alternative; its `YAML(typ='safe')` mode is the safe variant.

---

## 4. The smaller traps

### 4.1 `tarfile.extract` and `tarfile.extractall` — CVE-2007-4559, fixed 2023

For *fifteen years* between 2007 and 2022, the canonical Python `tarfile` module's `extract` and `extractall` methods would, by default, follow symlinks and absolute paths in the archive — meaning a malicious `.tar.gz` could write to `/etc/passwd` on the unpacking host. The CVE is **CVE-2007-4559**. The bug was documented in 2007. The fix shipped in Python 3.12 (2023): the `filter` parameter to `extractall` defaults to `'data'` (which strips dangerous members) in 3.12, with a deprecation warning in 3.10 and 3.11.

If you run Python ≥ 3.12, the default is now safe. If you run Python 3.10 or 3.11, pass `filter='data'` explicitly. If you run Python ≤ 3.9 and load adversarial tarballs, you have a known-unfixed CVE.

```python
# Vulnerable on Python ≤ 3.11 default:
import tarfile
with tarfile.open(sys.argv[1]) as t:
    t.extractall("/tmp/unpacked")

# Patched (works on 3.10+, default on 3.12+):
with tarfile.open(sys.argv[1]) as t:
    t.extractall("/tmp/unpacked", filter="data")
```

The same bug shape exists in `zipfile` (zip-slip; **CVE-2018-1002200** and many follow-ups). The recommended pattern is to walk the members yourself and reject any whose normalised path escapes the destination directory.

### 4.2 `shelve.open` — pickle under a different name

`shelve` is "a dict-like persistent store backed by `pickle`." Opening a shelf is calling `pickle.load` on the values. If the shelf file came from anywhere you do not control, you have a pickle-load on untrusted input.

This rarely bites in practice because shelves usually live on local disk and never travel over the network, but: if you ever copy a shelf out of an S3 bucket, your trust boundary is the bucket, not the local filesystem.

### 4.3 `dill`, `cloudpickle`, `joblib`

`dill` extends pickle to serialise more (lambdas, modules, closures). `cloudpickle` does similar for the Spark / Ray ecosystem. `joblib` is the scikit-learn-default model serialiser; under the hood it is pickle (with an optional `numpy`-aware fast path).

For every one of these: if you `load` from untrusted input, you have the same RCE as `pickle`. `joblib.load` on a downloaded `.joblib` model is a pickle load. The Hugging Face ecosystem has moved from `joblib` toward `safetensors` for exactly this reason.

### 4.4 `numpy.load` (`.npy` files)

NumPy historically defaulted `allow_pickle=True`. **CVE-2019-6446** flipped the default to `False`. Code written before 2019, or code that explicitly passes `allow_pickle=True`, deserialises pickle.

```python
# Modern, default-safe:
import numpy as np
arr = np.load("data.npy")           # allow_pickle=False by default since NumPy 1.16.3.

# Legacy / dangerous on untrusted input:
arr = np.load("data.npy", allow_pickle=True)
```

### 4.5 `torch.load`, `tensorflow.keras.models.load_model`

PyTorch's `torch.load` reads pickle. The 2024-era PyTorch introduced `weights_only=True` to constrain the load to a small allowlist of safe pickle ops (tensors, numbers, lists). `weights_only=True` is the default in PyTorch 2.6+ (2025-era). If you load a `.pt` file in older PyTorch, you load pickle.

TensorFlow Keras `load_model` reads HDF5 or `SavedModel`; both can embed Lambda layers, which serialise as pickled Python. **CVE-2022-29216**, **CVE-2024-7340**. The `safetensors`-style equivalent for TF is in progress.

---

## 5. The decision tree

When you find a deserialiser in a code review, walk this tree:

1. **Is the input attacker-controllable?** If "no" (it is a local file *we* write under a directory only this process writes, never from the network, never from user input), the deserialiser choice is a hygiene matter, not a security one. Document the trust boundary in a comment.
2. **If yes, can we change the format?** JSON + a typed loader (pydantic, dataclass, attrs) is *always* the first move when the data is "primitives + lists + dicts." This covers ~80% of legitimate uses of pickle.
3. **If we need binary efficiency or floats-and-tensors,** is `safetensors` (ML weights), `protobuf` / `cap'n proto` (typed cross-language messages), or `msgpack` + HMAC + schema (typed binary in-house) usable? One of these is the answer for the remaining 20%.
4. **If we are stuck with pickle** (interop with a third-party library that emits it, legacy ML checkpoints, etc.) — *constrain the input source* to a path that is signed-and-trusted (e.g., the model registry that produced it), document the trust boundary, and consider a sandboxed loader process you can kill if it misbehaves.

The right answer is almost never "we need pickle but with safety bolted on." The right answer is almost always "we do not need pickle in this code path."

---

## 6. Defender side — what catches deserialisation hazards

### 6.1 Static analysis

- **`bandit`** has rule `B301` (`pickle` use) and `B506` (`yaml.load` use). Both fire on import or on the specific call. Default severity is medium for `B301` and medium-to-high for `B506`. Tune up.
- **`semgrep`** ships a Python ruleset `p/python` that includes `python.lang.security.deserialization.avoid-pickle.avoid-pickle` and `python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load`. The `p/owasp-top-ten` ruleset catches the same shapes against A08.
- **CodeQL** ships `py/unsafe-deserialization` (`CWE-502`); GitHub's default Code Scanning configuration fires on `pickle.load(x)` where `x` is taint-flow-reachable from user input.

### 6.2 Runtime observability

- Log every successful and failed deserialisation that crosses a trust boundary. The log line should include the source (which client), the size, and the outcome.
- Wrap `pickle.load` (or the safer replacement) in a function whose name is in the codebase index. Grepping `pickle.load(` should return zero matches in your code in 2025; every legitimate use should go through your wrapper.

### 6.3 Process hardening

- Run the deserialiser in a constrained subprocess if the input is even slightly suspect. `seccomp`, `nsjail`, `firejail`, or a minimal Docker container with no network are appropriate.

---

## 7. The exercise tie-in

Exercise 1 (`exercise-01-pickle-rce.md`) walks the proof-of-concept end to end: build the vulnerable server, write the attack, observe the RCE on your own machine, replace `pickle` with JSON + pydantic, observe that the same attack now produces a validation error. The lecture is read; the exercise is the muscle memory.

---

## 8. Summary

- `pickle.load` (and every other unconstrained-callable deserialiser) is a programming-language interpreter that takes its program from the byte stream. The CPython documentation says this in its first warning admonition; the security guidance has been stable for two decades.
- The `__reduce__` protocol is the explicit hook; the RCE is a six-line payload; **CVE-2019-6446**, **CVE-2022-29216**, **CVE-2024-3568** are the receipts of the exact pattern shipping in mainstream libraries.
- `yaml.load` without `Loader=SafeLoader` has the same hazard class; **CVE-2017-18342** drove the API split. `yaml.safe_load` is the correct default; for untrusted YAML you also need a size cap and a depth cap.
- The smaller traps — `tarfile.extract`, `shelve`, `dill`, `cloudpickle`, `joblib`, `numpy.load(allow_pickle=True)`, `torch.load(weights_only=False)`, `keras.load_model` — are all variations on the same theme. Audit each one in your dependencies; assume each one is unsafe by default until proven otherwise.
- The fix is to *replace* the deserialiser with one that does not invoke arbitrary callables. JSON + pydantic is the right default; `msgpack` + HMAC or `protobuf` + schema for typed binary; `safetensors` for ML weights.
- Defender side: `bandit` `B301` / `B506`, `semgrep` `p/python` ruleset, CodeQL `py/unsafe-deserialization`, wrapping every legitimate use behind a single grep-able helper.

The next lecture covers SSRF in Python's HTTP clients, ReDoS in the `re` engine, and the rest of the standard-library footgun catalogue.

---

*End of Lecture 1.*
