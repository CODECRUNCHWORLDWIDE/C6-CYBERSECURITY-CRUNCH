# Exercise 2 — ReDoS: Catastrophic Backtracking and Three Fixes

**Estimated time:** 60 minutes. Python 3.11, `google-re2` (optional). Local only.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The ReDoS demonstrations in this exercise run on your own machine  │
│  and exhaust your own CPU. Do not run any regex you wrote against   │
│  a service you do not operate. ReDoS against a remote service is a  │
│  denial-of-service attack and is a crime.                           │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You are reviewing a small Python utility — an email-validator function someone wrote in 2018 — and you have a suspicion the regex is catastrophic. Your job is to demonstrate the catastrophic backtracking, classify the regex shape, and produce three different patches: rewrite to linear, switch engine to `re2`, and impose an input-size budget.

This exercise covers:

- **ReDoS (Regular Expression Denial of Service)** — CWE-1333.
- The doubling test as the diagnostic.
- Three documented fixes: rewrite / `re2` / size cap.
- The `semgrep` rule (`python.lang.security.audit.dangerous-regex`) that catches some catastrophic shapes.
- The CVE catalogue: **CVE-2020-7720** (NLTK), **CVE-2022-40898** (`wheel`), **CVE-2023-37920** (`certifi`).

---

## Step 1 — Build the catastrophic regex demo (10 min)

Create `redos_demo.py`:

```python
# redos_demo.py — local CPU experiment.
# AUTHORIZED USE ONLY — runs against your own Python process.
import re
import sys
import time

# A textbook catastrophic regex. Nested quantifiers: (a+)+ over the same charclass.
# Equivalent linear form: r"a+$" — see redos_good_rewrite.py.
CATASTROPHIC = re.compile(r"^(a+)+$")

# A real-world-shaped one. The "validate this list of comma-separated alphanumerics"
# pattern is a classic example.
LISTY = re.compile(r"^([a-zA-Z0-9]+,)*([a-zA-Z0-9]+)?$")

def doubling_test(pat: re.Pattern, base: str, suffix: str = "!", repeats=range(10, 32, 2)):
    """Run the regex on increasing-length adversarial inputs. Report time per length."""
    print(f"Pattern: {pat.pattern}")
    for n in repeats:
        s = base * n + suffix
        t0 = time.time()
        try:
            pat.match(s)
        except Exception as e:
            print(f"  n={n:3d}  ERROR {e}")
            return
        dt = time.time() - t0
        print(f"  n={n:3d}  {dt:7.3f}s  (input len={len(s)})")
        if dt > 5.0:
            print("  >>> aborting, already past 5 seconds")
            return

if __name__ == "__main__":
    print("=== Catastrophic: (a+)+$ on 'aaaa...!' ===")
    doubling_test(CATASTROPHIC, "a", "!")
    print()
    print("=== Listy: ([a-z0-9]+,)*([a-z0-9]+)?$ on 'a,a,a,...,a,a!' ===")
    doubling_test(LISTY, "a,", "!", repeats=range(10, 32, 2))
```

Run it:

```bash
python redos_demo.py
```

You should see something like:

```
Pattern: ^(a+)+$
  n= 10    0.000s  (input len=11)
  n= 14    0.000s  (input len=15)
  n= 18    0.001s  (input len=19)
  n= 22    0.018s  (input len=23)
  n= 26    0.282s  (input len=27)
  n= 28    1.123s  (input len=29)
  n= 30    4.473s  (input len=31)
  >>> aborting, already past 5 seconds
```

Each two-step bump roughly *quadruples* the time. The growth is exponential — `O(2^n)` in the input length. That is catastrophic backtracking.

**Classification.** Three shapes account for almost all catastrophic regexes in the wild:

- **Nested quantifiers over overlapping charclasses** — `(a+)+`, `(\d+)+`, `(\w+)+`. The outer `+` and inner `+` both match the same characters; the engine tries every split.
- **Alternation with overlap** — `(a|aa)+`, `(\w|\w*)+`. Both alternatives match the same prefix.
- **Lookaround + repetition over the same charclass** — `(?=.*X)(?=.*Y).*`. Each lookaround re-scans.

`CATASTROPHIC` is shape 1. `LISTY` is shape 1 + 2 (the outer `*` on `([a-z0-9]+,)*` plus the optional trailing group makes the engine try every split of where the commas go).

---

## Step 2 — Fix 1: rewrite as linear (10 min)

Create `redos_good_rewrite.py`:

```python
# redos_good_rewrite.py
# Rewriting the catastrophic regex to a linear equivalent.
import re
import time

# (a+)+$ matches "one or more, of (one or more a's), at end of line."
# That is the same set of strings as a+$. The nested + is redundant.
LINEAR_A = re.compile(r"^a+$")

# ([a-z0-9]+,)*([a-z0-9]+)?$ — accepts a comma-separated list of alphanumeric items
# with no trailing comma. Equivalent linear form: split on comma, validate each token.
# Or as a single regex: anchor each token with [a-z0-9]+, separator is literal comma,
# and the structure is unambiguous (no nested quantifiers over overlapping charclasses).
LINEAR_LIST = re.compile(r"^[a-z0-9]+(?:,[a-z0-9]+)*$")

def time_match(pat: re.Pattern, s: str) -> float:
    t0 = time.time()
    pat.match(s)
    return time.time() - t0

if __name__ == "__main__":
    print("=== Linear a+$ on 'a' * 30 + '!' ===")
    print(f"  time: {time_match(LINEAR_A, 'a' * 30 + '!'):.6f}s")
    print(f"  time: {time_match(LINEAR_A, 'a' * 1000 + '!'):.6f}s")
    print(f"  time: {time_match(LINEAR_A, 'a' * 100000 + '!'):.6f}s")
    print()
    print("=== Linear list on 'a,' * 30 + '!' ===")
    print(f"  time: {time_match(LINEAR_LIST, ('a,' * 30) + '!'):.6f}s")
    print(f"  time: {time_match(LINEAR_LIST, ('a,' * 10000) + '!'):.6f}s")
```

Run it:

```bash
python redos_good_rewrite.py
```

You should see all times in the microseconds range, even on 100k-character input. The linear regex is `O(n)` regardless of whether the input matches or not.

**The rule:** any regex with a `*` or `+` outside a group whose contents *also* contain a `*` or `+` over an overlapping charclass is suspicious. The fix is to remove the redundant outer quantifier or make the inner one non-overlapping.

---

## Step 3 — Fix 2: switch engine to `re2` (15 min)

Google's `re2` engine uses a Thompson NFA construction and runs in linear time — no backtracking, no catastrophic worst case. It is the right answer when the regex is intrinsically complex (real-world regexes are not always trivially rewritable) and the input is adversarial.

Install:

```bash
pip install google-re2
# If google-re2 fails to build on macOS, try: pip install pyre2
```

Create `redos_good_re2.py`:

```python
# redos_good_re2.py
# Use Google's re2 engine — linear time, no catastrophic backtracking by construction.
import time

try:
    import re2 as re                 # google-re2 binding.
except ImportError:
    import re2_compat as re          # placeholder; fall through to fail-loud.

CATASTROPHIC_PATTERN = r"^(a+)+$"     # The SAME catastrophic pattern, run on re2.
PAT = re.compile(CATASTROPHIC_PATTERN)

if __name__ == "__main__":
    for n in (10, 20, 30, 50, 100, 1000, 10000):
        s = "a" * n + "!"
        t0 = time.time()
        PAT.match(s)
        print(f"  n={n:6d}  {(time.time() - t0):.6f}s")
```

Run it:

```bash
python redos_good_re2.py
```

Even `n=10000` (which would be intractable on stock `re`) completes in milliseconds. The same pattern is now safe.

**Trade-off.** `re2` does not support backreferences (`\1`) and does not support lookaround (`(?=...)`, `(?!...)`). If your regex uses either of these features, you cannot drop in `re2`; you must rewrite. For most validation use cases, neither feature is required.

**When to choose `re2` over rewriting:**

- The regex is in a third-party library you cannot easily modify.
- The regex is intrinsically complex and a "rewrite to linear" introduces a bug.
- You want belt-and-braces — even if the regex *looks* safe, you do not want a future maintainer to introduce catastrophic backtracking.

---

## Step 4 — Fix 3: impose a size budget (10 min)

The third option is to *accept* that the regex is potentially catastrophic but cap the input size so the worst case is bounded.

Create `redos_good_capped.py`:

```python
# redos_good_capped.py
# Cap input length so the catastrophic worst case is bounded.
# Use this when the regex cannot be rewritten and re2 is not an option.
import re

CATASTROPHIC = re.compile(r"^(a+)+$")
MAX_LEN = 256        # Pick a length where worst-case time is tolerable.
                     # For (a+)+$, ~256 is past the practical doubling cutoff but
                     # still completes in under a second on a modern CPU.

def safe_match(user_input: str) -> bool:
    if not isinstance(user_input, str):
        raise TypeError("expected str")
    if len(user_input) > MAX_LEN:
        # Reject before the regex engine sees the input.
        return False
    return CATASTROPHIC.match(user_input) is not None

if __name__ == "__main__":
    print(safe_match("a" * 30 + "!"))          # False — does not match anyway.
    print(safe_match("a" * 300))                # False — rejected on size.
    print(safe_match("a" * 200))                # True — actual regex run, but bounded.
```

**When to choose the size cap:**

- The regex is in a hot path you cannot rewrite quickly.
- The input source has an obvious natural maximum (an email address is rarely longer than 254 characters; RFC 5321).
- You combine the size cap with a rate limit and a timeout at the request level.

**Trade-off.** The size cap is the weakest of the three fixes. It transforms "unbounded DoS" into "bounded DoS" — the worst case is still slower than the average case. Use it when nothing else is available; never use it as the *only* defence.

---

## Step 5 — Confirm the scanners catch the catastrophic pattern (5 min)

Run `bandit` and `semgrep` against `redos_demo.py`:

```bash
bandit redos_demo.py
# Bandit does NOT have a built-in ReDoS rule — it is pattern-class-based.
# This is a documented bandit limitation.

semgrep --config p/python --config p/security-audit redos_demo.py
# Semgrep ships dangerous-regex rules; expect a hit on (a+)+ at minimum on recent registries.
```

Note that `bandit` does *not* catch ReDoS — this is one of the gaps that motivates running multiple scanners. `semgrep`'s `python.lang.security.audit.dangerous-regex` and `python.lang.security.audit.regex` rules catch a subset of catastrophic shapes; CodeQL's `py/redos` and `py/polynomial-redos` queries catch a larger subset using more sophisticated analysis.

**The lesson:** scanners cover *some* of the ReDoS surface. The doubling test (Step 1) is what you should run on *every regex over user input*. Build that test into your project's test suite if you process user-controlled patterns.

---

## Step 6 — Write the writeup (10 min)

Create `writeup.md` (200-400 words). Cover:

1. **Hazard class and CWE.** Regular-expression denial of service; CWE-1333; OWASP A06:2021 (Vulnerable and Outdated Components) when the bad regex is in a dependency.
2. **The bug, one sentence anchored to the line.** Quote `redos_demo.py:9` (the `(a+)+$` pattern) and state the shape (nested quantifier over overlapping charclass).
3. **The fix, three sentences each anchored to one of the three patches.** Rewrite (`redos_good_rewrite.py`), `re2` (`redos_good_re2.py`), size cap (`redos_good_capped.py`).
4. **Defender-side detection.** Cite `semgrep python.lang.security.audit.dangerous-regex`, CodeQL `py/redos` and `py/polynomial-redos`, and note that `bandit` does not have a ReDoS rule.
5. **Residual risk.** Even with a linear regex, application-layer regex use over unbounded input is still a CPU cost; combine the fix with a request-level timeout and rate limit.

CVEs to cite as receipts: **CVE-2020-7720**, **CVE-2022-40898**, **CVE-2023-37920**.

---

## Acceptance

- `redos_demo.py`, `redos_good_rewrite.py`, `redos_good_re2.py`, `redos_good_capped.py`, `writeup.md` all present.
- `redos_demo.py` shows visibly-doubling time per length on the catastrophic pattern.
- `redos_good_rewrite.py` shows microsecond-scale time on inputs up to 100k characters.
- `redos_good_re2.py` shows microsecond-scale time on the *same* catastrophic pattern using the `re2` engine.
- `redos_good_capped.py` rejects oversized inputs before the regex engine runs.
- The writeup is 200-400 words and cites at least one CVE and the CWE ID.

---

## Stretch

If you finish early:

- Pick a regex from your own code (any C1 or C16 project). Run the doubling test on it. Document the result.
- Read **Russ Cox's "Regular Expression Matching Can Be Simple And Fast"** (<https://swtch.com/~rsc/regexp/regexp1.html>). It is free, online, and is the canonical explanation of *why* backtracking engines have catastrophic worst cases and *why* `re2` does not.
- Write a `semgrep` custom rule that flags `re.compile(...)` calls where the pattern literally contains `(...+)+` or `(...*)*`. Test against your own corpus.
- Read **CVE-2022-40898** in full — `wheel`'s tag-parsing regex shipped a ReDoS that affected `pip install` itself. Track the fix commit, read the diff, and explain in one paragraph why the original pattern was catastrophic and how the patch fixes it.
