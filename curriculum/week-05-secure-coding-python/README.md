# Week 5 — Secure Coding in Python

> *Week 4 was the OWASP Top 10 — the canonical web vulnerability classes that apply to any web stack. Week 5 zooms in on the **Python-specific** hazards: the language features, standard-library defaults, and idioms that turn a clean-looking Python program into a remote code execution one bad import away. The Top 10 told you what to look for. This week tells you what Python in particular keeps shipping.*

Welcome to Week 5 of **C6 · Cybersecurity Crunch**. Weeks 1, 2, 3 gave you the security mindset, the network, and the threat model. Week 4 walked all ten OWASP categories on Python web apps and asked you to patch each one. Week 5 holds the magnifying glass over Python itself. By Sunday you will have stared at the `pickle` module long enough to understand why no one credible loads it from the network, you will have triggered a regular-expression denial-of-service on a regex you almost certainly have in your own repos, you will have a `bandit` / `semgrep` / `pip-audit` baseline configured in CI, and you will have audited a real Python codebase you wrote — yours, from C1 or C16 — and documented every finding the toolchain produced.

This week is hands-on. You will read Python that is dangerous on purpose, you will run it, you will exploit it on your own laptop, and you will produce the patched-and-documented version. The defensive payoff is a CI pipeline you can drop into any Python project on Monday morning and a habit of reading the standard library with the same suspicion you read user input.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Practice the techniques in this module only on:                    │
│  - the deliberately vulnerable Python scripts provided with this    │
│    week (`*_bad.py` and the lab targets in the exercises)           │
│  - machines and networks you own                                    │
│  - your own C1 / C16 mini-project codebases (the Week 5 mini-       │
│    project is an audit of your own past code)                       │
│  - legal training platforms (OWASP Juice Shop, PortSwigger Web      │
│    Security Academy, picoCTF, HackTheBox starter tier, TryHackMe)   │
│  - public open-source code you have a local clone of, read-only,    │
│    where you do *not* exercise findings against the project's       │
│    deployed service                                                 │
│                                                                     │
│  Unauthorized testing is a crime. C6 does not teach crime.          │
└─────────────────────────────────────────────────────────────────────┘
```

The banner is mandatory on every page this week. Every lecture demonstrates an attack class against Python in particular; every exercise asks you to run the demonstration locally; the mini-project asks you to audit *your own code* against a real toolchain. The line Week 4 drew — read the source, reason about attacks, do not run them against systems you do not own — stays drawn this week. The fact that the target is *your own* C1 code in the mini-project is not an excuse to broaden it; it is a reminder that the first audit a security engineer does is on their own commits.

---

## Learning objectives

By the end of this week, you will be able to:

- **Explain** why `pickle.load` (and `pickle.loads`, and `dill.load`, and `shelve.open`, and any other Python serialiser that allows callable references) is unsafe on untrusted input, citing **CVE-2022-34265**, **CVE-2019-20907**, the Python documentation's own warning (`pickle` module, "Warning" admonition), and the OWASP *Deserialization Cheat Sheet*.
- **Demonstrate** a working `pickle` RCE against a server you wrote, then **patch** it to a signed-or-typed format (`json` + `pydantic`, or signed pickle with `hmac`, or `cbor2` with a strict schema, or `protobuf` / `msgpack` with a schema registry).
- **Distinguish** `yaml.load` from `yaml.safe_load`, cite **CVE-2017-18342** (the PyYAML default-loader CVE that drove the API change), and explain why even `yaml.safe_load` is **still not safe** against untrusted input above the parsing-resource-exhaustion line (billion-laughs, deeply nested anchors).
- **Identify** a regular-expression denial of service (ReDoS) by reading the regex, classify it as catastrophic / quadratic / linear, and patch it using one of the three documented strategies: rewrite as linear, switch engine to `re2` (`google-re2` or `pyre2`), or impose an input-size / wall-clock budget. Cite **CVE-2020-7720** (NLTK), **CVE-2022-23491** (`certifi` adjacent), and **CVE-2023-37920** (`certifi` again).
- **Identify** an SSRF in Python HTTP client code (`requests.get(user_url)`, `urllib.request.urlopen(user_url)`, `httpx.get(user_url)`), classify it against the SSRF allow-list / deny-list / DNS-rebinding spectrum, and patch it using an allow-list with literal-IP resolution.
- **Recognise** the standard-library footguns: `tempfile.mktemp` (TOCTOU), `subprocess.run(shell=True)`, `os.system`, `eval`, `exec`, `xml.etree.ElementTree.parse` (XXE / billion-laughs), `random` for security (should be `secrets`), `time.time()`-derived "randomness," `pickle` (every form). Cite the CPython documentation's "Warning" admonitions where they exist.
- **Configure** `bandit` for a Python project from scratch — `bandit -r .`, a `.bandit` or `pyproject.toml` configuration, a baseline, severity thresholds, and a CI step that fails the build on new High findings.
- **Configure** `semgrep` for a Python project from scratch — `p/python`, `p/owasp-top-ten`, `p/security-audit`, custom rules, ignore patterns, and a CI step.
- **Configure** `pip-audit` for the supply chain — `pip-audit -r requirements.txt`, `pip-audit --strict`, lockfile flow, OSV database awareness, the `--ignore-vuln` policy and when it is appropriate.
- **Triage** scanner findings into four buckets — *true positive, fix now*; *true positive, accept risk (documented)*; *false positive (suppressed with a comment)*; *won't fix (out of scope)*. The triage is the work; the scanner is the cheap part.
- **Produce** a written security audit of a real Python codebase you wrote, with every finding from `bandit`, `semgrep`, and `pip-audit` triaged, the false positives suppressed with comments explaining *why*, and a patch for every true positive that you intend to fix.

---

## Prerequisites

- **Weeks 1, 2, 3, and 4 completed.** You should be comfortable in a Linux terminal, able to read a PCAP, able to produce a small threat model, and able to walk the OWASP Top 10 against a Python web app.
- **Python 3.11+** installed locally, with `pip`, `venv`, and `git` on the path.
- **A Python project you own.** The mini-project audits one of your *own* repositories — the C1 mini-project, a C16 portfolio piece, anything you wrote yourself. If you do not have one, clone any small public Python project (≤ 5 kLoC) with a permissive licence and audit that instead; the *method* is what matters, not the target.
- **`bandit`, `semgrep`, and `pip-audit` installed.** Either system-wide (`pipx install bandit semgrep pip-audit`) or in the project venv. Verified with `--version` on each.
- **An IDE or editor with Python syntax awareness.** VS Code, PyCharm, Neovim with `pylsp` — anything. You will be reading code line by line.

---

## Topics covered

- **The deserialisation trap** — `pickle.load`, `pickle.loads`, `dill.load`, `shelve.open`, the `__reduce__` protocol, why "just sign it" is necessary-but-not-sufficient, why every well-known Python library that accepts pickle from the network has a security advisory in its history. The `__reduce__` payload as a one-liner RCE. The fix landscape: JSON + pydantic, signed pickle with `hmac`, `msgpack` with a schema, `cbor2` with strict typing, protobuf with a registry.
- **YAML loaded unsafely** — `yaml.load` (the historical default), `yaml.load(stream, Loader=yaml.SafeLoader)` (the recommended explicit), `yaml.safe_load` (the convenience), and the residual risks even `safe_load` does not address (billion-laughs, anchor depth, parsing memory). The PyYAML CVE timeline (**CVE-2017-18342** and the API split that followed) and the `ruamel.yaml` alternative.
- **Server-side request forgery in Python clients** — the standard-library and third-party HTTP clients (`urllib.request`, `requests`, `httpx`, `aiohttp`, `urllib3`) and what each does with redirects, proxies, schemes, IP-literal hosts, and DNS rebinding by default. The cloud-metadata exfiltration class (AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure variants). The allow-list pattern, the literal-IP resolution pattern, the egress-network policy pattern.
- **Regular-expression denial of service (ReDoS)** — the algorithmic class. The backtracking model in Python's `re` engine. The three regex shapes that go catastrophic: nested quantifiers (`(a+)+`), alternation with overlap (`(a|aa)+`), and lookaround on user input. The detection: ReDoS-checker tooling, manual inspection, the "doubling test." The fixes: rewrite as a linear automaton, switch to `re2`, impose a size / time budget.
- **Insecure randomness** — `random.random()`, `random.randint`, `random.choice` *all use the Mersenne Twister*, which is predictable from a few hundred outputs and is **not** for tokens, session IDs, password reset links, or anything an attacker can ever see. The `secrets` module is the answer for everything security-sensitive; `os.urandom` is the lower-level primitive.
- **Standard-library footguns** — `tempfile.mktemp` vs `tempfile.NamedTemporaryFile`, `subprocess.run(args, shell=False)` vs `shell=True`, `os.system`, `eval`, `exec`, `compile`, the `xml.etree` family vs `defusedxml`, `pickle` (already covered), `time.time()` for tokens.
- **`bandit` in depth** — the rules catalogue (B1xx loader rules, B3xx crypto, B6xx subprocess, B7xx misc), the configuration file, baselines, severity tuning, common false-positive shapes and how to suppress them with `# nosec` comments that *explain* the suppression.
- **`semgrep` in depth** — the registry rulesets you actually want enabled (`p/python`, `p/owasp-top-ten`, `p/security-audit`, plus framework-specific `p/flask`, `p/django`, `p/fastapi`), how to write a custom rule (YAML, `pattern`, `pattern-not`, `metavariables`), the CI integration, the `.semgrepignore` file.
- **`pip-audit` and the supply chain** — the OSV database backing it, the lockfile workflow (`pip-tools` + `requirements.in` → `requirements.txt`), the `--strict` flag, the `--ignore-vuln` policy, the relationship to `safety` and `dependabot`.
- **CI integration** — a GitHub Actions workflow that runs all three tools on every push, fails on new High findings, comments on PRs, and produces a SARIF upload for GitHub's Code Scanning. The same pattern in GitLab CI and CircleCI.
- **Triage discipline** — the four-bucket model, the suppression-with-justification rule, the "every `# nosec` cites a CWE or a written reason" habit. The cost of an untriaged backlog (alert fatigue) and the cost of an over-aggressive suppression (silent regression).

---

## Weekly schedule

The schedule below adds up to approximately **36 hours**. Treat it as a target.

| Day       | Focus                                                  | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|--------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | L1 — pickle, yaml, deserialisation                     |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Tuesday   | L2 — SSRF, ReDoS, stdlib footguns                      |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Wednesday | L3 — bandit, semgrep, pip-audit in CI                  |    2h    |    1h     |     0h     |    0.5h   |   1h     |     0.5h     |    0.5h    |    5.5h     |
| Thursday  | Exercises polished; challenge launch                   |    0h    |    2h     |     1.5h   |    0.5h   |   1h     |     1h       |    0.5h    |    6.5h     |
| Friday    | Mini-project: pick the target, run the tools           |    0h    |    1h     |     0.5h   |    0.5h   |   1h     |     2.5h     |    0.5h    |     6h      |
| Saturday  | Mini-project: triage, fix, write up                    |    0h    |    0h     |     0h     |    0h     |   1h     |     3h       |    0h      |     4h      |
| Sunday    | Quiz, review, polish, push                             |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    0.5h    |     1h      |
| **Total** |                                                        | **6h**   | **7h**    | **2h**     | **3h**    | **6h**   |   **7h**     |   **3h**   |  **36h**    |

---

## How to navigate this week

| File | What's inside |
|------|---------------|
| [README.md](./README.md) | This overview (you are here) |
| [resources.md](./resources.md) | `bandit` docs, `semgrep` registry, `pip-audit`, OWASP Python cheat sheets, CPython warning admonitions, CVE references |
| [lecture-notes/01-the-deserialization-trap-pickle-yaml.md](./lecture-notes/01-the-deserialization-trap-pickle-yaml.md) | The `pickle` RCE class, the `yaml.load` history, the fix landscape |
| [lecture-notes/02-ssrf-redos-and-the-stdlib-footguns.md](./lecture-notes/02-ssrf-redos-and-the-stdlib-footguns.md) | SSRF in Python HTTP clients, ReDoS in `re`, the standard-library footgun catalogue |
| [lecture-notes/03-bandit-semgrep-pip-audit-in-CI.md](./lecture-notes/03-bandit-semgrep-pip-audit-in-CI.md) | The three tools, their rule catalogues, their CI integration, the triage discipline |
| [exercises/README.md](./exercises/README.md) | Index of three Python exercises |
| [exercises/exercise-01-pickle-rce.md](./exercises/exercise-01-pickle-rce.md) | Build a server, send it a pickle, pop a shell on yourself, patch it |
| [exercises/exercise-02-redos-attack.md](./exercises/exercise-02-redos-attack.md) | Write a catastrophic regex, demonstrate the doubling, patch it three ways |
| [exercises/exercise-03-run-bandit-semgrep.md](./exercises/exercise-03-run-bandit-semgrep.md) | First-run `bandit` and `semgrep` against a tiny vulnerable script, read every finding, write the triage |
| [challenges/README.md](./challenges/README.md) | Index of weekly challenges |
| [challenges/challenge-01-audit-your-c1-mini-project.md](./challenges/challenge-01-audit-your-c1-mini-project.md) | Audit your own C1 mini-project for Python-specific vulnerabilities and document every finding |
| [quiz.md](./quiz.md) | 10 multiple-choice questions |
| [homework.md](./homework.md) | Six practice problems, six hours total |
| [mini-project/README.md](./mini-project/README.md) | Audit a real Python codebase with `bandit` + `semgrep` + `pip-audit`, document every finding — the Week 5 portfolio artifact |

---

## Stretch goals

If you finish early, push further:

- Read the **CPython `pickle` source** (`Lib/pickle.py`). The `Unpickler.find_class` method is the place every "safe pickle" proposal lands and almost every one of those proposals is, eventually, insufficient. Understanding why is a useful object-lesson in why "sandboxed" deserialisers do not survive contact with motivated attackers.
- Read the **`google-re2` Python binding** and benchmark a known-catastrophic regex against it and against stock `re`. The performance and DoS-resistance difference on adversarial input is sometimes 1000x or more.
- Read **Trail of Bits's "It Pays to be Circumspect" blog series** and their `pip-audit` design document. Trail of Bits maintains `pip-audit` for the PSF; their writing on supply-chain security is the cleanest practitioner material in the field. <https://blog.trailofbits.com/>
- Write your **own `semgrep` rule** for a Python anti-pattern not in any registry — a project-specific naming convention, a deprecated internal API, a regulatory requirement. Commit it to your portfolio repo with a `README` explaining the rule.
- Re-audit a Python codebase you audited *last year* (or your C1 mini-project after you patched it in Week 4) with `bandit` and `semgrep` updated to the latest version. The diff in findings between two scanner versions on the same code is its own lesson in tool drift.
- Read **PEP 458** (TUF for PyPI) and **PEP 740** (signing Python distributions with Sigstore). Both are the supply-chain integrity story the next five years of Python security will revolve around.
- Audit a **`setup.py`** for unsafe install-time behaviour — `subprocess.run` calls, `os.system`, network fetches at install time. The `setup.py` execution model is a supply-chain attack surface in its own right.

---

## Up next

Continue to [Week 6 — Code Review for Security](../week-06/) once your mini-project audit is pushed and your portfolio README links to all five weeks. Week 6 takes you from auditing your own code (Week 5) to reviewing someone else's PR with a security lens — the daily work of an application-security engineer at a team scale.

---

*Found an error? Open an issue or send a PR. The next learner will thank you.*
