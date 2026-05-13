# Week 5 — Resources

Every resource here is **free** and, where possible, a primary source. Week 5 is the toolchain week; the tools have their own documentation, and that documentation is the first reading on every tool. Read it before you read anything else.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The proof-of-concept code linked from these resources is for       │
│  reading and for reproduction on machines you own. Do not run an    │
│  exploit against any service you do not operate.                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Primary — the three scanners

- **`bandit`** — Python AST-level lint for security smells. Maintained by the Python Code Quality Authority (PyCQA).
  - Docs: <https://bandit.readthedocs.io/>
  - Rule index (B1xx loader, B2xx misc, B3xx crypto, B4xx imports, B5xx crypto-elsewhere, B6xx subprocess, B7xx misc Flask/Django, B9xx test/AST): <https://bandit.readthedocs.io/en/latest/plugins/index.html>
  - Configuration reference (`.bandit`, `pyproject.toml`, baselines): <https://bandit.readthedocs.io/en/latest/config.html>
  - Source: <https://github.com/PyCQA/bandit>
- **`semgrep`** — pattern-matching static analysis with a large free rule registry. Maintained by Semgrep Inc.; the core engine and registry are open-source.
  - Docs: <https://semgrep.dev/docs/>
  - Registry (browse rulesets by language and topic): <https://semgrep.dev/explore>
  - The rulesets you want enabled for Python: `p/python`, `p/owasp-top-ten`, `p/security-audit`, `p/secrets`, plus framework-specific `p/flask`, `p/django`, `p/fastapi`.
  - Writing custom rules: <https://semgrep.dev/docs/writing-rules/overview>
  - Source: <https://github.com/semgrep/semgrep>
- **`pip-audit`** — Python supply-chain vulnerability scanner from the Python Packaging Authority (PyPA), backed by the OSV database. Maintained by Trail of Bits.
  - Source / README: <https://github.com/pypa/pip-audit>
  - The OSV database it queries: <https://osv.dev/>
  - Trail of Bits design notes: <https://blog.trailofbits.com/2022/03/02/announcing-pip-audit-the-pypa-vulnerability-auditor/>

---

## Python documentation — the warnings you must read

Every CPython page below has a "Warning" admonition that is the single source of truth for the hazard in that module. Read each one. They are short.

- **`pickle` — Python object serialization**: <https://docs.python.org/3/library/pickle.html>
  > "The pickle module is **not secure**. Only unpickle data you trust."
  This is the headline of the entire week.
- **`subprocess` — Subprocess management**: <https://docs.python.org/3/library/subprocess.html#security-considerations>
  The "Security Considerations" section is the canonical reference for `shell=True` hazards.
- **`xml.etree.ElementTree` — The ElementTree XML API**: <https://docs.python.org/3/library/xml.html#xml-vulnerabilities>
  The "XML vulnerabilities" table — billion-laughs, quadratic-blowup, external entity, external DTD — and the recommendation to use `defusedxml`.
- **`random` — Generate pseudo-random numbers**: <https://docs.python.org/3/library/random.html>
  > "**Warning:** The pseudo-random generators of this module should not be used for security purposes. For security or cryptographic uses, see the `secrets` module."
- **`secrets` — Generate secure random numbers for managing secrets**: <https://docs.python.org/3/library/secrets.html>
  The replacement for `random` whenever the output is ever seen by an attacker.
- **`hashlib` — Secure hash and message digest algorithms**: <https://docs.python.org/3/library/hashlib.html>
  Note the `algorithms_guaranteed` and `algorithms_available` sets; note which algorithms are no longer recommended for any new use (`md5`, `sha1`).
- **`tempfile` — Generate temporary files and directories**: <https://docs.python.org/3/library/tempfile.html#tempfile.mktemp>
  > "**Deprecated since version 2.3:** Use `mkstemp()` instead."
  `mktemp` is a TOCTOU footgun; the deprecation has been in place for two decades.
- **`re` — Regular expression operations**: <https://docs.python.org/3/library/re.html>
  Read for the engine semantics; the ReDoS hazard is implicit (Python's `re` is a backtracking engine).
- **`shlex` — Simple lexical analysis**: <https://docs.python.org/3/library/shlex.html>
  `shlex.quote` and `shlex.split` are the canonical safe-shell-input helpers when you *must* construct a shell command.

---

## OWASP — the Python-specific cheat sheets

- **OWASP Cheat Sheet Series — Deserialization Cheat Sheet** (the canonical writeup of `pickle` / `yaml` / Java-serialisation hazards and their fixes): <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
- **OWASP Cheat Sheet Series — Server-Side Request Forgery Prevention Cheat Sheet** (the allow-list pattern, the literal-IP pattern, the cloud-metadata hazards): <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **OWASP Cheat Sheet Series — Regular Expression Denial of Service - ReDoS** (the catastrophic-backtracking pattern catalogue, the rewrite recipes): <https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS>
- **OWASP Cheat Sheet Series — Secure Coding Practices Quick Reference Guide** (the language-agnostic baseline; cite at audit-report-cover time): <https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/>
- **OWASP Python Security Project** (community-maintained, somewhat dated, still has the language-flavour primer): <https://github.com/ebranca/owasp-pysec>

---

## CVEs cited this week (read each advisory)

Every CVE below is cited in at least one lecture or exercise. The NVD entry and, where available, the upstream advisory are the primary sources; read the upstream first.

### Deserialisation and YAML

- **CVE-2017-18342** — PyYAML default-loader is unsafe; led to the `safe_load`-by-default API split. NVD: <https://nvd.nist.gov/vuln/detail/CVE-2017-18342>. Upstream: <https://github.com/yaml/pyyaml/issues/420>.
- **CVE-2019-20907** — `tarfile.TarFile.extract` directory traversal (path traversal during deserialisation of an archive). NVD: <https://nvd.nist.gov/vuln/detail/CVE-2019-20907>. This is the precursor to the better-known *zip-slip* and the long-running *tar-slip* class.
- **CVE-2022-34265** — Django QuerySet `Trunc()/Extract()` SQL injection (an injection CVE cited as the example of *even framework code can ship the bug*). NVD: <https://nvd.nist.gov/vuln/detail/CVE-2022-34265>.
- **CVE-2022-40898** — `wheel` regex DoS in tag parsing (Python tooling itself shipped a ReDoS). NVD: <https://nvd.nist.gov/vuln/detail/CVE-2022-40898>.
- **CVE-2024-35195** — `requests` proxy credential leak via `verify=False` followed by `verify=True` on the same `Session`. NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-35195>.

### ReDoS

- **CVE-2020-7720** — NLTK ReDoS in a regex used by `word_tokenize`. NVD: <https://nvd.nist.gov/vuln/detail/CVE-2020-7720>.
- **CVE-2022-23491** — `certifi` removed the TrustCor root after a ReDoS-adjacent disclosure. NVD: <https://nvd.nist.gov/vuln/detail/CVE-2022-23491>.
- **CVE-2023-37920** — `certifi` follow-up. NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-37920>.
- **CVE-2024-23334** — `aiohttp` static-route path traversal; cited as an example of a *real* finding in mainstream Python tooling. NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-23334>.

### SSRF and HTTP clients

- **CVE-2018-18074** — `requests` sent `Authorization` header on cross-host redirect (the canonical SSRF-adjacent CVE in the Python HTTP-client world). NVD: <https://nvd.nist.gov/vuln/detail/CVE-2018-18074>.
- **CVE-2023-32681** — `requests` proxy-Authorization leak on cross-host redirect. NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-32681>.

### Pickle in the wild

- **CVE-2019-6446** — `numpy.load` allowed pickle deserialisation by default; the default flipped to `allow_pickle=False`. NVD: <https://nvd.nist.gov/vuln/detail/CVE-2019-6446>.
- **CVE-2022-29216** — TensorFlow Keras `load_model` deserialises arbitrary Python via Lambda layers (a *real* ML-supply-chain pickle case). NVD: <https://nvd.nist.gov/vuln/detail/CVE-2022-29216>.

### Insecure randomness

- **CVE-2008-0166** — Debian OpenSSL predictable PRNG (cited as the canonical "randomness as a security primitive" case study; not Python, but every Python developer should know it). NVD: <https://nvd.nist.gov/vuln/detail/CVE-2008-0166>.

---

## Supply chain — the Python ecosystem

- **OSV (Open Source Vulnerabilities) database** — Google-led, schema-defined, JSON-API; backs `pip-audit`: <https://osv.dev/>
- **PyPI Advisory Database** (the JSON feed of advisories that pip-audit and dependabot consume): <https://github.com/pypa/advisory-database>
- **GitHub Advisory Database** — Dependabot's source: <https://github.com/advisories>
- **`safety`** — alternative Python supply-chain scanner; free CLI with a community-curated DB. Useful as a cross-check on `pip-audit`. <https://github.com/pyupio/safety>
- **`pip-tools`** — `pip-compile` for deterministic lockfiles, the prerequisite for a meaningful supply-chain audit: <https://github.com/jazzband/pip-tools>
- **`uv`** — Astral's Rust-based pip / pip-tools replacement; fast lockfile resolution, becoming common in 2025: <https://docs.astral.sh/uv/>
- **PEP 458** — "Surviving a Compromise of PyPI" — the TUF (The Update Framework) deployment design for PyPI: <https://peps.python.org/pep-0458/>
- **PEP 740** — "Index support for digital attestations" — the Sigstore-based signing story: <https://peps.python.org/pep-0740/>
- **Sigstore / `cosign`** — keyless signing for software artifacts, including Python packages: <https://www.sigstore.dev/>
- **The XZ Utils backdoor (CVE-2024-3094)** — supply-chain incident that shifted the conversation in 2024. Andres Freund's disclosure: <https://www.openwall.com/lists/oss-security/2024/03/29/4>.

---

## Regular expressions and ReDoS

- **`re2`** (Google's linear-time regex engine; no backtracking, ReDoS-immune by construction): <https://github.com/google/re2>
- **`google-re2`** (Python binding): <https://pypi.org/project/google-re2/>
- **`re2`** (older Python binding): <https://pypi.org/project/re2/>
- **`pyrelint`** (a ReDoS-finder lint tool): <https://github.com/myint/eradicate> (note: ecosystem moves; verify current tooling at audit time).
- **OWASP ReDoS page** (already linked above; primary reference for the pattern catalogue).
- **rxxr2** (an academic ReDoS finder; useful as a reference for the detection algorithm): <https://www.cs.bham.ac.uk/~hxt/research/rxxr.shtml>.
- **CodeQL ReDoS queries** (GitHub's CodeQL ships a polynomial-and-exponential-ReDoS query suite for Python): <https://codeql.github.com/codeql-query-help/python/>.

---

## CI integration — primary references

- **GitHub Actions — `setup-python`**: <https://github.com/actions/setup-python>
- **`bandit-action`** (community-maintained GH Action wrapper; verify maintenance status before pinning): <https://github.com/marketplace?query=bandit>.
- **`semgrep` GitHub Action** (official): <https://semgrep.dev/docs/semgrep-ci/sample-ci-configs/#github-actions>
- **`pip-audit` GitHub Action** (official): <https://github.com/pypa/gh-action-pip-audit>
- **GitHub Code Scanning** (the SARIF upload target; both `bandit` and `semgrep` emit SARIF): <https://docs.github.com/en/code-security/code-scanning>
- **GitLab CI — SAST integration** (for learners on GitLab): <https://docs.gitlab.com/ee/user/application_security/sast/>

---

## CWE / standards mapped this week

The Week 5 lectures and exercises map to the following weaknesses (cite by CWE ID in your audit reports):

- **CWE-502** Deserialization of Untrusted Data — every `pickle` / `yaml.load` finding.
- **CWE-1333** Inefficient Regular Expression Complexity — every ReDoS finding.
- **CWE-918** Server-Side Request Forgery (SSRF) — every `requests.get(user_url)` finding.
- **CWE-78** OS Command Injection — every `subprocess(shell=True)` / `os.system` finding.
- **CWE-94** Code Injection — `eval` / `exec` / `compile` on tainted input.
- **CWE-330** Use of Insufficiently Random Values — every `random` for security finding.
- **CWE-377** Insecure Temporary File — `tempfile.mktemp`.
- **CWE-22** Path Traversal — `tarfile.extract` without `data_filter`, `zipfile.extract` without member check.
- **CWE-611** Improper Restriction of XML External Entity Reference — XXE.
- **CWE-776** Improper Restriction of Recursive Entity References — billion-laughs.
- **CWE-1395** Vulnerable Third-Party Component — every `pip-audit` finding.

NIST and ASVS context (when reporting upward):

- **NIST SP 800-218 (SSDF)** — Secure Software Development Framework. <https://csrc.nist.gov/publications/detail/sp/800-218/final>. Cite at audit-report-cover time for regulated audiences.
- **OWASP ASVS v4.0.3** — Level 1 controls map to the findings in this week. <https://owasp.org/www-project-application-security-verification-standard/>.

---

## Trail of Bits and other practitioner blogs

- **Trail of Bits** — the maintainers of `pip-audit`, regularly publish on Python supply-chain topics: <https://blog.trailofbits.com/>.
- **Snyk Python advisory feed**: <https://security.snyk.io/vuln/pip>.
- **Sonatype Python advisory feed**: <https://www.sonatype.com/resources/vulnerabilities>.
- **PortSwigger Web Security Academy — SSRF labs**: <https://portswigger.net/web-security/ssrf>. Free, browser-only, the cleanest interactive teaching material in the SSRF space.

---

## Books

- **David Aitel, *The Hacker's Handbook for Python*** (informal; check current edition). Old but pedagogically clean on the `pickle` and `eval` classes.
- **Bryan Sullivan and Vincent Liu, *Web Application Security: A Beginner's Guide*** (McGraw-Hill, 2011). Dated in specifics, still clean on the categories.
- **Andrew Hoffman, *Web Application Security*** (O'Reilly, 2nd ed. 2024). The most up-to-date single-author book.
- **Russ Cox's regex blog series** (free, online; the canonical explanation of why backtracking engines have catastrophic worst cases and why `re2` does not): <https://swtch.com/~rsc/regexp/regexp1.html> (and parts 2-4 linked from there). Read this before patching any ReDoS finding.

---

## Glossary

- **AST** — Abstract syntax tree; the data structure `bandit` walks to find patterns.
- **Backtracking regex engine** — a regular expression engine that explores alternatives by saving state and undoing; vulnerable to catastrophic worst cases on adversarial input.
- **Catastrophic backtracking** — the regex-engine pathology that produces exponential time for some inputs; the foundation of ReDoS.
- **CVE** — Common Vulnerabilities and Exposures; the public identifier for a security advisory.
- **CWE** — Common Weakness Enumeration; the weakness-class identifier (the *type* of bug, vs. CVE's *specific instance*).
- **CI** — Continuous integration; the automated build that runs on every push and every PR.
- **OSV** — Open Source Vulnerabilities; the database backing `pip-audit`.
- **Pickle RCE** — Remote Code Execution via the `__reduce__` protocol in Python's `pickle` module; the canonical Python deserialisation-trap exploit.
- **ReDoS** — Regular Expression Denial of Service; exhausting CPU via a catastrophic-backtracking regex.
- **SARIF** — Static Analysis Results Interchange Format; the JSON schema for scanner output that GitHub Code Scanning ingests.
- **SAST** — Static Application Security Testing; the umbrella term for tools that read source code (`bandit`, `semgrep`).
- **SCA** — Software Composition Analysis; the umbrella term for tools that read dependency manifests (`pip-audit`, `safety`).
- **SSRF** — Server-Side Request Forgery; coercing a server to make an HTTP request the attacker chose.
- **TOCTOU** — Time-Of-Check-Time-Of-Use; the race-condition class around file-system primitives (`tempfile.mktemp`).
- **TUF** — The Update Framework; the model PyPI is adopting (PEP 458) for repository-level supply-chain integrity.
- **Triage** — sorting scanner findings into act/accept/suppress/won't-fix buckets; the work the scanner cannot do for you.
- **XXE** — XML eXternal Entity attack; one of the classic XML-parser vulnerability classes covered by `defusedxml`.

---

*Updated 2025-Q4. Resources move; if a link 404s, search the archive (`web.archive.org`) and open a PR with the replacement URL.*
