# Week 6 — Resources

Every resource here is **free** and, where possible, a primary source. Week 6 is the *reading-heavy* week; you will read more code (other people's PRs) and more audit reports (Trail of Bits, Project Zero, NCC, Cure53) than you will write. The reading list below is the corpus working application-security engineers cite to each other; the rest is supporting material.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The audit reports and proof-of-concept code linked from these      │
│  resources are for reading and for reproduction on machines you     │
│  own. Do not run any exploit code against a service you do not      │
│  operate. Do not file public PoCs against upstream projects         │
│  without coordinated disclosure.                                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Primary — public audit reports (read at least two complete)

The two practitioner bodies of work below are the cleanest, most-cited, and most-imitated audit writing in the public domain. Both are free; both are recent; both are the same shape as the audit report you will eventually be asked to write at work.

### Trail of Bits

Trail of Bits is a New York–based security-engineering firm that publishes the majority of its commercial audit reports under permissive licences after the engagement concludes. The reports cover cryptocurrency contracts, distributed systems, cryptographic libraries, build systems, and a great deal of Python. They are the closest thing in the public domain to "this is what a paid audit looks like."

- **Public-audits index:** <https://publicaudits.org/> — the cross-firm aggregator, includes Trail of Bits and many others.
- **Trail of Bits publications repository:** <https://github.com/trailofbits/publications> — every public report, with the engagement PDF and (often) a `README.md` describing scope, methodology, and high-severity findings.
- **Trail of Bits blog:** <https://blog.trailofbits.com/> — short-form posts covering tooling (`pip-audit`, `slither`, `manticore`), methodology, and case studies.
- **Trail of Bits "Building Secure Contracts" guide:** <https://secure-contracts.com/> — for Solidity audits but the *review-methodology* sections are language-agnostic and worth reading.
- **"Testing Handbook":** <https://appsec.guide/> — Trail of Bits's published methodology for testing software, free and updated.

Reports to read this week (any one is enough; two is the recommended budget):

- **Trail of Bits audit of `cpython` (2023)** — the audit of the Python interpreter itself. Read the methodology section even if you skip the findings.
- **Trail of Bits audit of `pip-audit` design** — <https://blog.trailofbits.com/2022/03/02/announcing-pip-audit-the-pypa-vulnerability-auditor/> — the design document for the tool you used in Week 5.
- **Trail of Bits audit of `cryptography`** — the audit of the de-facto Python cryptography library.
- **Trail of Bits audit of `ZenGo`, `Compound`, `Curve`, `Yearn`** (smart contracts) — even if blockchain is not your stack, the *finding-write-up* shape is the same.

### Google Project Zero

Project Zero is Google's in-house zero-day research team. They publish a deep technical write-up for every vulnerability they disclose, with the *root-cause analysis*, the *exploit primitives*, and the *patch-gap analysis* that distinguishes a senior security engineer's reading of a bug from a junior's.

- **Project Zero blog:** <https://googleprojectzero.blogspot.com/> — free, no paywall, no signup.
- **Project Zero issue tracker:** <https://bugs.chromium.org/p/project-zero/issues/list> — every reported vulnerability, with the technical write-up after the 90-day disclosure window.
- **"0day In the Wild" tracker:** <https://googleprojectzero.github.io/0days-in-the-wild/> — the consolidated list of zero-days observed exploited in the wild, with root-cause analyses for each.

Posts to read this week:

- The most-recent **"Year in Review"** post (Project Zero publishes an annual retrospective). The methodology and statistics sections are the cleanest summary of the state of practical exploitation.
- Any **three "0day-in-the-wild"** root-cause analyses from the last twelve months. The bugs are not Python; the *reasoning* is universal.
- **"In the Wild Series"** (2021) — the seven-part post chain analysing a state-actor-grade exploit chain. The patch-gap analysis in part 6 is the gold standard for "what to look for in code review beyond the immediate bug."

### NCC Group

NCC Group is a UK-based security consultancy that publishes a large catalogue of public technical advisories and whitepapers.

- **NCC Group research index:** <https://research.nccgroup.com/> — free, primary, recent.
- **NCC public reports archive:** <https://research.nccgroup.com/category/public-tools-and-reports/>.
- Specifically worth reading: their **public reviews of CPython and PyPI tooling**, their **TLS/PKI work**, and their **threat-modeling whitepapers**.

### Cure53

Cure53 is a Berlin-based application-security consultancy. They publish nearly every commercial pentest report after the engagement closes, with the client's permission, and the reports are the canonical "what does a web-application pentest look like" reference.

- **Cure53 publications index:** <https://cure53.de/#publications> — free PDFs.
- Specifically worth reading: their reviews of **Mullvad VPN, Signal Desktop, Tutanota, Cryptocat, Mailvelope**, and the more recent **Open Tech Fund-sponsored audits** of OSS communications tools.

### OSTIF (Open Source Technology Improvement Fund)

OSTIF brokers and publishes audits of important open-source projects funded by various foundations. Their published audits include the underlying Trail of Bits / X41 / NCC / Cure53 reports plus a project-level retrospective.

- **OSTIF index:** <https://ostif.org/our-work/> — free, primary, recent.
- Worth reading: their audits of **OpenSSL, curl, GnuTLS, Git, Bouncy Castle, Lodash, Logstash, Sigstore**.

---

## Primary — public PR-review writing

Other people's review *style* is the cheapest way to learn yours. The following are public, free, and recent.

- **CPython peps and core-review threads:** <https://github.com/python/cpython/pulls> — the public CPython PR queue. Pick five recently-merged PRs and read every review comment. Note Brett Cannon's, Pablo Galindo's, and Sam Gross's review register.
- **CPython security advisories:** <https://github.com/python/cpython/security/advisories> — every published advisory with the upstream patch.
- **Django security archive:** <https://docs.djangoproject.com/en/stable/releases/security/> — twenty years of "this CVE was discovered, this patch was shipped" pairs, each with the upstream commit. The diff for every fix is one click away.
- **Flask / FastAPI / Werkzeug security advisories:** the GHSA database for each project — <https://github.com/pallets/flask/security/advisories>, <https://github.com/tiangolo/fastapi/security/advisories>, <https://github.com/pallets/werkzeug/security/advisories>.
- **`requests` / `urllib3` / `aiohttp` security advisories:** <https://github.com/psf/requests/security/advisories>, <https://github.com/urllib3/urllib3/security/advisories>, <https://github.com/aio-libs/aiohttp/security/advisories>.
- **PyPA `pip-audit` advisories** for the supply chain: <https://github.com/pypa/pip-audit/issues?q=label%3Asecurity>.

---

## OWASP — review-specific cheat sheets and guides

- **OWASP Code Review Guide v2 (2017, still current; ~200 pages PDF):** <https://owasp.org/www-project-code-review-guide/> — the canonical written method for security code review. Read sections 4 (review process), 5 (the most-common-vulnerabilities checklist), and 6 (review by technology) at minimum.
- **OWASP Secure Coding Practices — Quick Reference Guide (~10 pages):** <https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/> — the short list. Memorise it.
- **OWASP Cheat Sheet Series — Code Review Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Code_Review_Cheat_Sheet.html>.
- **OWASP Application Security Verification Standard (ASVS) v4.0.3:** <https://owasp.org/www-project-application-security-verification-standard/> — the 286-control checklist. Use Levels 1-2 in PR review; Level 3 is for full pentest.
- **OWASP Top 10 (2021):** <https://owasp.org/Top10/> — required prior reading from Week 4; cite the category in review comments.
- **OWASP API Security Top 10 (2023):** <https://owasp.org/API-Security/editions/2023/en/0x00-header/> — the API-specific list; cite when the PR touches a REST or GraphQL surface.

---

## CWE — the canonical hazard taxonomy

Every review comment cites a CWE. The CWE database is at <https://cwe.mitre.org/>; the relevant subsets:

- **CWE Top 25 (2024):** <https://cwe.mitre.org/top25/> — the list of the 25 most-prevalent, highest-impact weaknesses.
- **CWE Categories:** <https://cwe.mitre.org/data/definitions/699.html> — the "Software Development" category tree.
- **CWE-VIEW-1003 (Weaknesses for Simplified Mapping):** <https://cwe.mitre.org/data/definitions/1003.html> — the curated subset MITRE recommends for CVE assignment. About 130 entries; if you cite from this list, your reviewer will recognise every CWE.

The CWEs most frequently cited in PR review comments:

| CWE | Name | Pattern cue in a diff |
|-----|------|------------------------|
| CWE-20 | Improper Input Validation | Any new input source without a validator |
| CWE-22 | Path Traversal | `os.path.join(base, user_input)` without normalisation |
| CWE-77 | Command Injection | `subprocess.run(..., shell=True)` with user input |
| CWE-78 | OS Command Injection | `os.system(f"...{user_input}...")` |
| CWE-79 | XSS (Stored / Reflected / DOM) | `mark_safe`, `\|safe`, `\| autoescape false`, raw HTML concat |
| CWE-89 | SQL Injection | `cursor.execute(f"SELECT ... {x}")` or `.format()` into SQL |
| CWE-94 | Code Injection | `eval`, `exec`, `compile` on user input |
| CWE-200 | Information Disclosure | Logging tokens / passwords / PII |
| CWE-285 | Improper Authorization | New route without `@login_required` or equivalent |
| CWE-287 | Improper Authentication | Weak password policy, missing 2FA, broken session reset |
| CWE-295 | Improper Certificate Validation | `verify=False`, `ssl.CERT_NONE`, custom verifier |
| CWE-300 | Channel Accessible by Non-Endpoint | MITM-shaped issues |
| CWE-307 | Improper Restriction of Authentication Attempts | No rate-limit on login |
| CWE-311 | Missing Encryption | Sensitive data sent over `http://` |
| CWE-326 | Inadequate Encryption Strength | RSA-1024, ECB mode, MD5 / SHA1 |
| CWE-327 | Use of Broken or Risky Crypto | `md5`, `sha1`, `DES`, `RC4`, custom crypto |
| CWE-330 | Use of Insufficiently Random Values | `random.randint` for tokens, `time.time()` for nonces |
| CWE-345 | Insufficient Verification of Data Authenticity | Deserialising without signature |
| CWE-352 | CSRF | New POST route without CSRF token |
| CWE-377 | Insecure Temporary File | `tempfile.mktemp` |
| CWE-400 | Resource Exhaustion | Unbounded loop / allocation / regex over user input |
| CWE-426 | Untrusted Search Path | PATH manipulation, `subprocess` without full path |
| CWE-434 | Unrestricted File Upload | No content-type / size / extension check |
| CWE-444 | HTTP Request Smuggling | Custom HTTP parsing |
| CWE-502 | Deserialisation of Untrusted Data | `pickle.loads`, `yaml.load`, `marshal.loads` |
| CWE-522 | Insufficiently Protected Credentials | Hardcoded secret, secret in URL, secret in log |
| CWE-601 | Open Redirect | `redirect(request.args["next"])` without allow-list |
| CWE-611 | XXE | `xml.etree.ElementTree.parse` on untrusted input |
| CWE-639 | IDOR | Object ID from request without ownership check |
| CWE-668 | Exposure of Resource to Wrong Sphere | World-readable secret file, `chmod 777` |
| CWE-732 | Incorrect Permission Assignment | `os.chmod(path, 0o777)`, `setuid` |
| CWE-770 | Allocation Without Limits | Unbounded read, unbounded list growth |
| CWE-798 | Use of Hardcoded Credentials | API key in source |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | `pip install` from a URL, `curl ... \| sh` |
| CWE-862 | Missing Authorization | New endpoint without `@requires_permission` |
| CWE-863 | Incorrect Authorization | Permission check on the wrong object |
| CWE-918 | SSRF | `requests.get(user_url)` without allow-list |
| CWE-1004 | Sensitive Cookie Without HttpOnly | `response.set_cookie(...)` missing `httponly=True` |
| CWE-1275 | SameSite Cookie Default | Missing `samesite="Lax"` or stricter |
| CWE-1333 | Inefficient Regex Complexity (ReDoS) | `(a+)+`, `(a|aa)+`, lookbehinds on user input |

The table is comprehensive enough to be a working reference; print it and keep it open while reviewing.

---

## `gh` CLI — the PR-review verbs

The GitHub CLI is the cheapest way to pull a PR onto your laptop, run scanners on it, and write comments.

- **Install:** <https://cli.github.com/>.
- **Authenticate:** `gh auth login` once per machine; afterwards `gh` is available wherever `git` is.
- **The verbs you will use this week:**

```bash
gh pr list --repo OWNER/REPO --state open --label security
gh pr view  NNN --repo OWNER/REPO
gh pr diff  NNN --repo OWNER/REPO                     # the canonical diff
gh pr diff  NNN --repo OWNER/REPO --patch | less       # the diff as a patch file
gh pr checkout NNN --repo OWNER/REPO                   # local branch == the PR's HEAD
gh pr review NNN --repo OWNER/REPO --comment           # post the review
gh pr review NNN --repo OWNER/REPO --request-changes   # request changes (use sparingly)
gh pr review NNN --repo OWNER/REPO --approve           # approve (use carefully)
gh search prs --label security --state open --json url --limit 50
```

- **The `gh pr review` body** can be Markdown; the line-anchored review comments come from the GitHub web UI or from `gh api`. For learning purposes, write reviews as Markdown documents in your portfolio repo and *do not* file them upstream unless the maintainer welcomes the input.

---

## `semgrep` — running rulesets on a PR branch

`semgrep` is the same tool from Week 5; this week you run it against PR branches instead of your own code.

```bash
# After gh pr checkout NNN, on the PR branch:
semgrep --config p/python \
        --config p/owasp-top-ten \
        --config p/security-audit \
        --config p/secrets \
        .

# To scan only the changed files (faster on large repos):
semgrep --config p/python \
        --config p/security-audit \
        $(git diff --name-only main...HEAD | grep '\.py$')
```

The findings go into the model-based review section; treat them as *hints*, not as verdicts.

---

## Recommended reading order for this week

1. **The OWASP Code Review Guide v2**, sections 4 and 5 (~1 hour).
2. **Trail of Bits audit of any one Python project of your choice** (~1 hour, including skimming the methodology section).
3. **Two Project Zero blog posts** of your choice (~1 hour).
4. **Ten recently-merged PRs from the project you will audit in the mini-project**, just for register and cadence (~30 minutes).
5. **The CWE Top 25** (~15 minutes; skim, recognise the top of the list by name).
6. **The OWASP ASVS v4** Level-1 controls (~30 minutes; skim for shape).

Total ~4 hours of focused reading. Spread across the week.

---

## Self-test — before you start the mini-project

You should be able to:

- Open a random Python PR and within five minutes name the trust boundaries the diff crosses.
- Quote the CWE number for "deserialisation of untrusted data" without looking it up.
- Recite the five-anchor comment format from memory: location, hazard, reference, suggestion, severity.
- Distinguish a `[blocking]` finding from a `[minor]` from a `[nit]` and justify each choice.
- Cite one Trail of Bits report by name and one Project Zero post by name and summarise the finding in two sentences each.

If any of the above is shaky, re-read the relevant lecture and resource before starting the mini-project; the mini-project assumes the discipline is in place.
