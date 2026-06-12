# C6 · Cybersecurity Crunch — Full Syllabus

**12 weeks · ~432 hours full-time · ~36 hrs/week · C1 graduate → junior security engineer / red-team intern**

This is the full syllabus for C6. Every week follows the standard Code Crunch layout (README, resources, lecture-notes, exercises, challenges, quiz, homework, mini-project).

> **Important — what this track teaches.** C6 covers **defensive and authorized offensive security**. Everything we do is on machines you own, on intentionally vulnerable training environments (VulnHub, Hack The Box, picoCTF, OverTheWire), or with written permission. **We do not teach attacks against systems you don't have authorization to test.** That's a felony in most jurisdictions; it's also lazy thinking — real security work is structured, careful, and consent-based.

---

## Who this is for

- You've completed **C1 · Code Crunch Convos**.
- You've also completed **C14 · Crunch Linux** (or are equivalently comfortable in a Linux terminal).
- You're curious about how systems fail, and how to defend them.

If you want to "learn hacking" in the movie sense, this isn't that course. If you want to be the engineer who catches the vulnerability before it ships — and the one who knows what to do when it doesn't — this is.

---

## What you will be able to do at the end of 12 weeks

- **Read** a security advisory, understand the CVE, reproduce it in a lab, and write the patch.
- **Audit** a Python codebase for the OWASP Top 10 web vulnerabilities and find at least one real instance.
- **Perform** an authorized network scan with `nmap`, interpret the results, and write a remediation memo.
- **Capture and analyze** packet traces with `tcpdump` / Wireshark, and identify suspicious patterns.
- **Set up and exploit (in your own lab)** common Linux privilege escalations — and explain how to prevent each.
- **Write Python tooling** for security work: log parsers, scanners, payload generators, IOC matchers.
- **Understand cryptography enough to not break it**: symmetric vs. asymmetric, signing vs. encryption, why home-rolled crypto fails, why password hashing isn't "encryption."
- **Conduct an incident response** drill: detect → contain → eradicate → recover → review.
- **Compete in CTFs** at the intermediate level (picoCTF, OverTheWire wargames, a small HackTheBox box).

---

## Program at a glance

| Phase | Weeks | Outcome |
|-------|-------|---------|
| **Phase 1 — Fundamentals** | 01 – 03 | Linux security model, networking, threat modeling |
| **Phase 2 — Application Security** | 04 – 06 | OWASP Top 10, secure coding in Python, code audit |
| **Phase 3 — Offensive & Defensive Tooling** | 07 – 09 | Recon, exploitation in lab, detection, hardening |
| **Phase 4 — Operations, Crypto, Capstone** | 10 – 12 | Incident response, cryptography, capstone CTF |

---

## How the weekly load adds up

| Component | hrs/wk |
|-----------|------:|
| Lectures / readings | 6 |
| Hands-on exercises | 8 |
| Coding challenges | 4 |
| Quiz + readings | 3 |
| Homework problems | 6 |
| Mini-project | 7 |
| Self-study & review | 2 |
| **Total** | **36** |

---

## Weekly breakdown

### Phase 1 — Fundamentals

#### Week 1 — The Security Mindset & The Linux Security Model

What "security" actually means (CIA triad and its limits). Threat modeling 101. The Linux security model: users, groups, file permissions, capabilities, setuid, namespaces.

- **Mini-project:** Threat-model a small system you actually use (your laptop, a side project). Produce a 2-page write-up.

#### Week 2 — Networking for Security

TCP/IP refresh from the security angle. Ports, sockets, NAT, firewalls. `tcpdump`, `wireshark`, `iptables` / `nftables`. Reading PCAPs.

- **Mini-project:** Capture and annotate 10 minutes of your own home network traffic. Identify every protocol you see. Flag what surprises you.

#### Week 3 — Threat Modeling and Risk

STRIDE, DREAD, PASTA. Attack trees. Asset-driven vs. attacker-driven models. Risk = likelihood × impact, and why that formula breaks in practice.

- **Mini-project:** Pick a real open-source project. Produce a threat model document covering its 3 highest-priority risks and recommended mitigations.

---

### Phase 2 — Application Security

#### Week 4 — OWASP Top 10 (2025 edition) for Python

Each item explained, demonstrated on a deliberately vulnerable Python app (we provide one based on the OWASP Juice Shop pattern), then patched.

- **Mini-project:** Patch all 10 categories of vulnerability in the provided lab app. Commit each fix as a separate PR with a security write-up.

#### Week 5 — Secure Coding in Python

`pickle` and the deserialization trap. YAML loaded unsafely. SSRF in `requests`. ReDoS. SQL injection (even with ORMs). Insecure randomness. The `bandit` and `semgrep` linters. `pip-audit` for the supply chain.

- **Mini-project:** Run `bandit`, `semgrep`, and `pip-audit` on a real Python codebase (yours from C1 or C16 mini-projects). Document every finding, true positive or false.

#### Week 6 — Code Review for Security

Reviewing PRs through a security lens. Pattern matching for vulnerability classes. The check-list approach vs. the model-based approach. Reading other people's audits — Trail of Bits, Google P0, etc.

- **Mini-project:** Conduct a security code review on a real open-source PR (from a Python project you use). Produce a comment-by-comment review.

---

### Phase 3 — Offensive & Defensive Tooling

#### Week 7 — Recon & Scanning (Authorized Only)

`nmap` in depth, `masscan`, banner grabbing, DNS recon. Passive recon: certificate transparency logs, public archives. Avoiding noisy scans. **Strictly on machines you own or in CTF environments.**

- **Mini-project:** Map a local lab network. Identify every running service. Produce a "what would I close" memo.

#### Week 8 — Exploitation in a Lab

Buffer overflows on a deliberately vulnerable binary. Web exploitation with Burp Community or `mitmproxy`. Linux privilege escalation: kernel CVEs, sudo misconfigs, world-writable scripts. **All on intentionally vulnerable VMs (VulnHub) or HackTheBox starter boxes you have authorization for.**

- **Mini-project:** Solve a beginner CTF box (HackTheBox "starting point" tier, or VulnHub equivalent). Document the full chain from recon to root.

#### Week 9 — Detection & Defense

Hardening Linux. `auditd`, `fail2ban`, `crowdsec`. SIEM basics. Writing detection rules. The "Pyramid of Pain." YARA for file pattern matching.

- **Mini-project:** Set up a small SIEM-lite on your home network (Wazuh or Loki + custom rules). Detect three patterns you generate yourself.

---

### Phase 4 — Operations, Crypto, Capstone

#### Week 10 — Cryptography (Just Enough)

Symmetric (AES) vs. asymmetric (RSA, ECC). Hashes vs. encryption. HMAC. Digital signatures. TLS in plain English. Why home-rolled crypto fails. Why you should use `cryptography` (the Python library), not `pycrypto`.

- **Mini-project:** Implement a tiny end-to-end encrypted note-sharing tool using `cryptography`. Generate and exchange keys. Verify signatures. Don't roll your own primitives.

#### Week 11 — Incident Response

The phases of IR. Log collection and preservation. Memory and disk forensics tooling at a high level (Volatility, Plaso). Communication during incidents. The legal landscape.

- **Mini-project:** Run a tabletop incident: someone (a peer, or yourself) generates a synthetic incident (provided scenarios). You walk through detection → containment → recovery → post-mortem.

#### Week 12 — Capstone CTF + Career Path

A multi-flag CTF designed for you (provided lab environment). Then: how to actually become a security engineer — bug bounties, junior pen-test roles, blue-team paths, certifications worth getting (OSCP, etc.).

- **Capstone:** Solve a custom multi-stage CTF and produce a full pen-test report (executive summary, technical findings, remediation roadmap).

---

## Skills progression chart

```text
W1  ─ security mindset, Linux security
W2  │ networking for security
W3  ─ threat modeling
W4  ─ OWASP Top 10 in Python
W5  │ secure coding in Python
W6  ─ security code review
W7  ─ recon & scanning
W8  │ exploitation in lab
W9  ─ detection & defense
W10 ─ cryptography
W11 │ incident response
W12 ─ CAPSTONE CTF + career
```

---

## Code of conduct

- All offensive techniques are practiced on machines and networks you own, on legally accessible training platforms (picoCTF, OverTheWire, HackTheBox, VulnHub, TryHackMe), or with explicit written permission from the owner.
- Bug bounty programs are an excellent way to apply skills legitimately. Always read the scope.
- Reporting a vulnerability you find responsibly is itself a security skill. We dedicate part of Week 11 to coordinated disclosure.
- **Do not** test systems without authorization. It's a crime in most jurisdictions, professionally career-ending, and ethically not OK.

If a learner is caught doing offensive work outside authorized environments, they are removed from the program. We're serious about this.

---

## What you won't learn (but should later)

- **Hardware / IoT security** — touched briefly. After C6, see C7 for embedded.
- **Cryptanalysis (breaking crypto)** — out of scope; we teach enough to use crypto correctly.
- **Red-team adversary simulation at scale** — graduate work; OSCP / OSEP / OSEE are the certification path.
- **Cloud-specific security** — touched but not deep. After C6, see C15 + provider-specific docs.
- **OS internals / kernel exploitation** — needs C in addition to Python; see [pwn.college](https://pwn.college) (free) for a deep dive.

---

## License

GPL-3.0.
