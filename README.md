# C6 · Cybersecurity Crunch

> A free, open-source **12-week defensive + authorized-offensive security track**. From the Linux security model to a final capture-the-flag exercise — entirely on machines you own, on legal training platforms, or with written authorization. C1 + C14 graduate → junior security engineer / red-team intern.

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Built in the open](https://img.shields.io/badge/built-in%20the%20open-EF4444.svg)](https://github.com/CODE-CRUNCH-CLUB)

C6 teaches **how systems fail, and how to defend them.** Defensive work is the bulk of the curriculum. Offensive techniques are practiced *only* on machines you own, on legal training platforms (picoCTF, OverTheWire, HackTheBox starter rooms, TryHackMe, VulnHub), or with explicit written permission.

> **Read this first.** Testing systems without authorization is a felony in most jurisdictions and an immediate ejection from this program. We're serious about it. See the [Code of Conduct](#code-of-conduct) below.

---

## Pathway summary

- **Full-time:** 12 weeks · ~36 hrs/week · ~432 hours
- **Working-engineer pace:** 6 months · ~18 hrs/week
- **Evening / college-club pace:** 1 year · ~9 hrs/week

See [`SYLLABUS.md`](SYLLABUS.md) for the full 12-week breakdown across four phases (Foundations · AppSec · Offensive & Defensive Tooling · Operations, Crypto, Capstone).

---

## What you will be able to do at the end of 12 weeks

- **Read** a security advisory, understand the CVE, reproduce it in a lab, and write the patch.
- **Audit** a Python codebase for the OWASP Top 10 and find at least one real instance.
- **Perform** an authorized network scan with `nmap`, interpret the results, write a remediation memo.
- **Capture and analyze** packet traces with `tcpdump` / Wireshark, identify suspicious patterns.
- **Set up and exploit (in your own lab)** common Linux privilege escalations — and explain how to prevent each.
- **Write Python tooling** for security work: log parsers, scanners, payload generators, IOC matchers.
- **Understand cryptography enough to not break it.**
- **Conduct an incident-response drill** end-to-end: detect → contain → eradicate → recover → review.
- **Compete in CTFs** at the intermediate level — picoCTF, OverTheWire, a small HackTheBox box.

---

## Who this is for

- **C1 graduate** with a security interest.
- **System / network engineer** ready to move toward security work.
- **Junior developer** who wants to ship safer code.
- **Student or club member** preparing for university capture-the-flag teams.

Not for: people seeking a "how to hack" thrill course (this is engineering work, not a heist film), nor people without Linux comfort (do [C14](../C14-CRUNCH-LINUX/) first).

---

## Prerequisites

- **C1 Weeks 1–11** completed (Python, basic web, basic SQL, testing).
- **C14 · Crunch Linux** completed *or* equivalent comfort with bash, `ssh`, file permissions, services.
- Willingness to read RFCs, advisories, and post-mortems.
- The ability to take notes obsessively.

---

## Code of conduct

- All offensive techniques are practiced **on machines and networks you own**, on **legally accessible training platforms**, or **with explicit written permission** from the owner.
- Bug-bounty programs are an excellent way to apply skills legitimately. Always read the scope carefully.
- Reporting a vulnerability responsibly is itself a security skill. Week 11 dedicates time to coordinated disclosure.
- **Do not** test systems without authorization. It is a crime in most jurisdictions, immediately career-ending, and ethically wrong.

If a learner is observed doing offensive work outside authorized environments, they are removed from the program. There are no second chances on this. The cybersecurity field's reputation depends on practitioners taking authorization seriously.

---

## What you ship

By the end of the program, a `crunch-sec-portfolio-<yourhandle>` GitHub repo containing:

1. A **threat model** for a real system (Week 1).
2. An **annotated PCAP** of your own home-network traffic (Week 2).
3. A **patched vulnerable web app** with all 10 OWASP categories fixed and documented (Week 4).
4. A **security code review** on a real open-source PR (Week 6).
5. A **CTF write-up** for one HackTheBox starter or VulnHub box (Week 8).
6. A **small home SIEM setup** with three custom detection rules (Week 9).
7. An **end-to-end encrypted note tool** built with the `cryptography` library (Week 10).
8. An **incident-response tabletop write-up** (Week 11).
9. A **pen-test report** for the Week-12 capstone CTF — executive summary, technical findings, remediation roadmap (Week 12).

That portfolio is what you point hiring managers at.

---

## Tools (all free, all open-source)

| Tool | Role |
|------|------|
| **Linux** | The work environment. Kali (live or VM), Ubuntu, or your own. |
| **Python 3.11+** | Custom tooling |
| **nmap · masscan** | Network discovery |
| **Wireshark · tcpdump** | Packet analysis |
| **Burp Community · mitmproxy** | Web traffic interception |
| **bandit · semgrep · pip-audit** | Python static analysis & supply-chain audit |
| **Wazuh / Loki + Grafana** | SIEM-lite |
| **YARA** | File pattern matching |
| **cryptography (Python library)** | Crypto primitives — use, don't roll your own |
| **TryHackMe · HackTheBox · picoCTF · OverTheWire · VulnHub** | Legal training grounds |

No paid certifications required. No proprietary scanners. No vendor-locked SIEMs.

---

## Next track after C6

- **[C15 · Crunch DevOps](../C15-CRUNCH-DEVOPS/)** — for the production-operations side of security.
- **OSCP / Pentest+ / Security+** — vendor certifications worth pursuing after C6, with the practical groundwork now done.
- **[pwn.college](https://pwn.college)** — free, deep OS / binary exploitation if you want to specialize in that direction.

---

## License

GPL-3.0. See [LICENSE](LICENSE).

---

*C6 is part of the Code Crunch open-source curriculum.* [Master catalog ↗](../MASTER-CURRICULUM.md) · [Brand family ↗](../../assets/brand/BRAND-FAMILY.md)


---

<!-- CCWW:AUTO-INDEX:START — generated by scripts/restructure_course_repos.py; edit ABOVE this marker -->

## Course at a glance

| Section | Count |
| --- | --- |
| Curriculum entries | 13 |
| Projects | 0 |
| Past sessions | 2 |

## Curriculum

- [SYLLABUS](curriculum/SYLLABUS.md)
- [week 01 security mindset and linux security](curriculum/week-01-security-mindset-and-linux-security/README.md)
- [week 02 networking for security](curriculum/week-02-networking-for-security/README.md)
- [week 03 threat modeling and risk](curriculum/week-03-threat-modeling-and-risk/README.md)
- [week 04 owasp top 10 python](curriculum/week-04-owasp-top-10-python/README.md)
- [week 05 secure coding python](curriculum/week-05-secure-coding-python/README.md)
- [week 06 code review for security](curriculum/week-06-code-review-for-security/README.md)
- [week 07 authorized recon and scanning](curriculum/week-07-authorized-recon-and-scanning/README.md)
- [week 08 web application security hands on](curriculum/week-08-web-application-security-hands-on/README.md)
- [week 09 incident response and log forensics](curriculum/week-09-incident-response-and-log-forensics/README.md)
- [week 10 network defense firewalls ids vpn](curriculum/week-10-network-defense-firewalls-ids-vpn/README.md)
- [week 11 cloud security iam and misconfig](curriculum/week-11-cloud-security-iam-and-misconfig/README.md)
- [week 12 capstone vulnerability discovery and disclosure](curriculum/week-12-capstone-vulnerability-discovery-and-disclosure/README.md)

## In this course

- **Community** — [community/](community/)
- **Curriculum** — [curriculum/](curriculum/)
- **Projects** — [projects/](projects/)
- **Resources** — [resources/](resources/)
- **Past sessions** — [past-sessions/](past-sessions/)

<!-- CCWW:AUTO-INDEX:END -->
