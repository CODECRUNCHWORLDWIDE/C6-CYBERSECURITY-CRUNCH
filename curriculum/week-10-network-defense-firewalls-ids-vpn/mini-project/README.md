# Mini-Project — Home / Office Network Defence Plan

> *AUTHORIZED USE ONLY.* The mini-project assumes you are designing a network you personally own (your home, your home lab, or a small office you operate). If the network in your mind is not one you own, the deliverable is still valid but the *implementation* portion stays in a VM lab on your laptop. Re-read the week README banner.

---

## What you are building

A defensible network plan for one small environment: your home network, your home lab, or a small office you operate. The plan integrates everything from the three lectures:

- A **stateful firewall** built with nftables that enforces default-deny on `input` and `forward`, with an egress allowlist on at least one server.
- A **Suricata IDS sensor** running the **Emerging Threats Open** ruleset, with at least one full tuning iteration applied.
- A **WireGuard VPN** with at least one client peer onboarded, full configs committed (private keys *not* committed; public keys committed).
- A **segmented network plan** with at least three trust segments (trusted, guest, and either DMZ or IoT or VPN as the third).
- The **documentation an auditor would expect**: topology, addressing plan, allowed-flow matrix, ruleset, sensor config, key inventory (public only), runbook.

The deliverable is a directory inside the repository, not a live deployment. (If you build the live deployment too, that is excellent — but the grade is on the documents.)

---

## Scope discipline

Be honest about what your environment is. The mini-project is graded on *fit-for-purpose*, not on *size*. A coherent plan for a four-device home network beats an aspirational plan for a fifty-device enterprise.

Allowed scopes:

- **Home** — typically 5–30 devices, a single L3 boundary at the router. Realistic: most students.
- **Home lab** — a home with an additional VLAN-capable switch, a dedicated gateway box, and a few servers / VMs that pose a different threat surface from the workstations.
- **Small office** — a business you own, an office space you operate, a small non-profit you administer.

Not allowed (without explicit written authorisation):

- Your school's network.
- Your employer's network (unless you are *the* network administrator, with written sign-off).
- A friend's network, an apartment building's network, a coffee shop's network.

If your real-world environment falls into the "not allowed" bucket, do the mini-project on a **VM lab** on your own laptop. Document the VM lab honestly ("this plan describes a simulated environment of four VMs on my laptop") and the plan is still valid for grading.

---

## Required deliverables

A directory `mini-project/submission-<your-handle>/` containing:

### 1. `plan.md` — the master document

A single Markdown document that contains, in this order:

- **Section 1 — Scope and authorisation.** What network is this plan for? Do you own it? Quote your own authorisation in plain language.
- **Section 2 — Topology.** ASCII diagram (or PNG, but the ASCII version must also be present for grading). At minimum: WAN, gateway, switch, the segments, the IDS sensor's placement, the VPN listener.
- **Section 3 — Addressing plan.** Table of segment → VLAN ID → subnet → gateway → DHCP range → DNS resolver.
- **Section 4 — Allowed-flow matrix.** A square matrix as in Challenge 2 section C.
- **Section 5 — Firewall ruleset.** Reference to `ruleset.nft` plus a paragraph per chain explaining what it does.
- **Section 6 — IDS sensor.** Reference to `suricata.yaml`, `local.rules`, `disable.conf`, `threshold.config`. Plus a paragraph describing what tuning you applied.
- **Section 7 — VPN.** Reference to `wg0-server.conf` and at least one `wg0-<peer>.conf`. Plus a paragraph on key rotation policy and the **jump host** plan.
- **Section 8 — Runbook.** Three runbook entries, one paragraph each:
  - "How to add a new VPN client to the network."
  - "How to triage a Suricata alert."
  - "How to open a new inbound port (and then close it when the use case ends)."
- **Section 9 — Limitations.** A short, honest section naming at least three things this plan does *not* cover. Examples: no EDR on the endpoints, no backup strategy, no incident-response plan (Week 9 covered IR; reference if you already have one), the IDS is signature-based and misses zero-day attacks, the VPN authenticates devices and not users.

### 2. `ruleset.nft` — the gateway's nftables config

A complete, applicable file. Must:

- Default-deny on `input` and `forward`.
- Egress allowlist on at least one server's `output` (or on the gateway's `forward` if you treat the gateway as the egress chokepoint).
- Use named sets for IP and port allowlists.
- Include a comment block at the top with: your name (or handle), the date, the host this ruleset is for, and the authorised-use disclaimer.

### 3. `suricata.yaml` — your sensor's config

Must:

- Set `HOME_NET` correctly to your segments.
- Set the capture interface to the actual NIC you used (or `eth1` as a placeholder if you did not deploy).
- Reference `threshold.config` and `local.rules`.

### 4. `local.rules` — your custom Suricata rules

At least three custom signatures. Each must:

- Use a `sid` in the 1 000 000–1 999 999 range.
- Include `msg`, `classtype`, `metadata:mitre_technique_id ...`.
- Be tied to a specific allowed-flow row from your matrix.

### 5. `disable.conf` and `threshold.config`

At least three categories disabled in `disable.conf`. At least three signatures suppressed or thresholded in `threshold.config`.

### 6. `wg0-server.conf` — your WireGuard server config

With the private key replaced by `PLACEHOLDER_PRIVATE_KEY_FOR_SUBMISSION` (real values stay on the host).

### 7. `wg0-<peer>.conf` — at least one client config

With the same placeholder treatment for the private key.

### 8. `key-inventory.md` — your public-key registry

A Markdown table: peer name, peer device, peer public key, date added, segment the peer belongs to. Public keys *are* committed. Private keys *never* are. The pre-commit hook (described below) will fail any PR that includes a string matching the private-key shape in a file not named `*.public`.

### 9. `runbook.md` — the three operational runbooks

Same as Section 8 in `plan.md` but in a standalone file for the on-call operator to read at 03:00 without scrolling through `plan.md`.

### 10. `evidence/` — proof you actually applied this

A small directory containing:

- `nft-list-ruleset.txt` — the output of `sudo nft list ruleset` after you applied the ruleset to a real host (or a VM in your lab; declare which).
- `wg-show.txt` — the output of `sudo wg show` showing the tunnel up and the peer handshake (you may redact the public keys to last 8 chars).
- `suricata-status.txt` — the output of `sudo systemctl status suricata`.
- `eve-top10.txt` — the top-10 alert SIDs from your sensor's `eve.json` after at least one hour of monitoring.

If your scope is "VM lab on my laptop", say so — the evidence is still real, just from the VMs.

---

## Grading rubric (100 points)

| Section | Points | Rubric                                                                 |
|---------|-------:|------------------------------------------------------------------------|
| Scope & authorisation | 5  | Plain-language declaration; honest about what you own.            |
| Topology              | 10 | All segments visible; sensor + VPN placement clear.               |
| Addressing plan       | 5  | Every segment has a row; subnets do not collide.                  |
| Allowed-flow matrix   | 10 | Every cell filled; deny cells are intentional, not omissions.     |
| Firewall ruleset      | 20 | Applies cleanly; default-deny on input + forward; egress allowlist on at least one host. |
| IDS sensor            | 15 | Healthy service; ET Open loaded; tuning iteration applied.        |
| VPN                   | 15 | Server + at least one peer; private keys not committed; jump host plan articulated. |
| Runbook               | 10 | Three concrete operational scenarios.                              |
| Limitations           | 5  | At least three honest gaps named.                                  |
| Evidence              | 5  | Files in `evidence/` show real artefacts, not fabricated.         |

Total: **100**. Pass: **70**. Distinction: **90**.

---

## Pre-commit safety

Add `.gitignore` entries to your fork:

```
*.private
*private*
*.psk
**/private/
.wg-secrets/
```

And, if you have `pre-commit` installed, add a hook that fails on any base64 string matching the WireGuard private-key shape (`^[A-Za-z0-9+/]{43}=$`) appearing in a tracked file whose name does not end in `.public`. A minimal hook script is at `mini-project/starter/precommit-no-wg-private.sh`.

If your repository does not use pre-commit, the manual check is:

```bash
git ls-files | xargs grep -l -E '^[A-Za-z0-9+/]{43}=$' \
    | grep -v '\.public$' \
    | head
# Output should be empty.  If not, you have a private key in a file
# the repository will commit.
```

Run this before every push.

---

## Realistic time budget

- Plan (Sections 1–4 of `plan.md`): **2 hours**.
- Ruleset (`ruleset.nft`): **2 hours**.
- Suricata deployment and tuning: **2 hours** (most of it waiting for an hour of real traffic for the tuning pass).
- WireGuard server + one peer: **30 minutes**.
- Sections 5–9 of `plan.md` and `runbook.md`: **1.5 hours**.
- Evidence-gathering and pre-commit safety: **30 minutes**.

Target total: **8.5 hours over Friday and Saturday**.

---

## What this mini-project is *not*

It is not a production network. It is not a substitute for an EDR, for backups, for an identity provider, for an incident-response retainer, for cyber insurance. It is the network-layer baseline that every other control sits on top of.

The Week 11 mini-project will build on this baseline. The Week 12 mini-project will tie a Week-9 IR plan, this Week-10 network plan, and a future-week identity-and-access plan into a single coherent posture for a small organisation. Treat *this* week's plan as the network-layer foundation of that arc.

---

## References

- `../README.md` — the week overview and authorised-use banner.
- `../resources.md` — every external reference cited this week.
- `../lecture-notes/` — the three lectures.
- `../exercises/SOLUTIONS.md` — solution walkthroughs.
- `./starter/` — skeleton files to copy and fill in.
