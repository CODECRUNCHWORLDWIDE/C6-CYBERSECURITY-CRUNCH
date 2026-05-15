# Challenge 2 — Segmentation Blueprint for a Small Office

> *AUTHORIZED USE ONLY.* This challenge is a paper exercise plus an optional lab implementation. If you implement, do so on a network you own. Re-read the week README banner.

---

## Scenario

You are the part-time IT contractor for **Citrus Bay Pediatrics**, a five-physician pediatric clinic in a small commercial space. The clinic has:

- Five exam rooms, each with a workstation that pulls patient charts from the EMR.
- A receptionist desk with a workstation and a card-terminal device.
- A back-office room with the EMR server, a file server for scanned documents, the gateway router, the network switch, and an unused Raspberry Pi 5 that you are authorised to repurpose.
- Approximately twenty IoT devices: a smart-TV in the waiting room, smart thermostats, smart locks, two networked printers, a few networked weight scales, an ultrasound device, an X-ray-capture machine, a backup-power inverter that reports to a vendor cloud.
- Two physicians who need remote access to the EMR from home (HIPAA-covered, so the access has to be encrypted end-to-end and auditable).
- A guest Wi-Fi for patients to use in the waiting room.

The current state of the network is: one flat `192.168.1.0/24` subnet, an off-the-shelf consumer router (no VLAN support), no firewall beyond the router's default NAT, no IDS, no VPN. The office computers, the IoT, the EMR server, and the guest Wi-Fi are all on the same broadcast domain. The physicians' remote access is "port-forward 8443 to the EMR server and hope".

You have been asked to write a **segmentation blueprint** — *the document you would hand to a network installer* — that describes the target state of the network. You are not asked, in this challenge, to do the physical install; you are asked to specify it well enough that an installer can.

The clinic operates under **HIPAA**. The clinic's compliance officer is one of the physicians, and she has handed you a one-page summary of the **HIPAA Security Rule's** technical safeguards (§164.312): access control, audit controls, integrity, person-or-entity authentication, transmission security. Your blueprint must address those five points by reference; the implementation details are network-level.

---

## Deliverable

A single document, `challenge-02-blueprint.md`, with the following sections.

### Section A — Topology diagram (ASCII or PNG)

A network diagram showing:

- The WAN uplink to the ISP.
- The new managed L2/L3 switch (specify a model class — "Ubiquiti EdgeSwitch 8 or equivalent" is fine).
- The new gateway (the Raspberry Pi 5 you have been authorised to repurpose, running Debian or Ubuntu, acting as the gateway with nftables + Suricata + WireGuard).
- **At least five segments**, with subnet and VLAN ID for each:
  - **trusted** — physician + receptionist workstations.
  - **medical** — EMR server, file server, medical-device equipment that the physician workstations need to reach (X-ray, ultrasound).
  - **iot** — printers, thermostats, scales, locks, the smart-TV.
  - **guest** — the patient Wi-Fi.
  - **vpn** — WireGuard overlay for the two remote physicians.
- The relationship between each segment and the others, drawn as either an "allow" or "deny" line.

### Section B — Addressing plan (a Markdown table)

Each row of the table: segment, VLAN ID, subnet (IPv4 CIDR), gateway address, DHCP range, DNS resolver address. Use private addressing (RFC 1918). Choose subnets that do not collide with common home-network ranges (`192.168.0.0/24`, `192.168.1.0/24`).

### Section C — Allowed-flow matrix (a Markdown table)

A square matrix, one row per source segment, one column per destination segment, cell value = "allow + protocols" or "deny" or "via jump host". At minimum:

|         | trusted | medical | iot | guest | vpn | WAN  |
|---------|---------|---------|-----|-------|-----|------|
| trusted |   any   |  ...    | ... |  ...  | ... | ...  |
| medical |   ...   |  ...    | ... |  ...  | ... | ...  |
| iot     |   ...   |  ...    | ... |  ...  | ... | ...  |
| guest   |   ...   |  ...    | ... |  ...  | ... | ...  |
| vpn     |   ...   |  ...    | ... |  ...  | ... | ...  |

Fill every cell. For each "allow", specify the protocol(s) and the port(s). For each "via jump host", specify the jump host's address.

### Section D — The nftables ruleset (an `nft` file)

A complete `ruleset.nft` that implements Section C on the gateway. Default-deny on `input` and `forward`. Egress allowlist on `output`. Use named sets for the trusted segments and named verdict maps for the per-segment forwarding decisions.

Apply on a VM in your lab; verify with `sudo nft -f ruleset.nft && sudo nft list ruleset`.

### Section E — The Suricata configuration (a `suricata.yaml` + a `local.rules`)

- A `suricata.yaml` fragment that sets `HOME_NET` correctly to the five segments above.
- A `disable.conf` that drops at least three irrelevant categories.
- A `local.rules` with at least three custom signatures, each tied to a flow you described in Section C and each tagged with an ATT&CK technique ID.

### Section F — The WireGuard plan

- A server config (`wg0-server.conf`) skeleton with the placeholders for the server's keys and the two physicians' peer blocks.
- Two client config skeletons (`wg0-alice.conf`, `wg0-bob.conf`) for the two physicians' laptops.
- A short paragraph on key rotation: when, how, by whom. Acknowledge that re-keying the server requires re-distributing the new public key to every peer.
- A short paragraph on the **jump host** for VPN-to-medical access. The two physicians do NOT get direct SSH to the EMR server. They get SSH (over the VPN) to a hardened jump host in the medical segment; from the jump host they reach the EMR server over its application port.

### Section G — HIPAA traceability (a Markdown table)

Two columns: HIPAA Security Rule technical safeguard (§164.312 (a) through (e)), and your blueprint's control. Example:

| 45 CFR § 164.312 | Blueprint control                                  |
|------------------|----------------------------------------------------|
| (a)(1) Access control | Segmentation + jump-host for medical segment   |
| (b) Audit controls    | Suricata `eve.json` + sshd logging on jump host |
| (c)(1) Integrity      | (your answer)                                  |
| (d) Person-or-entity authentication | (your answer)                       |
| (e)(1) Transmission security | (your answer)                            |

The cells must be specific; "we have a firewall" is not a control.

### Section H — Runbook

Three short runbooks (one paragraph each):

1. **Add a new physician's laptop to the VPN.** (Onboarding.)
2. **A Suricata alert with severity 1 fires from the IoT segment.** (Triage.)
3. **The clinic's internet uplink drops; what continues to work?** (Resilience.)

---

## Pass criteria

- **Topology.** Five segments. Each with a subnet, a VLAN, a gateway, a DHCP scope, a DNS resolver. No subnet collides with any common home-network range.
- **Allowed-flow matrix.** Every cell filled. The medical segment is reachable only from trusted via a jump host or from authorised application ports.
- **Ruleset.** Applies cleanly with `nft -f`. Default-deny on `input` and `forward`.
- **HIPAA traceability.** Every row of Section G has a concrete control.
- **Honesty.** A "Limitations" section at the end of the document acknowledging at least three controls your blueprint does *not* implement (endpoint EDR, multi-factor on the EMR application itself, encrypted-at-rest disk on the medical segment, BAA with the EMR vendor, etc.).

---

## What "done" looks like

A PR to your fork of the curriculum repository, branch `week-10-challenge-02-<your-handle>`, that adds:

```
week-10-network-defense-firewalls-ids-vpn/challenges/submissions/
    <your-handle>/
        challenge-02-blueprint.md           (the document with Sections A–H)
        challenge-02-ruleset.nft            (Section D)
        challenge-02-suricata.yaml          (Section E - fragment)
        challenge-02-local.rules            (Section E - rules)
        challenge-02-wg0-server.conf        (Section F)
        challenge-02-wg0-alice.conf         (Section F)
        challenge-02-wg0-bob.conf           (Section F)
```

No file with `private` or `psk` in its name. The keys in the config skeletons are placeholders (`PLACEHOLDER_BASE64_KEY_HERE`), not real.

---

## References

- NIST SP 800-41 Rev. 1, *Guidelines on Firewalls and Firewall Policy.* https://doi.org/10.6028/NIST.SP.800-41r1
- NIST SP 800-207, *Zero Trust Architecture.* https://doi.org/10.6028/NIST.SP.800-207
- NIST SP 800-46 Rev. 2, *Guide to Enterprise Telework, Remote Access, and BYOD Security.* https://doi.org/10.6028/NIST.SP.800-46r2
- HHS, *HIPAA Security Rule.* 45 CFR Part 160 and Subparts A and C of Part 164. https://www.hhs.gov/hipaa/for-professionals/security/index.html
- nftables wiki — https://wiki.nftables.org/
- Suricata documentation — https://docs.suricata.io/
- Emerging Threats Open — https://rules.emergingthreats.net/open/
- Donenfeld 2017 — https://www.wireguard.com/papers/wireguard.pdf
- CISA, *Layering Network Security Through Segmentation.* https://www.cisa.gov/news-events/news/layering-network-security-through-segmentation

This challenge is the bridge to the mini-project, which asks you to do the same for a network you actually own. Treat the blueprint here as the *exemplar*, and treat the mini-project as the *real version of you*.
