# Challenge 1 — Egress Breakout

> *AUTHORIZED USE ONLY.* This challenge is a tabletop scenario plus a rule-writing task. The implementation is done in a VM or a small lab you own; no traffic crosses any network you are not authorised to operate. Re-read the week README banner.

---

## Scenario

A junior developer on your team has compromised their own laptop by clicking a malicious link in what looked like a job-offer PDF. The laptop is on the trusted segment of the office network (`10.0.10.0/24`). The malware is a modern commodity command-and-control implant. It:

- Speaks **HTTPS to a CDN-fronted domain**. The TLS handshake looks ordinary; SNI is a benign-looking domain that the CDN also serves legitimate sites from. JA3 fingerprint is the default Chrome on Windows.
- **Beacons every 30 seconds** with a small request (~1 KB). Posts data on demand in chunks of up to 50 KB.
- **Falls back to DNS tunnelling** if HTTPS is blocked. Uses TXT-record queries to `*.evil-c2.example` to encode commands and exfiltrate data in 200-byte chunks.
- **Falls back to ICMP tunnelling** if both HTTPS and DNS are blocked. Encodes data in the `Data` portion of ICMP echo-request packets.
- Does *not* attempt SMB, RPC, or any other internal protocol. The traffic is purely egress.

Your gateway is a Linux box running `nftables`. The trusted segment is allowed to egress to the internet today, with no constraints. You have authorisation from the office owner (the developer's employer) to change the gateway's ruleset and to put their compromised laptop in a contained sub-segment for analysis.

The Suricata sensor on the gateway saw the beacon traffic in `eve.json` at a low alert severity and the alert was lost in the unfiltered alert stream. (Lesson for next quarter: tune Suricata. That is not this week's challenge.)

---

## Deliverable

A single document, `challenge-01-write-up.md`, containing **all** of the following sections:

### Section A — Threat model (200–400 words)

Describe the threat in the terms of MITRE ATT&CK. Cite at least:

- **Initial Access**: one technique.
- **Command and Control**: at least three techniques (HTTPS-C2, DNS-C2, ICMP-C2 should map cleanly).
- **Exfiltration**: at least one technique.

For each technique cited, link to its page on https://attack.mitre.org/.

### Section B — The first-response containment posture (150–300 words)

Before any sophisticated rule-writing, what do you do *right now* to stop the bleeding while you write the more careful rules? Two paragraphs. Be specific about:

- Network-level containment of the compromised host (move it to a quarantine VLAN? unplug it? leave it running and tap the traffic?).
- Communications to the developer and to leadership.

### Section C — The egress ruleset (an `nft` file)

A complete, applicable nftables ruleset that, when applied to the gateway, would have prevented each of the four egress channels above. The ruleset must:

1. **Default-deny on the `forward` chain** between the trusted segment and the WAN.
2. **Allowlist outbound HTTPS** to a small, enumerated set of approved destinations only.
3. **Force outbound DNS** through a recursive resolver you operate (`10.0.0.53` in the lab) and block direct UDP/53 to any external resolver from anything except that recursive resolver.
4. **Block outbound ICMP from the trusted segment** to the WAN, except for explicit `ping` from the operations team's subnet to the gateway's WAN address.
5. **Rate-limit** the recursive resolver's queries to a sane rate so that DNS tunnelling, if the recursive resolver were itself compromised, is not free.
6. **Log every drop** with a prefix that identifies which rule dropped it (so you can post-mortem the alert stream).

Include comments explaining each rule. Cite the **nftables wiki** as the primary reference.

### Section D — The Suricata signature(s) you would write or enable (a `local.rules` fragment)

At least three signatures: one for each of the three egress channels (HTTPS-C2, DNS-tunnel, ICMP-tunnel). For each:

- Use a `sid` in the 1 000 000–1 999 999 range.
- Include a `msg`, a `classtype`, a `metadata:mitre_technique_id ...`, and an `sid` / `rev`.
- For the HTTPS-C2 signature, key off something that is *not* SNI alone — beaconing-by-volume, JA3 fingerprint, or destination-port-plus-known-bad-IP. Acknowledge in a comment that the signature is partial (no signature catches all HTTPS-C2; this is honest).

Cite the **Suricata documentation** and **ET Open** as references.

### Section E — What the ruleset does *not* catch (100–250 words)

Be honest about the gaps. Examples to consider:

- A more sophisticated attacker who uses an HTTPS destination that *is* on the allowlist (a popular CDN, a SaaS provider).
- A more sophisticated attacker who DNS-tunnels through your own recursive resolver via DoH (DNS over HTTPS) inside a permitted HTTPS connection.
- An attacker with physical access who exfiltrates via USB.

What additional controls — at the endpoint, at the identity layer, at the data-layer — would you propose? Two paragraphs.

### Section F — The runbook entry (50–100 words)

A single short paragraph an on-call engineer could read at 03:00. Inputs: "Suricata signature 1 000 0XX has fired with severity 1, source IP is in `10.0.10.0/24`". Outputs: which segment to move the host to, which channel to escalate, who to call.

---

## Pass criteria

Your write-up is graded on:

- **Specificity.** The nftables ruleset must apply cleanly with `sudo nft -f <your-file>`. Test on a VM before submitting.
- **Honesty.** Section E must name *concrete* gaps; "this rule does not catch everything" is not a gap, "this rule does not catch an attacker who uses Cloudflare as the C2 fronting domain" is.
- **Citation.** Each external reference (nftables wiki, ATT&CK page, Suricata docs, ET Open) must include a URL and be reachable.
- **Authorised-use compliance.** The write-up must include an "Authorisation" header at the top with the line "The implementation in this document was tested in a VM I own; no traffic crossed an unauthorised network."

---

## What "done" looks like

A pull-request to your fork of the curriculum repository, branch `week-10-challenge-01-<your-handle>`, that adds:

```
week-10-network-defense-firewalls-ids-vpn/challenges/submissions/
    <your-handle>/
        challenge-01-write-up.md
        challenge-01-ruleset.nft       (the nft file from Section C)
        challenge-01-local.rules        (the Suricata fragment from Section D)
```

The PR description summarises Section A in one sentence and links to the file.

---

## References

- MITRE ATT&CK — https://attack.mitre.org/
- nftables wiki — https://wiki.nftables.org/
- Suricata documentation — https://docs.suricata.io/
- ET Open — https://rules.emergingthreats.net/open/
- NIST SP 800-41 Rev. 1 — https://doi.org/10.6028/NIST.SP.800-41r1
- Donenfeld 2017 (for the context of a VPN as a complementary control) — https://www.wireguard.com/papers/wireguard.pdf
