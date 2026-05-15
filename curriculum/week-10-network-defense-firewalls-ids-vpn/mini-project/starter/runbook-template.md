# Runbook — TEMPLATE

> Three operational procedures, one paragraph each. Written so an on-call engineer can read at 03:00 and execute without scrolling through the full plan. Replace the placeholders with the values for your network.

---

## Runbook 1 — Add a new VPN client

**When to run:** A new authorised user needs remote access. Authorisation has already been signed (engagement letter, employer authorisation, family-member-on-shared-home-network agreement — whatever applies to your context).

**Procedure:**

1. On a host you trust, run the keygen script:
   ```bash
   python3 exercises/exercise-05-wireguard-keygen.py "<peer-name>" \
       --output-dir ~/wg/peers \
       --client-address 10.10.0.<next-free>/32 \
       --server-endpoint vpn.example.com:51820 \
       --server-public-key <SERVER-PUBLIC-KEY> \
       --full-tunnel
   ```
   The script prints a `[Peer]` block (for the server) and a `wg0.conf` (for the client device).
2. Copy the printed `[Peer]` block; append it to `/etc/wireguard/wg0.conf` on the gateway. Update the *added on* comment with today's date.
3. Atomic reload on the gateway:
   ```bash
   sudo wg syncconf wg0 <(wg-quick strip wg0)
   ```
4. Deliver the printed `wg0.conf` to the peer's device. For laptops, USB drive or signal-message. For phones, generate a QR code:
   ```bash
   qrencode -t ansiutf8 < ~/wg/peers/<peer-name>.client.conf
   ```
   Scan with the WireGuard mobile app.
5. On the client device, `sudo wg-quick up wg0` (or "Activate" in the mobile app).
6. Verify on the gateway: `sudo wg show` shows a recent handshake for the new peer.
7. Append a row to `key-inventory.md` with the peer name, device, public key, today's date, and the segment the peer routes to.
8. Append a row to the changes-log in `topology.md`.

**Rollback if something fails:** remove the `[Peer]` block from the server, run `sudo wg syncconf wg0 <(wg-quick strip wg0)` again. The peer's public key is now useless against the network.

---

## Runbook 2 — Triage a Suricata alert (severity 1 or 2)

**When to run:** Suricata writes an `alert` record with `severity: 1` or `severity: 2` to `/var/log/suricata/eve.json`. The on-call alerting (your phone, your SIEM, your e-mail filter) has paged you.

**Procedure:**

1. Pull the alert's full context. From the gateway:
   ```bash
   sudo grep -F '"signature_id":<SID>' /var/log/suricata/eve.json \
       | tail -20 \
       | jq 'select(.event_type=="alert")'
   ```
   Note: `src_ip`, `dest_ip`, `dest_port`, `alert.signature`, `alert.metadata`.
2. Identify the **direction**: is `src_ip` in `$HOME_NET`?
   - **Yes** — likely an internal host doing something suspicious. Worry more.
   - **No** — likely ambient external probing. Worry less.
3. Identify the **affected host** on your network. Match its IP to an entry in `topology.md` host-inventory.
4. Look up the signature on the ET Open site:
   ```
   https://rules.emergingthreats.net/open/suricata-7.0.0/rules/emerging-<category>.rules
   ```
   The `msg` and `metadata.mitre_technique_id` fields tell you what the rule thinks it found.
5. Decide:
   - If the alert is **plausible signal** (e.g., a known malware C2 signature firing on a workstation), execute Runbook 3 below to contain.
   - If the alert is **noise** (the source IP is your own pentesting box; the destination IP is a benign service the rule misfires on), add the SID to `threshold.config` and run `sudo systemctl restart suricata`.
6. Append a one-line entry to your operations log (an append-only file in this repository's `evidence/` directory works) with the alert ID, your decision, and the time.

**Escalate when:**

- The alert is a plausible signal *and* you cannot reach the affected host's owner within 15 minutes.
- The alert's `metadata.mitre_technique_id` is in the **Command and Control** tactic — those are urgent.
- The same SID fires five or more times in an hour with different `src_ip` values, suggesting a real campaign.

---

## Runbook 3 — Contain a compromised host

**When to run:** Runbook 2 told you the alert is plausible signal *and* the affected host appears to be actively compromised.

**Procedure:**

1. **Do not unplug the host.** Memory contents are evidence (see Week 9 — order of volatility). Containment by network is preferred.
2. **Move the host to a quarantine segment.** Add a temporary nftables rule on the gateway that drops all traffic to and from the affected host *except* a single SSH path from an investigator workstation:
   ```bash
   sudo nft add rule inet filter forward ip saddr <affected-ip> ip daddr != <investigator-ip> drop
   sudo nft add rule inet filter forward ip daddr <affected-ip> ip saddr != <investigator-ip> drop
   ```
3. **Page the host's owner.** Communicate by a channel that does *not* depend on the host — text, phone, in-person. Do not use the host's own e-mail, chat, or any service it might be logging.
4. **Run the Week-9 incident-response procedures.** Memory acquisition (LiME/AVML), log triage, timeline reconstruction. See `../C6-CYBERSECURITY-CRUNCH/curriculum/week-09-incident-response-and-log-forensics/` if you have that course's notes; otherwise see the W9 references in `resources.md`.
5. **Update the changes-log in `topology.md`** with the temporary containment rule.
6. **Remove the containment rules** after the host is rebuilt or proven clean. Append the removal to the changes-log.

**Authorisation note:** containing a compromised host on your own network is within authorisation. Containing a host on a network you do not own — even a compromised one — is not. If the affected host is "not really yours" (a roommate's laptop, a guest's phone), the right move is communication, not unilateral action.

---

## A note on the runbook's scope

These three runbooks cover the most-common 80% of operational actions on this network. The 20% they do not cover — kernel upgrades, certificate rotation, ISP outages, hardware failure — belong in their own runbooks in the same file as you write them. Treat the runbook collection as the operational equivalent of the post-incident report from Week 9: an artefact that survives the day it was written and helps the next person on call.
