# Lecture 2 — Suricata IDS and the Emerging Threats Open Ruleset

> *The firewall decides whether to let a packet through. An IDS — intrusion detection system — decides whether to alert on a packet that the firewall already let through. The two are complementary. Suricata is the free, open-source IDS that, in 2026, is the default choice for greenfield deployments at every scale from a Raspberry Pi to a 100-gigabit hardware appliance.*

---

## 1. What an IDS is and is not

An **intrusion detection system** reads network traffic and matches it against a set of rules called **signatures**. When a packet — or a sequence of packets, in the stateful cases — matches a signature, the IDS emits an **alert**. The alert is a structured record of what fired, on which traffic, against which signature. Alerts are written to a log file (Suricata's `eve.json` is the modern standard) and may be forwarded to a SIEM, a SOC, or a person.

What an IDS *is*:

- A passive observer of network traffic.
- A pattern-matcher with a stateful rule engine.
- A noisy producer of alerts that requires *tuning* before its output is useful.

What an IDS *is not*:

- A firewall — it does not block traffic in its default mode.
- A vulnerability scanner — it does not probe hosts; it reads traffic that is already on the wire.
- An automatic incident-handling system — it produces alerts; a human or a SOAR system handles them.
- A guarantee — a signature-based IDS misses attacks for which no signature exists, and fires false positives on benign traffic that resembles a signature.

The complementary control is an **intrusion prevention system** (IPS), which is the same engine running *inline*: it can drop a packet that matches a signature. IPS mode is more dangerous (a wrong signature breaks legitimate traffic) and is covered in section 9.

---

## 2. Suricata in three sentences

Suricata is a multi-threaded, signature-based, network-intrusion detection and prevention engine, developed since 2009 by the **Open Information Security Foundation** (OISF), distributed under the GPLv2 licence, and packaged in every major Linux distribution. Suricata reads from one or more capture interfaces (`af-packet` on Linux, `pf_ring` on high-throughput deployments, `dpdk` on userspace networking), parses every packet through its protocol decoders, evaluates each packet against its loaded rules, and emits structured logs in `eve.json` plus per-protocol logs (`http.log`, `dns.log`, `tls.log`, etc.). Suricata is a viable alternative to **Snort** (the older OISF-precursor IDS, now Cisco-owned) and to **Zro** / **Bro** (the script-based network-security-monitoring framework, complementary rather than competing).

The website is **https://suricata.io/**. The documentation is **https://docs.suricata.io/**. Read those two before continuing — this lecture is a tour, not a substitute.

---

## 3. The Suricata pipeline

A packet entering the Suricata process flows through this pipeline:

```
[ NIC ]
   |
   v
[ Capture ]   (af-packet / pf_ring / dpdk / nfqueue)
   |
   v
[ Decode ]    (Ethernet -> IP -> TCP/UDP -> HTTP/DNS/TLS/SMB/...)
   |
   v
[ Flow / Stream tracking ]   (assemble TCP streams; track flow timeouts)
   |
   v
[ Detection engine ]   (run rules against packet + flow context)
   |
   v
[ Output ]   (eve.json, fast.log, file extraction, pcap output)
```

Each stage is a separate set of threads. Modern Suricata scales by pinning capture-thread + worker-thread tuples to CPU cores; a quad-core box handles roughly 1 Gbps with the full ET Open ruleset; a 16-core box with multi-queue NICs handles roughly 10 Gbps.

The thread model has one architectural consequence worth knowing: **packets that arrive on the same flow must reach the same worker**, so that stream reassembly and flow state are coherent. This is done by the kernel via Receive Side Scaling (RSS) when capturing with `af-packet`, or by the NIC's flow director when capturing with `dpdk`. The default `af-packet` config in `suricata.yaml` sets `cluster-type: cluster_flow`, which does this for you.

---

## 4. The signature format

A Suricata rule (signature) looks like this:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 ( \
    msg:"SSH connection attempt from external network"; \
    flow:to_server,established; \
    classtype:network-scan; \
    sid:1000001; \
    rev:1; \
)
```

The fields:

- `alert` — the action. `alert` logs an alert; `pass` lets the packet through without further evaluation; `drop` drops the packet (IPS mode only); `reject` sends a reject reply.
- `tcp` — the protocol. Can be `tcp`, `udp`, `icmp`, `ip`, or a Suricata-decoded application-layer protocol like `http`, `dns`, `tls`, `smb`.
- `$EXTERNAL_NET any -> $HOME_NET 22` — the five-tuple matcher. `$EXTERNAL_NET` and `$HOME_NET` are variables defined in `suricata.yaml`; `any` matches any port; `->` is the direction.
- The parenthesised block contains the **rule options**:
  - `msg:"..."` — the human-readable name of the alert.
  - `flow:to_server,established` — the flow state required for the rule to match.
  - `classtype:network-scan` — the rule's classification (used for severity tagging).
  - `sid:1000001` — the signature ID. User rules use 1 000 000–1 999 999. ET Open uses 2 000 000–2 999 999. Sourcefire/Snort VRT uses 1–1 999 999 historically.
  - `rev:1` — the revision. Increment when you edit the rule.

The complete reference is at https://docs.suricata.io/en/latest/rules/intro.html. The most-used additional options:

- `content:"GET /admin"` — match a byte string in the payload.
- `pcre:"/^GET \/admin.*sid=[0-9]+/"` — match a Perl-compatible regular expression.
- `http.uri; content:"/admin"` — match a string in the HTTP request URI (sticky buffer).
- `http.user_agent; content:"sqlmap"; nocase;` — match the HTTP User-Agent header, case-insensitive.
- `tls.cert_subject; content:"badactor"; nocase;` — match a substring in the TLS server certificate subject.
- `dns.query; content:"evil.example."; nocase;` — match a DNS query name.
- `metadata:mitre_technique_id T1059;` — attach an ATT&CK technique to the alert.

---

## 5. The Emerging Threats Open ruleset

Proofpoint distributes a free signature ruleset called **ET Open** at **https://rules.emergingthreats.net/open/**. The bundle is roughly 50 000 signatures organised into the categories named at the start of `resources.md`. The ruleset is updated daily; you pull it with the `suricata-update` tool.

The categories most likely to fire on a small lab network:

- `emerging-scan` — port scanners, fingerprinting tools (Nmap, Nikto, sqlmap).
- `emerging-malware` — known-bad command-and-control signatures.
- `emerging-policy` — policy-violation signatures (BitTorrent, anonymisers, suspicious DNS).
- `emerging-info` — informational, low-severity (mostly noise; consider disabling).
- `emerging-current_events` — high-profile newly-disclosed threats (the Log4Shell signature lives here).

The categories that produce more noise than signal on a typical lab:

- `emerging-chat` — IM-protocol fingerprints, mostly obsolete.
- `emerging-games` — game-protocol fingerprints, irrelevant unless you run game servers.
- `emerging-inappropriate` — pornography / gambling URL signatures, irrelevant outside enterprise content filtering.

A starter configuration disables those three by editing `disable.conf`:

```
# /etc/suricata/disable.conf
group:emerging-chat.rules
group:emerging-games.rules
group:emerging-inappropriate.rules
```

After editing, run `sudo suricata-update` and the disabled groups are dropped from the merged ruleset.

The licence on ET Open is BSD-2-Clause; you may redistribute it, study it, and use it commercially without restriction. The paid **ET Pro** ruleset adds rules tied to active commercial threat intelligence; ET Open is more than sufficient for a hobbyist lab and for many small businesses.

---

## 6. The minimal Suricata deployment

The fastest path from `apt install suricata` to a working IDS:

```bash
# Install.
sudo apt install suricata suricata-update

# Pull the ET Open ruleset.
sudo suricata-update

# Tell Suricata which interface to listen on. Edit /etc/suricata/suricata.yaml:
# - find the af-packet section
# - set the interface to your monitoring NIC
# - if monitoring a span port, set 'threads: <cores>' and 'cluster-id: 99'

# Start Suricata.
sudo systemctl enable --now suricata

# Tail the alerts.
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

Within five minutes of starting Suricata on a live internet-connected interface, you will see alerts. Most will be scan-attempts from ambient internet noise. That is normal.

The next step, which Day 2's exercises spend most of their time on, is **tuning**: making the alert stream useful rather than overwhelming.

---

## 7. Output: `eve.json`

Suricata's modern output format is **`eve.json`** — Extensible Event Format. One JSON object per line, one line per event. Events are not just alerts: protocol-parsed records (HTTP transactions, DNS queries, TLS handshakes, SMTP sessions, SMB operations, SSH banners) are also emitted, which means `eve.json` is by itself a fair-quality network-security-monitoring dataset.

A typical alert record:

```json
{
  "timestamp": "2026-05-14T18:23:14.451239+0000",
  "flow_id": 1234567890123456,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "203.0.113.45",
  "src_port": 51230,
  "dest_ip": "192.0.2.10",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2030013,
    "rev": 4,
    "signature": "ET SCAN Nmap NSE Heartbleed Response",
    "category": "Attempted Information Leak",
    "severity": 2,
    "metadata": {
      "affected_product": ["Linux", "BSD"],
      "deployment": ["Datacenter"],
      "mitre_tactic_id": ["TA0007"],
      "mitre_technique_id": ["T1046"]
    }
  },
  "flow": {
    "pkts_toserver": 1,
    "pkts_toclient": 0,
    "bytes_toserver": 60,
    "bytes_toclient": 0
  }
}
```

The fields are stable across Suricata versions; `jq` is the canonical tool for slicing them at the shell:

```bash
# Top 10 alert signatures by frequency in the last hour.
sudo tail -n 100000 /var/log/suricata/eve.json \
  | jq -r 'select(.event_type=="alert") | .alert.signature' \
  | sort | uniq -c | sort -rn | head -10

# All alerts touching a specific source IP.
sudo grep -F '"src_ip":"203.0.113.45"' /var/log/suricata/eve.json \
  | jq 'select(.event_type=="alert")'
```

Exercise 4 builds a small Python triage script around `eve.json`.

---

## 8. Tuning — the work that turns Suricata from noise into signal

A freshly-deployed Suricata with the full ET Open ruleset, sitting on a typical home network, will produce somewhere between 50 and 5 000 alerts per day depending on traffic volume. Most of those alerts are noise: vulnerable-product signatures that do not match any product on your network, scanner signatures that fire on every ambient internet probe, policy-violation signatures that fire on your own legitimate traffic.

The discipline of *tuning* is the work of reducing that noise to a level a single operator can triage.

### 8.1 Disable categories that do not match your threat model

The starter configuration in section 5 disables the chat, games, and inappropriate categories. Extend it for your environment:

- No SCADA equipment? Disable `emerging-scada.rules`.
- No VoIP? Disable `emerging-voip.rules`.
- No SMTP server? Disable `emerging-smtp.rules`.
- No FTP server? Disable `emerging-ftp.rules`.

### 8.2 Suppress individual noisy signatures

Some signatures fire constantly on benign traffic. Suppress them in `/etc/suricata/threshold.config`:

```
# Suppress the "DNS query for outdated TLS root certificate domain" rule
# for our resolver. Format: suppress, gen_id, sig_id, [track by_src|by_dst, IP|net]
suppress gen_id 1, sig_id 2027865

# Or suppress only when the source is our resolver.
suppress gen_id 1, sig_id 2027865, track by_src, ip 10.0.0.53
```

The first form silences the signature entirely; the second silences it only for the specified track + address.

### 8.3 Threshold (rate-limit) loud signatures

Some signatures are useful in aggregate but spam the log in detail. Threshold them:

```
# Rate-limit signature 2027865 to one alert per minute per destination.
event_filter gen_id 1, sig_id 2027865, type both, track by_dst, count 1, seconds 60
```

Suricata's `event_filter` types: `limit` (silence after N), `threshold` (only after N), `both` (combination — first one in a window, then silence for the rest of the window).

### 8.4 Write local rules for your high-value flows

`/etc/suricata/rules/local.rules` is where your custom signatures live. A small lab example: alert on any inbound HTTP request to `/admin` that does not originate from the management subnet:

```
alert http any any -> $HOME_NET any ( \
    msg:"Local: external access to /admin"; \
    flow:to_server,established; \
    http.uri; content:"/admin"; startswith; \
    classtype:policy-violation; \
    sid:1000010; \
    rev:1; \
)
```

Combined with a suppression on the legitimate management subnet:

```
suppress gen_id 1, sig_id 1000010, track by_src, ip 10.0.10.0/24
```

You now alert on the case that matters and silence the case that does not.

### 8.5 Iterate weekly

Tuning is a recurring activity, not a one-time setup. Every Monday morning: pull the prior week's top-10 noisy signatures, decide for each whether to suppress, threshold, or keep. After three months of weekly iteration, the alert stream stabilises at a few alerts per day, every one of which deserves human attention. Exercise 4 walks the first iteration of this loop.

---

## 9. IDS mode vs. IPS mode

So far this lecture has assumed **IDS mode**: Suricata observes, alerts, does not block. The complementary mode is **IPS mode**: Suricata sits inline, can drop a packet that matches a signature.

### IDS mode

```
[ NIC ] -- (span/mirror or tap) --> [ Suricata ]   alerts only
```

### IPS mode (af-packet inline)

```
+----------+              +-----------+              +----------+
|  iface A | ---packet--> | Suricata  | ---packet--> | iface B  |
+----------+              +-----------+              +----------+
```

### IPS mode (NFQUEUE)

```
[ packet ] -> [ nftables NFQUEUE verdict ] -> [ Suricata userspace ] -> verdict
```

The trade-off:

- **IDS mode** is safe. A misfired rule produces a noisy alert. The traffic continues to flow.
- **IPS mode** is risky. A misfired rule drops legitimate traffic. A Suricata crash takes the network down (if Suricata is in the data path).

The recommendation for this course: **stay in IDS mode**. The mini-project's reference architecture places Suricata on a span port off the gateway switch, where it cannot affect production traffic. Once you have run an IDS for six months and your false-positive rate is genuinely zero, you can graduate to IPS mode on specific high-confidence signatures — but the operator skill for that graduation is real, and the cost of a mistake is the same as a misconfigured firewall.

The Suricata documentation has a dedicated "IPS Deployment" chapter that covers both `af-packet` inline mode and `nfqueue` mode; it is the canonical reference when you do graduate.

---

## 10. Sensor placement

Where you put the sensor matters more than how you tune it.

**Option A: Span / mirror port off the gateway switch.**

Most consumer-grade switches do not support port mirroring; most prosumer switches (Ubiquiti EdgeSwitch, Mikrotik, TP-Link "Easy Smart") do. Configure the switch to mirror the port carrying internet traffic to a dedicated monitoring port; plug the sensor's NIC into that port. The sensor sees every packet between the internet and the LAN; it cannot affect traffic.

**Option B: TAP device.**

A network tap is a small hardware device that sits between two cables and forwards every packet to a monitoring port. Passive taps are physically incapable of affecting traffic; they are the right answer when paranoia is justified. A simple passive tap costs roughly $100 in 2026; the Dualcomm ETAP-2003 is the canonical hobbyist model.

**Option C: On the gateway itself.**

If the gateway is a Linux box you run, Suricata can capture directly off the WAN-facing interface. The trade-off is that the sensor competes with the gateway for CPU; on a Raspberry Pi 5 with a 1 Gbps link this is fine for most home networks, but a small NUC with a 10 Gbps link saturates more easily.

**Option D: In-host on each server.**

Suricata can also run on each server, watching that host's own traffic. This is the *host-based IDS* pattern; it captures traffic that a network-edge sensor cannot see (encrypted lateral traffic that terminates on the same host). It is the more enterprise-y pattern and is owed to a later course.

For the mini-project, options A and C are the realistic ones for a small lab. The starter blueprint includes both.

---

## 11. Storage

`eve.json` grows fast. A busy network can produce hundreds of MB to several GB per day. Plan for storage.

The canonical pattern: rotate `eve.json` daily, compress the rotated files, retain compressed files for 30 days, and forward the live `eve.json` to a longer-term store (a SIEM, OpenSearch / Elasticsearch, or even just a remote log host).

`/etc/logrotate.d/suricata` ships a sane default with the Debian package; review it and adjust the retention to match your storage.

If you also enable per-protocol logs (`http.log`, `dns.log`, etc.) the storage grows further. The mini-project's reference config disables those per-protocol logs and relies on `eve.json` alone, which is the modern recommendation.

---

## 12. The companion tools

A short tour of tools that show up around Suricata.

- **suricata-update.** The ruleset manager. Pulls ET Open and any other configured sources; merges them; applies `disable.conf` / `enable.conf` / `modify.conf` / `drop.conf`; writes a single merged rule file that Suricata loads. Run it on a cron — daily is the recommendation.

- **EveBox.** A web UI that reads `eve.json` and gives a queryable view of alerts. Free under MIT licence; runs as a small Go binary. Useful for visual triage; not required.

- **Scirius.** A heavier web UI from the Stamus Networks people that integrates with Splunk / Elasticsearch / OpenSearch. The free Community Edition is at https://github.com/StamusNetworks/scirius.

- **OPNsense / pfSense.** Firewall distros that bundle Suricata as a package. If you already run one of these as a gateway, the IDS is one checkbox away. Worth knowing about; not the path this course takes (we run the components separately so each one is comprehensible in isolation).

- **Zeek (formerly Bro).** A network-security-monitoring framework that is *complementary* to Suricata. Zeek does not have signatures; it parses traffic into deeply-structured logs and runs operator-written scripts against those logs. Many serious shops run Zeek and Suricata side by side. Worth knowing about; out of scope for this course.

---

## 13. Building a useful starter `suricata.yaml`

`suricata.yaml` is roughly 1 500 lines in a default install. Ninety percent of it can stay at defaults. The fields you have to set or review:

```yaml
# Vars used by signatures to mean "my network" and "the internet".
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"

# Where to listen.
af-packet:
  - interface: eth1            # your monitoring interface
    threads: 2
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

# Output.
outputs:
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - flow

# Rules.
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules           # the merged file written by suricata-update
  - /etc/suricata/rules/local.rules
```

Exercise 4 ships an annotated starter `suricata.yaml`.

---

## 14. Verifying a deployment works

After the install + configure + start sequence, run these sanity checks:

```bash
# 1. Suricata is running and not failing.
sudo systemctl status suricata

# 2. The rules loaded.
sudo grep -c '^[^#]' /var/lib/suricata/rules/suricata.rules
# Expect: thousands.

# 3. eve.json is being written.
sudo tail -f /var/log/suricata/eve.json | head -5
# Expect: JSON records, even if not yet of type "alert".

# 4. Fire a test alert. Suricata ships a curl-and-it-alerts test signature:
# search for "2100498" in the rules — "GPL ATTACK_RESPONSE id check returned root"
# fires on the literal string "uid=0(root)" in HTTP response.
# In a test against a non-production server you control:
sudo nc -l -p 8080 &
echo -e "HTTP/1.1 200 OK\r\n\r\nuid=0(root)" | nc target.example 8080
# Expect: an alert in eve.json within seconds.
```

If step 4 fires, the pipeline works end-to-end: capture, parse, match, output. The next iteration of work is tuning, not deployment.

---

## 15. A note on encrypted traffic

Modern internet traffic is overwhelmingly TLS-encrypted, which means Suricata cannot read the payload. What Suricata *can* still inspect on a TLS flow:

- TCP SYN/SYN-ACK timing and source/destination ports (flow-level signatures).
- TLS handshake: server name indication (SNI), certificate subject, certificate fingerprint, JA3/JA3S fingerprints of the client and server TLS stacks.
- TLS-version downgrades (alertable).
- Suspicious certificate properties (self-signed, recently-issued, known-malicious thumbprint).

ET Open has thousands of signatures targeting the TLS handshake and JA3/JA3S fingerprints. A surprisingly large fraction of malware command-and-control is identifiable by JA3 alone; the canonical reference is the Salesforce JA3 project (https://github.com/salesforce/ja3).

The trade-off is real: an attacker who uses HTTPS with a benign-looking JA3 to a benign-looking domain (a CDN, a cloud provider) will not trip most ET Open signatures. The mitigation, at the IDS layer alone, is incomplete. The complementary controls are egress filtering (Lecture 1) and endpoint visibility (a future course).

---

## 16. The honest performance budget

A Raspberry Pi 5 with a 1 GbE NIC runs Suricata + the full ET Open ruleset at about 600 Mbps before packet drops. A 4-core Intel NUC with a 2.5 GbE NIC handles a saturated 2.5 Gbps link. A 16-core server with a 25 GbE NIC handles a fully-loaded 10 Gbps with capacity to spare.

The single biggest source of dropped packets in a Suricata deployment is **CPU pinning** — failing to assign Suricata's worker threads to dedicated CPU cores. The single biggest source of *false positives* is **leaving the full ET Open ruleset enabled without tuning**. The single biggest source of *missed detections* is **not refreshing the ruleset**: signatures for last week's malware do not catch this week's, and `suricata-update` has to run on a cron.

For the mini-project's small-lab scope, none of those pitfalls is hard to avoid. The defaults work for most home network throughputs.

---

## 17. Summary

- An **IDS** detects; an **IPS** prevents. Suricata can do both; this course runs it in IDS mode.
- **Suricata** is multi-threaded, signature-based, free, GPLv2, well-maintained, the default greenfield choice in 2026.
- **ET Open** is a free signature ruleset under the BSD licence, updated daily, sufficient for hobbyist and small-business deployments.
- **`eve.json`** is the modern output: one JSON record per event, queryable with `jq`.
- **Tuning** is the difference between a noisy alert stream and a useful one. Disable irrelevant categories, suppress signatures that fire on benign traffic, threshold loud signatures, write local rules for your highest-value flows, iterate weekly.
- **Sensor placement** matters more than tuning. Span ports, taps, on-gateway, on-host — each has trade-offs.
- **Encrypted traffic** is mostly opaque; the IDS sees the TLS handshake metadata and the flow timings, not the payload.

Next: Lecture 3 on WireGuard and segmentation. The firewall and the IDS together describe the inside of the network. WireGuard describes how authorised users *get* inside.

---

## References cited inline

- Open Information Security Foundation. *Suricata User Guide* version 7.0. https://docs.suricata.io/
- OISF. *Suricata source code.* https://github.com/OISF/suricata
- Proofpoint. *Emerging Threats Open Ruleset.* https://rules.emergingthreats.net/open/
- Suricata-update tool. https://suricata-update.readthedocs.io/
- Salesforce. *JA3/JA3S fingerprinting.* https://github.com/salesforce/ja3
- Stamus Networks. *Scirius community.* https://github.com/StamusNetworks/scirius
