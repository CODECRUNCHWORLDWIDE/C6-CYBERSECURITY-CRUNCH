# Week 10 — Network Defence: Firewalls, IDS, and VPN

> *Week 9 reconstructed an intrusion after it happened. Week 10 raises the cost of the next one. The deliverable this week is a defensible small-environment network: a stateful firewall built with **nftables** that enforces a default-deny posture, a free open-source intrusion-detection sensor (**Suricata**) running the **Emerging Threats Open** ruleset, and a **WireGuard** VPN that replaces ad-hoc SSH-over-port-forward exposure with a single cryptographic tunnel. The mini-project is a home or office network plan — diagrams, ruleset, sensor placement, VPN keys, segmentation rationale — written so an auditor or a peer would believe it.*

Welcome to Week 10 of **C6 · Cybersecurity Crunch**. The first nine weeks built the skills of an individual responder: secure code, threat models, scans, exploit-and-patch, incident response. Week 10 is the first week that asks you to *design* a defended environment rather than react to one. The audience for the deliverable is not your future self with a shell on a single host; it is a colleague who needs to onboard, an auditor who needs to sign off, and a future-you who has forgotten which interface the egress filter sits on. The currency this week is therefore *plans and rules and diagrams* — the artefacts that survive the day you wrote them.

```
+---------------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                                |
|                                                                     |
|  Every command, rule file, packet capture, and Suricata signature   |
|  in this module is run against:                                     |
|                                                                     |
|  - a small lab network you personally own and administer            |
|    (your own home network, your own VMs, your own Raspberry Pi),    |
|    OR                                                               |
|  - a network on which you hold a current, written, signed           |
|    authorisation from the network's owner (employer's network-team  |
|    standing authorisation, a customer engagement letter, a school   |
|    IT department's signed authorisation, or equivalent).            |
|                                                                     |
|  Deploying an IDS sensor on a network you do not own and are not    |
|  authorised to monitor is, in the United States, a violation of     |
|  both the Wiretap Act (18 U.S.C. § 2511) and, depending on the      |
|  state, the Stored Communications Act (18 U.S.C. § 2701). In        |
|  Florida, two-party consent for interception applies (Fla. Stat.    |
|  § 934.03). In the United Kingdom the Investigatory Powers Act      |
|  2016 governs. In the European Union the GDPR plus each member      |
|  state's surveillance laws apply. Suricata reads every packet on    |
|  its monitoring interface; treating that interface as if it were    |
|  off-the-shelf hardware on a network you do not own is the same     |
|  category of mistake as running tcpdump on a coffee-shop Wi-Fi      |
|  uplink. The penalties are real.                                    |
|                                                                     |
|  Firewall rules are less invasive — they affect only your own       |
|  host or your own gateway — but a misconfigured ruleset can still   |
|  lock you out of a remote host or deny service to other users of    |
|  a shared network. Test every ruleset on a host you can recover     |
|  physically before pushing it to one you cannot.                    |
|                                                                     |
|  VPN deployment requires explicit authorisation from anyone whose   |
|  device will connect through the tunnel and anyone whose network    |
|  the tunnel will egress onto. A WireGuard server placed on an       |
|  employer's network without the network team's written sign-off     |
|  is a textbook insider-threat artefact and grounds for termination  |
|  at any organisation with an acceptable-use policy.                 |
|                                                                     |
|  If you cannot point at a document or an ownership claim that       |
|  authorises the deployment, you do not deploy. The same rule that   |
|  governed every previous week of C6 governs this one.               |
+---------------------------------------------------------------------+
```

Read the banner once carefully now; thereafter treat it as a contract. The mini-project explicitly scopes a *home or office network you own*. If the network you have in mind is a dormitory, a shared apartment, a co-working space, or any network you do not personally own, the deliverable is still valid — but the implementation portion stays in a VM lab on your laptop, and you write the plan as if the deployment were authorised. The grade is on the plan and the rule artefacts, not on whether bits ever crossed a wire you did not own.

---

## Learning objectives

By the end of this week, you will be able to:

- **Explain** what a **stateful firewall** is and why every modern host firewall is stateful: the connection-tracking table (`conntrack` in the Linux kernel) records the five-tuple of every flow it has seen, so the firewall can accept the *reply* to a connection without an explicit rule for the reply direction. Contrast with a *stateless* packet filter, which has to permit both directions independently and therefore admits a much larger attack surface.
- **Write** a complete **nftables** ruleset for a Linux host or a Linux gateway from scratch. Use the modern nftables syntax (the `nft` command, atomic ruleset reloads, named sets, verdict maps, the `inet` family for dual-stack IPv4/IPv6), not the legacy `iptables` command. Apply a **default-deny** posture on `input` and `forward` chains and a **default-accept** posture on `output` for a workstation (versus default-deny on `output` for a tightly-scoped server). Cite the nftables wiki as the canonical reference.
- **Distinguish** **ingress filtering** (what enters the network from the outside) from **egress filtering** (what leaves the network from the inside). Articulate why egress filtering is the single highest-leverage control against modern attacker tradecraft: command-and-control channels, exfiltration over HTTPS, DNS tunnelling. Configure egress filters that allow only the protocols and destinations the host actually needs.
- **Rate-limit** abusive flows with nftables `limit` expressions and the `meter` keyword. Build a rule that drops SSH connection attempts above five per minute per source address. Build a rule that limits inbound ICMP echo-requests to a sane background rate. Understand why rate-limiting is a partial mitigation, not a defence — a sufficiently distributed attacker bypasses any per-source limit.
- **Deploy** a free open-source **Suricata** intrusion-detection sensor on a Raspberry Pi, a small x86 box, or a VM. Configure Suricata in **IDS mode** (passive, off a span/mirror port or a `tap` interface) for a starter deployment; understand the trade-offs of **IPS mode** (inline, can drop packets, can also break the network when a signature is wrong). Run the **Emerging Threats Open** ruleset, which Proofpoint distributes free of charge under the BSD licence; understand what the **paid ET Pro** ruleset adds and why a hobbyist lab does not need it.
- **Tune** Suricata signatures to reduce false-positive noise to a level a single operator can triage. Suppress signatures that fire on benign traffic specific to your environment (suppression rules in `threshold.config`). Disable categories that do not match your threat model (e.g., emerging-game-server signatures on a network with no game servers). Promote signatures that match your highest-value assets. Cite the Suricata documentation as the canonical reference.
- **Build** a **WireGuard** VPN that admits authorised devices to your home or lab network. Generate keypairs (`wg genkey | tee privatekey | wg pubkey > publickey`), write a server config that listens on UDP/51820 and routes a `10.10.0.0/24` overlay, write per-peer client configs for a phone, a laptop, and a remote workstation, and verify the tunnel with `wg show` and `ping`. Cite Donenfeld's 2017 WireGuard whitepaper as the canonical reference.
- **Compare** **WireGuard** with the legacy alternatives — **OpenVPN** (TLS-based, decade-old, mature, slow, complex configuration) and **IPsec/IKEv2** (RFC-standard, performant, baroque configuration, kernel-level on modern Linux) — and articulate why WireGuard has displaced both in greenfield deployments since roughly 2020: 4 000 lines of kernel code vs. hundreds of thousands, no negotiated cipher suites (one fixed modern set), keys-as-identity instead of certificates-and-PKI, sub-second roaming between networks.
- **Design** a **segmented network** for a small environment. Place untrusted devices (guest Wi-Fi, IoT, the smart TV that phones home to its vendor) on an isolated VLAN that cannot reach trusted devices. Place servers that receive inbound traffic in a **DMZ** that cannot initiate outbound traffic to the trusted segment. Use a **jump host** (also called a *bastion*) as the single authorised entry point for administrative SSH from the VPN segment; deny direct SSH from the VPN segment to other hosts. Acknowledge the conceptual successor model, **zero trust**, in which the segment boundary is replaced by per-flow authentication.
- **Document** a network the way an auditor would expect: a topology diagram (ASCII or PNG), an interface inventory, an addressing plan, the full firewall ruleset committed to version control, the IDS sensor's `suricata.yaml` and `local.rules` committed alongside, the WireGuard keys stored *off* the repository with the public keys committed, a list of allowed inbound and outbound flows with their business justification, and a runbook for the three operations that happen most often (add a VPN client, add an open port, investigate a Suricata alert).

---

## Prerequisites

- **Weeks 1 through 9 completed.** Week 2 covered the networking primitives this week applies — IP, TCP, UDP, the kernel's view of an interface — and Week 9's log-forensics discipline carries over directly: every artefact this week (rule files, sensor configs, key inventories) is treated as something an auditor will read.
- **A Linux host where you have root, plus at least one additional host on the same network.** The exercises run against a Linux host (Ubuntu 24.04 LTS, Debian 12, Fedora 40, or equivalent). The mini-project benefits from a second host — a Raspberry Pi 4 or 5, a small x86 mini-PC, or a second VM — to act as the IDS sensor. If you only have one machine, run everything in nested VMs (VirtualBox, VMware, UTM on Apple Silicon, libvirt/KVM on Linux).
- **Python 3.11 or later.** Verify with `python3 --version`. The non-shell exercises and the report-generator script for the mini-project are Python. Type hints throughout.
- **The standard network-engineering toolkit on the path.** `ip` (from `iproute2`; the modern replacement for `ifconfig` and `route`), `ss` (the modern replacement for `netstat`), `tcpdump`, `nft` (the nftables command-line front-end), `wg` (the WireGuard userspace tool), `systemctl`, `journalctl`.
- **`nftables` installed.** On Debian/Ubuntu: `sudo apt install nftables`. On Fedora: `sudo dnf install nftables`. On Arch: `sudo pacman -S nftables`. Verify with `nft --version`; expect 1.0.x or newer.
- **`suricata` installed (for Day 2 and the mini-project).** On Debian/Ubuntu: `sudo apt install suricata`. The Suricata project distributes a PPA with newer releases (`ppa:oisf/suricata-stable`); the distro package is sufficient for this week. Verify with `suricata --build-info`. Suricata 7.0 LTS is the assumed version.
- **`wireguard` installed.** On Debian/Ubuntu: `sudo apt install wireguard`. The userspace tools (`wireguard-tools`) include `wg` and `wg-quick`. On modern kernels (5.6+) the WireGuard module is in-tree and requires no DKMS. Verify with `wg --version`.
- **Comfort with the assumption that you will lock yourself out at least once this week.** Every network engineer has locked themselves out of a remote host with a misconfigured firewall rule. Test rulesets on hosts you can physically recover. The exercises walk you through the canonical recovery pattern: schedule a rule-reset with `at` *before* applying the new ruleset, so that ten minutes later the host reverts to the old config if you did not log back in to cancel it.
- **A network you own, or a willingness to confine the lab to VMs on your laptop.** Re-read the banner.

---

## Topics covered

- **Stateful packet inspection.** The Linux kernel's `conntrack` subsystem maintains a table of every flow it has tracked, keyed on the five-tuple (source IP, destination IP, source port, destination port, protocol). Connection states (`NEW`, `ESTABLISHED`, `RELATED`, `INVALID`). The canonical rule pattern `ct state established,related accept` and why it sits at the top of every modern input chain. The cost: connection-table memory and CPU. The tuning knobs: `nf_conntrack_max`, `nf_conntrack_tcp_timeout_*`.
- **nftables vs. iptables.** Why nftables exists (single command for IPv4 and IPv6, atomic ruleset reloads, named sets, verdict maps, JSON output, a smaller kernel surface). Why iptables is still on every host (legacy, muscle memory, third-party tools that emit iptables rules — Docker, Kubernetes, fail2ban historically). The translation: `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` becomes `add rule inet filter input tcp dport 22 accept`. The nftables wiki at https://wiki.nftables.org is the canonical free reference.
- **Default-deny posture.** Workstation-style: `input` default-deny, `output` default-accept, `forward` default-deny. Server-style: `input` default-deny with a small list of accepted services, `output` default-deny with an explicit allowlist of egress destinations (NTP, DNS, package mirrors, monitoring endpoints), `forward` default-deny unless the box is a router. The argument for tight egress: every modern intrusion's value to the attacker depends on egress; deny it and you neuter the kill chain.
- **Rate-limiting with nftables.** The `limit` keyword (`limit rate 10/second burst 5 packets`). The `meter` keyword for per-source tracking. SSH brute-force mitigation with a stateful rule. The honest caveat: rate-limiting hardens an asset against opportunistic noise; a determined attacker uses a botnet and bypasses any per-source limit.
- **Ingress vs. egress filtering.** Ingress: what you let *in* from the outside; the traditional firewall metaphor. Egress: what you let *out* from the inside; the lever that constrains an attacker who already has a foothold. The argument for default-deny egress on servers and the practical pattern (named sets for allowed destinations, periodic audit of the set).
- **Suricata in IDS mode.** Passive monitoring on a span/mirror port or a SmartNIC `tap`. The `af-packet` capture path. The `eve.json` log format. The `fast.log` legacy format and why most people skip it. Performance: a single core handles roughly 1 Gbps with the ET Open ruleset; multi-queue NICs and `cpu-affinity` configuration scale to ~10 Gbps on commodity hardware.
- **Suricata in IPS mode.** Inline deployment with `nfqueue` (Linux NFQUEUE) or `af-packet` in `af-packet-ips` mode. The cost: a Suricata crash takes the network down; signature false-positives drop legitimate traffic. The hobbyist-lab recommendation: stay in IDS mode for Week 10. Cite the Suricata documentation's IDS-vs-IPS comparison.
- **Emerging Threats Open ruleset.** Proofpoint (formerly Emerging Threats LLC, acquired in 2015) distributes the ET Open ruleset free under the BSD licence at https://rules.emergingthreats.net/open/. The ruleset is updated daily. Pull with `suricata-update` (the official manager) or by hand with `curl`. The categories: `emerging-malware`, `emerging-trojan`, `emerging-exploit`, `emerging-policy`, `emerging-scan`, `emerging-shellcode`, and roughly twenty more. Disable the categories that do not match your threat model.
- **Suricata tuning.** Suppression rules in `threshold.config`. The `flowbits` system for stateful signatures that depend on a prior event. The `metadata` field for tagging rules with severity, MITRE ATT&CK technique, or affected product. Custom rules in `local.rules`. The `signature_id` (`sid`) numbering convention: user rules use the 1 000 000–1 999 999 range.
- **WireGuard fundamentals.** Donenfeld's 2017 whitepaper (https://www.wireguard.com/papers/wireguard.pdf) describes the protocol; it is short (12 pages) and is required reading this week. The protocol uses **Curve25519** for ECDH, **ChaCha20-Poly1305** for AEAD, **BLAKE2s** for hashing, **SipHash24** for key indexing, and the **Noise** framework's IK handshake pattern. Keys are 32 bytes, encoded base64 for human handling. No certificates, no PKI.
- **WireGuard server configuration.** `[Interface]` block with `Address`, `ListenPort`, `PrivateKey`. `[Peer]` blocks with `PublicKey`, `AllowedIPs`. The `wg-quick` helper, which wraps `ip link`, `ip addr`, and `ip route` into a single `wg-quick up wg0` invocation. Persistence with `systemctl enable wg-quick@wg0`.
- **WireGuard client configuration.** Same structure, mirrored. `AllowedIPs = 0.0.0.0/0, ::/0` for a full-tunnel client. `AllowedIPs = 10.10.0.0/24` for a split-tunnel client that only reaches the lab subnet. The `PersistentKeepalive = 25` setting for clients behind NAT.
- **WireGuard vs. OpenVPN vs. IPsec.** OpenVPN: TLS-based; runs over UDP/443 or TCP/443; about 100 000 lines of OpenSSL plus 60 000 of OpenVPN itself; slow on commodity CPUs because every packet round-trips userspace. IPsec/IKEv2: kernel-resident; performant; standardised; configuration involves two daemons (`strongswan`, `racoon`, or `libreswan`), three or four config files, and a willingness to read RFC 4301. WireGuard: kernel-resident; ~4 000 lines of kernel code; one config file; faster than both alternatives on every benchmark Donenfeld published in 2017 and in every independent benchmark since.
- **Network segmentation.** **DMZ** (Demilitarised Zone) for externally-reachable servers — they sit on their own segment with a firewall between them and the trusted segment. **Jump host** / **bastion** — a single hardened SSH gateway that is the only host the VPN clients can SSH to, and from which all other administrative SSH is launched. **VLANs** for separating untrusted device classes (guest Wi-Fi, IoT, work-from-home laptops that visit untrusted networks). **Zero trust** as the conceptual successor — segment boundaries replaced by per-flow authentication and continuous authorisation; mentioned here, deferred for depth.
- **Documentation discipline.** The auditor test: if a colleague who has never seen your network reads the documents in your repository, can they recreate the network from scratch? If not, the documentation is not done. The artefacts: topology diagram, addressing plan, ruleset, sensor config, key inventory (public keys only), allowed-flow matrix, change log, runbooks.

---

## Weekly schedule

The schedule below adds up to approximately **35 hours**. Treat it as a target.

| Day       | Focus                                                          | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Self-Study | Daily Total |
|-----------|----------------------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|-----------:|------------:|
| Monday    | L1 — Stateful firewalls and nftables                           |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Tuesday   | L2 — Suricata IDS and the ET Open ruleset                      |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0h       |    0.5h    |    5.5h     |
| Wednesday | L3 — WireGuard and network segmentation                        |    2h    |    1.5h   |     0h     |    0.5h   |   1h     |     0.5h     |    0.5h    |    6h       |
| Thursday  | Exercises polished; challenge launch                           |    0h    |    2h     |     1.5h   |    0.5h   |   1h     |     1h       |    0.5h    |    6.5h     |
| Friday    | Mini-project: design the network plan, write the rules         |    0h    |    1h     |     0.5h   |    0.5h   |   1h     |     2h       |    0.5h    |    5.5h     |
| Saturday  | Mini-project: stand up the sensor, ship the VPN, write the doc |    0h    |    0h     |     0h     |    0h     |   1h     |     3h       |    0h      |    4h       |
| Sunday    | Quiz, review, polish, push                                     |    0h    |    0h     |     0h     |    0.5h   |   0h     |     0h       |    1h      |    1.5h     |
| **Total** |                                                                | **6h**   | **7.5h**  | **2h**     | **3h**    | **6h**   | **6.5h**     | **3.5h**   | **34.5h**   |

---

## File map

```
week-10-network-defense-firewalls-ids-vpn/
├── README.md                            ← this file
├── resources.md                         ← annotated bibliography, every link free
├── quiz.md                              ← 25 short-answer questions
├── homework.md                          ← five graded exercises, deliverables defined
├── lecture-notes/
│   ├── 01-stateful-firewalls-and-nftables.md
│   ├── 02-suricata-ids-and-et-open.md
│   └── 03-wireguard-and-network-segmentation.md
├── exercises/
│   ├── exercise-01-host-firewall.nft           ← nftables ruleset for a workstation
│   ├── exercise-02-egress-allowlist.nft        ← server-style egress filter
│   ├── exercise-03-ssh-rate-limit.sh           ← shell driver + nftables snippet
│   ├── exercise-04-suricata-tuning.yaml        ← suricata.yaml fragment
│   ├── exercise-05-wireguard-keygen.py         ← reproducible keygen, type-hinted
│   └── SOLUTIONS.md                            ← walkthrough for all five
├── challenges/
│   ├── challenge-01-egress-breakout.md         ← scenario: design rules to stop C2
│   └── challenge-02-segmentation-blueprint.md  ← scenario: blueprint a small office
└── mini-project/
    ├── README.md                               ← the deliverable specification
    └── starter/
        ├── README.md                           ← inventory of starter files
        ├── topology-template.md                ← ASCII diagram + addressing plan
        ├── ruleset-template.nft                ← skeleton nftables ruleset
        ├── suricata-template.yaml              ← skeleton suricata.yaml
        ├── wg0-server-template.conf            ← skeleton WireGuard server config
        ├── wg0-client-template.conf            ← skeleton WireGuard client config
        ├── allowed-flows-template.md           ← flow-matrix template
        └── runbook-template.md                 ← three-operation runbook template
```

The starter directory ships skeletons that compile and parse but do not implement a useful policy; you fill them in to make the lab work.

---

## Submission

- A pull request against the `main` branch of your fork of this curriculum repository.
- Branch named `week-10-<your-handle>`.
- The PR description links to every deliverable inside the branch by relative path.
- The PR description includes the SHA-256 of every WireGuard public key your plan references. **Do not commit private keys.** The starter README and the mini-project README repeat this rule; the grader will fail any submission that contains a base64 string in a file named with `private` in its path.

---

## Honesty about scope

This week designs a small-environment defence. The same skills scale to enterprise-grade deployments (centralised SIEM ingest of Suricata `eve.json`, hardware appliances running Suricata at 100 Gbps, hub-and-spoke WireGuard meshes that replace site-to-site IPsec) but the operational concerns of an enterprise — high availability, change management, multi-tenant policy, regulatory audit — are owed to a later course. The lab is honest about what it is: one person, one network, one weekend. The plan you produce should be honest the same way.

---

## A note on naming

This week uses the names **nftables**, **Suricata**, **Emerging Threats**, and **WireGuard** to refer to the projects (capitalisations as the projects themselves use them on their landing pages). Linux kernel subsystems (`netfilter`, `conntrack`, `xt_*`) are lower-case to match the kernel source. The Donenfeld paper is cited as "Donenfeld 2017"; the full reference is in `resources.md`.

Read `resources.md` next, then move to `lecture-notes/01-stateful-firewalls-and-nftables.md`.
