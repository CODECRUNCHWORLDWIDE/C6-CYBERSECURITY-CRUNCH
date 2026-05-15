# Week 10 — Resources

Every link below is free and primary unless explicitly tagged otherwise. The "tagged paid" items appear because they are widely cited; nothing in the curriculum requires them.

---

## Primary references — nftables

- **nftables wiki — the canonical reference.** https://wiki.nftables.org/wiki-nftables/index.php/Main_Page — maintained by the Netfilter project itself, the wiki is the authoritative reference for nftables syntax, semantics, and migration from iptables. Read at minimum the pages "Quick reference-nftables in 10 minutes", "Configuring chains", "Sets", "Maps", and "Performing Network Address Translation (NAT)" before starting Exercise 1.

- **nftables manual pages.** `man 8 nft`, `man 8 nft-rules`, `man 5 nftables`. Locally installed when you install the `nftables` package. The man pages are terse but exhaustive; treat them as your reference when the wiki page is silent on a flag.

- **netfilter.org — the project home.** https://netfilter.org/ — Linux kernel packet-filtering home. The "Documentation" link goes to the wiki; the "Downloads" link is rarely needed because every distro ships nftables.

- **Eric Leblond, "Why you will love nftables".** https://home.regit.org/2014/01/why-you-will-love-nftables/ — written by one of the maintainers when nftables was the new option; still the clearest single-page argument for the migration.

- **Pablo Neira Ayuso, "nftables — what's new in 0.9 / 1.0".** Linux Plumbers Conference 2019 / 2020 slides, archived on the netfilter site. https://www.netfilter.org/about.html#authors — the maintainer's own notes on the surface that is most stable.

- **Linux kernel documentation, netfilter.** https://www.kernel.org/doc/html/latest/networking/netfilter-sysctl.html — sysctl knobs for connection tracking. Read the `nf_conntrack_max`, `nf_conntrack_tcp_timeout_established`, and `nf_conntrack_buckets` entries.

- **Florian Westphal, "nftables — a year later".** Netdev 2.1 conference 2017. https://netdevconf.info/2.1/papers/nftables-paper-final.pdf — the post-launch report on nftables design decisions. Useful background; not required reading.

---

## Primary references — Suricata

- **Suricata documentation.** https://docs.suricata.io/ — versioned, comprehensive, free. The 7.0 LTS line is the current long-term-support series as of 2026; the 8.x line is the development series. Read at minimum the "Getting Started", "Suricata.yaml", "Rules", and "Performance" sections.

- **Open Information Security Foundation (OISF) project home.** https://suricata.io/ — the non-profit that maintains Suricata. The "Get Suricata" link goes to the install instructions for every major distribution.

- **Suricata-update tool documentation.** https://suricata-update.readthedocs.io/ — the official ruleset-management tool. Replaces the older Oinkmaster and Pulledpork scripts. The mini-project uses `suricata-update` to pull and refresh the ET Open ruleset.

- **OISF GitHub.** https://github.com/OISF/suricata — source code, issue tracker, release notes. The release notes for 7.0.0 (October 2023) describe the LTS commitments.

- **Suricata Rules Format reference.** https://docs.suricata.io/en/latest/rules/intro.html — every signature you read this week is in this format. The most-used keywords this week: `alert`, `tcp`, `flow:established,to_server`, `content:`, `pcre:`, `classtype:`, `sid:`, `rev:`, `metadata:`.

- **Suricata-verify test suite.** https://github.com/OISF/suricata-verify — the integration tests; useful as a corpus of example rules and the traffic they fire on.

---

## Primary references — Emerging Threats Open

- **ET Open ruleset distribution.** https://rules.emergingthreats.net/open/ — the live distribution point. The `suricata-7.0.0/emerging-all.rules.tar.gz` tarball is the bundle you pull with `suricata-update`. Free under the BSD-2-Clause licence (https://rules.emergingthreats.net/licensing/).

- **Proofpoint Emerging Threats product page.** https://www.proofpoint.com/us/products/advanced-threat-protection/et-pro-ruleset — the paid ET Pro page. Listed for context; ET Open is sufficient for this week.

- **ET Open rule announcements mailing list.** https://lists.emergingthreats.net/mailman/listinfo/emerging-sigs — the list where new rules are announced and discussed. Read-only subscription is the minimum for an active operator.

- **ET Open category index.** Every rules file in the tarball is named `emerging-<category>.rules`. The canonical categories: `attack_response`, `chat`, `current_events`, `dns`, `dos`, `exploit`, `exploit_kit`, `ftp`, `games`, `icmp`, `icmp_info`, `imap`, `info`, `inappropriate`, `malware`, `misc`, `mobile_malware`, `netbios`, `p2p`, `phishing`, `policy`, `pop3`, `rpc`, `scada`, `scan`, `shellcode`, `smtp`, `snmp`, `sql`, `telnet`, `tftp`, `trojan`, `user_agents`, `voip`, `web_client`, `web_server`, `web_specific_apps`, `worm`.

---

## Primary references — WireGuard

- **Jason A. Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel" (2017).** https://www.wireguard.com/papers/wireguard.pdf — 12 pages, freely distributed. The canonical reference for the protocol design. Required reading this week. Cite as: Donenfeld, Jason A. *WireGuard: Next Generation Kernel Network Tunnel.* Network and Distributed System Security Symposium (NDSS) 2017.

- **WireGuard project home.** https://www.wireguard.com/ — the project landing page. The "Quick Start" and "Cross-Platform" sections cover every supported platform.

- **WireGuard formal verification.** https://www.wireguard.com/formal-verification/ — Dowling and Paterson's 2018 formal analysis of the WireGuard protocol. Useful background; not required.

- **`wg(8)`, `wg-quick(8)` man pages.** Locally installed with the `wireguard-tools` package. The `wg` man page is the reference for the userspace tool; the `wg-quick` man page is the reference for the systemd-friendly wrapper.

- **WireGuard mailing list.** https://lists.zx2c4.com/mailman/listinfo/wireguard — Donenfeld and the active community.

- **Linux kernel WireGuard documentation.** In-tree at `Documentation/networking/wireguard.rst` since Linux 5.6 (March 2020). https://www.kernel.org/doc/Documentation/networking/wireguard.rst

---

## Comparative references — OpenVPN, IPsec

- **OpenVPN community wiki.** https://community.openvpn.net/openvpn/wiki — for the comparison in Lecture 3. The "HOWTO" page is the canonical setup reference for OpenVPN.

- **strongSwan project.** https://www.strongswan.org/ — the most-used IPsec implementation on Linux as of 2026. The "Configuration" section of the documentation is the canonical IPsec/IKEv2 reference.

- **RFC 4301, "Security Architecture for the Internet Protocol".** https://www.rfc-editor.org/rfc/rfc4301 — the IPsec architecture document. Long; cited for completeness.

- **RFC 7296, "Internet Key Exchange Protocol Version 2 (IKEv2)".** https://www.rfc-editor.org/rfc/rfc7296 — the IKEv2 spec. Long; cited for completeness.

---

## Network segmentation and zero-trust references

- **NIST SP 800-207, "Zero Trust Architecture".** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf — the canonical free description of zero-trust architecture from a primary source. Read pages 1–20 for the architectural principles; the rest is implementation guidance.

- **NIST SP 800-41 Rev. 1, "Guidelines on Firewalls and Firewall Policy".** https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf — pre-zero-trust but still the clearest free articulation of segment-based firewall policy.

- **NIST SP 800-46 Rev. 2, "Guide to Enterprise Telework, Remote Access, and Bring Your Own Device (BYOD) Security".** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-46r2.pdf — covers the VPN deployment patterns Lecture 3 invokes.

- **CISA, "Layering Network Security Through Segmentation".** https://www.cisa.gov/news-events/news/layering-network-security-through-segmentation — short, free, government-issued overview of segmentation as a control.

- **SANS, "The Case for Network Segmentation".** https://www.sans.org/white-papers/ — search "network segmentation"; multiple free whitepapers. Recommended: read at least one beyond the NIST documents.

---

## Tooling and supplementary

- **`ip`, `ss`, `tcpdump` man pages.** Locally installed. The day-to-day toolkit; the man pages are the reference.

- **`conntrack-tools`.** https://conntrack-tools.netfilter.org/ — the userspace tools for inspecting the kernel's connection-tracking table. Install with `apt install conntrack` (Debian/Ubuntu). The `conntrack -L` command dumps the live table.

- **Raspberry Pi OS documentation.** https://www.raspberrypi.com/documentation/ — for the optional Pi-as-IDS-sensor portion of the mini-project. The "Computers and microcontrollers" section is the relevant one.

- **Wireshark.** https://www.wireshark.org/ — free packet capture and analysis. Useful as a sanity check on Suricata's parsing; not required.

---

## Standards and RFCs cited inline this week

- **RFC 793, "Transmission Control Protocol".** https://www.rfc-editor.org/rfc/rfc793 — TCP state machine; cited when introducing connection tracking.

- **RFC 4787, "Network Address Translation (NAT) Behavioral Requirements for Unicast UDP".** https://www.rfc-editor.org/rfc/rfc4787 — cited when discussing UDP connection tracking, which is technically a behavioural extrapolation rather than a protocol-level state.

- **RFC 7857, "Updates to Network Address Translation (NAT) Behavioral Requirements".** https://www.rfc-editor.org/rfc/rfc7857 — companion to RFC 4787 for the same topic.

---

## Reading order

Week 10 is dense. The recommended reading order:

1. This `resources.md` (you are here).
2. `lecture-notes/01-stateful-firewalls-and-nftables.md` plus the **nftables wiki** "in 10 minutes" page.
3. `lecture-notes/02-suricata-ids-and-et-open.md` plus the **Suricata docs** "Getting Started" section.
4. **Donenfeld 2017** (12 pages, do not skim) before `lecture-notes/03-wireguard-and-network-segmentation.md`.
5. Exercises 1 through 5 in order.
6. Challenges 1 and 2 in either order.
7. Mini-project.
8. Quiz on Sunday.

---

## Bibliography (suggested citation form for the post-incident-style write-up in the mini-project)

If the mini-project's write-up cites a source, prefer the following form:

- Donenfeld, Jason A. *WireGuard: Next Generation Kernel Network Tunnel.* NDSS 2017. https://www.wireguard.com/papers/wireguard.pdf
- Open Information Security Foundation. *Suricata User Guide* version 7.0. 2024. https://docs.suricata.io/en/suricata-7.0.0/
- Proofpoint. *Emerging Threats Open Ruleset.* Continuously updated. https://rules.emergingthreats.net/open/
- The Netfilter Project. *nftables Wiki.* Continuously updated. https://wiki.nftables.org/
- NIST. *Special Publication 800-207, Zero Trust Architecture.* August 2020. https://doi.org/10.6028/NIST.SP.800-207
- NIST. *Special Publication 800-41 Revision 1, Guidelines on Firewalls and Firewall Policy.* September 2009. https://doi.org/10.6028/NIST.SP.800-41r1

The exact form is your choice; consistency within a document matters more than the choice between style guides.
