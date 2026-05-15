# Week 10 — Quiz

> 25 short-answer questions. One sitting; no notes; aim for under 45 minutes. Answer in your own words. If a question begins with "Cite", give the canonical reference (URL or RFC number) you would point a colleague at.

---

## Section 1 — Stateful firewalls and nftables (Q1–Q9)

**Q1.** In one sentence, define what makes a firewall *stateful* rather than *stateless*.

**Q2.** Name the five fields in the conntrack five-tuple.

**Q3.** Translate the iptables rule `iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT` into the modern nftables equivalent.

**Q4.** What is the difference between a chain whose policy is `drop` and a chain whose default verdict at the end of all rules happens to be drop? Why does the distinction matter operationally?

**Q5.** Explain in two sentences why `inet` is the recommended chain family for most rulesets in 2026.

**Q6.** Write a single nftables rule that drops every TCP packet to port 22 whose source address is not in the named set `@mgmt_v4`.

**Q7.** What is the difference between `ct state new`, `ct state established`, and `ct state related`? Give an example of a packet that would match each.

**Q8.** Why is **egress filtering** described as "the highest-leverage single control against modern attacker tradecraft"? Give two specific attacker techniques that egress filtering disrupts.

**Q9.** Cite the canonical free reference for nftables syntax and semantics.

---

## Section 2 — Suricata and ET Open (Q10–Q17)

**Q10.** In one sentence, define what an **IDS** is, and in one more sentence, name one thing it is *not*.

**Q11.** Name the four cryptographic primitives Suricata's own protocol decoders parse out of a TLS handshake that remain visible even on encrypted traffic.

**Q12.** Why does the Suricata documentation recommend `cluster-type: cluster_flow` in the `af-packet` configuration? What problem would arise without it?

**Q13.** What licence is the **Emerging Threats Open** ruleset distributed under, and what does that licence permit?

**Q14.** What is the `signature_id` (`sid`) range convention for user-written local rules in Suricata?

**Q15.** Suricata's `eve.json` log is one JSON object per line. Write the `jq` one-liner that prints the top 10 alert signatures by frequency from a file `eve.json`.

**Q16.** Give two reasons a small-lab Suricata deployment should run in **IDS** mode rather than **IPS** mode.

**Q17.** Cite the canonical free reference for the Suricata rule format.

---

## Section 3 — WireGuard and segmentation (Q18–Q25)

**Q18.** In two sentences, describe what makes the **Noise framework's IK pattern** appropriate as the basis for WireGuard's handshake.

**Q19.** Name the four cryptographic primitives WireGuard uses (cipher, authentication, hash, key-derivation).

**Q20.** Explain in one paragraph why WireGuard's `AllowedIPs` directive provides *cryptographic routing* — a property OpenVPN and IPsec do not provide.

**Q21.** What is the difference between a **full-tunnel** and a **split-tunnel** WireGuard client configuration? When would you choose each?

**Q22.** Give two technical reasons WireGuard has displaced OpenVPN as the default choice for greenfield VPN deployments since 2020.

**Q23.** Define **jump host** (also called **bastion**) in two sentences. Why does a jump host reduce the attack surface of an SSH-administered network?

**Q24.** What is the difference between *segmentation* and *zero-trust*? Cite the NIST document that defines zero-trust architecture.

**Q25.** Cite the canonical free reference for the WireGuard protocol.

---

## Answer key

> Do not read until you have written your answers.

### Section 1

**A1.** A stateful firewall maintains a per-flow state table (the connection-tracking table) so the *reply* direction of a permitted flow is implicitly accepted, rather than requiring an explicit rule for each direction.

**A2.** Source IP, destination IP, source port (or ICMP type), destination port (or ICMP code), protocol.

**A3.** `ct state established,related accept`. (The full nftables rule sits inside a chain in an `inet` table; the matcher itself is the four words above.)

**A4.** A chain with `policy drop` enforces drop at the end of the chain via the kernel's chain-policy mechanism; if the policy is `accept` and you instead rely on a final explicit `drop` rule, the policy *and* the rule both run, and reordering the rules can accidentally bypass the drop. Operationally: relying on the policy is the safer default-deny because it is independent of rule order.

**A5.** A single `inet` table applies to both IPv4 and IPv6 traffic, which halves the rule count and eliminates one of iptables' most common bugs — IPv6 traffic accidentally unfiltered because the operator wrote an `iptables` rule but forgot the parallel `ip6tables` rule.

**A6.** `tcp dport 22 ip saddr != @mgmt_v4 drop` (or, with `reject`: `tcp dport 22 ip saddr != @mgmt_v4 reject with icmpx admin-prohibited`).

**A7.** `new` is the first packet of a flow conntrack has not seen before (TCP SYN, the first UDP packet of a conversation). `established` is any packet on a flow conntrack has seen in both directions. `related` is a packet that is *not* part of the flow but is logically associated — examples: an ICMP "destination unreachable" responding to a UDP packet; the FTP data channel that opens in response to an FTP control-channel command.

**A8.** Modern attacker post-exploit value depends on egress: command-and-control channels, exfiltration of stolen data, downloading second-stage payloads. Two examples: (i) blocking outbound to anything other than an enumerated allowlist neuters a beacon to an attacker-controlled domain; (ii) blocking outbound DNS to external resolvers (forcing the trusted recursive resolver) prevents DNS-tunnelling as an exfiltration channel.

**A9.** The nftables wiki at https://wiki.nftables.org/.

### Section 2

**A10.** An IDS reads network traffic and emits alerts when traffic matches a signature in its loaded ruleset. It is *not* a firewall — by default, the IDS does not block traffic.

**A11.** Server-name indication (SNI), certificate subject, certificate fingerprint (and JA3/JA3S fingerprints of the client/server TLS stacks, which count as one item for the purposes of this question).

**A12.** `cluster_flow` ensures that packets belonging to the same flow are delivered to the same worker thread, which keeps stream-reassembly and flow-state coherent. Without it, packets of the same flow can be split across workers and stream reassembly produces garbage, dropping detections or generating false ones.

**A13.** BSD-2-Clause. The licence permits redistribution, modification, and commercial use without restriction beyond the licence's attribution requirement.

**A14.** 1 000 000 through 1 999 999.

**A15.** `jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn | head -10`.

**A16.** (Any two of:) An IPS-mode crash takes the network down because Suricata is in the data path; a misfired signature in IPS mode drops legitimate traffic with no human in the loop; the operator skill required to keep an IPS deployment from causing outages is substantial; the lab does not generate enough traffic to justify the risk.

**A17.** The Suricata documentation at https://docs.suricata.io/, specifically https://docs.suricata.io/en/latest/rules/intro.html.

### Section 3

**A18.** Noise IK provides a one-round-trip handshake in which the initiator's first message is encrypted to the responder's static public key, which the initiator knows in advance — appropriate because a VPN client knows its server's public key from configuration, so the round-trip-reduction property of IK is fully usable.

**A19.** **ChaCha20** (cipher), **Poly1305** (AEAD authentication), **BLAKE2s** (hashing), **HKDF** (key derivation, instantiated with BLAKE2s). Plus **Curve25519** (ECDH) for the asymmetric step and **SipHash24** for session indexing — accept any four of the six as a full answer.

**A20.** WireGuard's `AllowedIPs` directive binds each peer's public key to a fixed set of permitted source IPs. A packet that arrives on the tunnel with a source IP not in the peer's `AllowedIPs` is dropped, and a packet destined for an IP not in any peer's `AllowedIPs` is unroutable. The IP layer's source-and-destination decisions therefore depend on cryptographic identity, not on declarative routing — a peer who steals another peer's IP cannot impersonate that peer without also stealing that peer's private key.

**A21.** A full-tunnel client routes *all* traffic through the VPN (`AllowedIPs = 0.0.0.0/0, ::/0`); a split-tunnel client routes only specific destinations through the VPN. Full-tunnel is appropriate when you do not trust the local network (coffee shop, hotel) and want every packet to traverse the VPN. Split-tunnel is appropriate when you trust the local network for general internet access but need access to specific internal resources over the VPN.

**A22.** (Any two of:) the kernel-resident implementation is ~4 000 lines of code vs. OpenVPN's ~60 000 plus OpenSSL; the cipher suite is fixed and modern with no negotiation; key-as-identity removes the certificate-and-PKI infrastructure; throughput is ~3x higher on commodity CPUs; sub-second roaming between networks; configuration is one file per peer.

**A23.** A jump host (bastion) is a single hardened SSH server that is the only legitimate inbound-SSH entry point to an administered network; all other hosts deny inbound SSH except from the jump host's address. The attack surface shrinks from "every host that listens on 22/tcp" to "the one jump host", which can be hardened with 2FA, session recording, and aggressive patching at a cost that does not scale linearly with fleet size.

**A24.** Segmentation enforces *perimeter-based* trust — there is an inside and an outside, and the firewall is the boundary. Zero-trust replaces the perimeter with *per-flow authentication* — every flow is authenticated and authorised at the application layer regardless of network position. NIST SP 800-207, *Zero Trust Architecture*, https://doi.org/10.6028/NIST.SP.800-207.

**A25.** Donenfeld, Jason A. *WireGuard: Next Generation Kernel Network Tunnel.* NDSS 2017. https://www.wireguard.com/papers/wireguard.pdf.

---

## Scoring

- 23–25 correct: you can drive the mini-project without rereading the lectures.
- 18–22 correct: re-read the section(s) you missed before starting the mini-project.
- below 18: re-read all three lecture notes and retake.

The quiz is not graded for the course; it is graded by you, against yourself.
