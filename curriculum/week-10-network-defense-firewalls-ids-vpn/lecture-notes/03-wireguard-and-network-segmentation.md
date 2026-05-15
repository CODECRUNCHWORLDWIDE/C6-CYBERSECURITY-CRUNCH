# Lecture 3 — WireGuard and Network Segmentation

> *Lecture 1 controlled which packets enter and leave a host. Lecture 2 watched packets and alerted on the suspicious ones. Lecture 3 controls who can ride the tunnel into the network in the first place, and how the network is internally divided so a single compromise does not become a wholesale compromise.*

---

## 1. Why a VPN at all

A VPN — virtual private network — exists for two practical purposes that are worth distinguishing.

**Remote access.** You are at a coffee shop, your team's servers are on a private network behind a firewall, and you need to administer them. The traditional answer was to expose SSH (or worse, RDP) directly on the internet on a non-standard port. The modern answer is to expose a single VPN port and put SSH/RDP/internal web apps behind it. The VPN moves you, network-topologically, *inside* the perimeter.

**Site-to-site.** Two physical locations need to act as one network. Office A in New York, office B in Miami, both with their own LAN, both behind their own firewall. A site-to-site VPN bridges the two so that a host in office A can reach a host in office B as if they were on the same switch.

This lecture concentrates on **remote access**. The mini-project's reference architecture has a small office network with a VPN listener that admits a handful of laptops and phones from outside the office. The same techniques scale to site-to-site, but the operational concerns there (HA, BGP-over-VPN, multi-tenant isolation) are owed to a later course.

What a VPN is *not*:

- An anonymity tool. A VPN provider's "no logs" claim notwithstanding, the VPN provider sees every flow you send through it; you have moved the trust boundary from your ISP to your VPN provider, not eliminated it. This week's VPN is one you operate yourself, so the trust boundary is *you*.
- A security control by itself. A compromised laptop on the inside of the VPN is on the inside of your network. The VPN authenticates the *device*; the controls inside the network handle authorisation.
- A panacea for misconfigured services. If your internal admin panel is configured to accept any login on the local network, putting it behind a VPN means the attacker must compromise a VPN-connected device first — a meaningful hurdle, but not zero.

---

## 2. WireGuard in twelve pages

The canonical reference is **Donenfeld 2017** — Jason A. Donenfeld's NDSS 2017 paper, *WireGuard: Next Generation Kernel Network Tunnel*. The paper is 12 pages, free, well-written, and is the single most important piece of reading this week. Open it now: https://www.wireguard.com/papers/wireguard.pdf.

The paper's argument, condensed:

1. Existing VPN protocols (IPsec, OpenVPN, L2TP) are decades of cruft. The codebases are large. The configuration is complex. The handshakes negotiate too many parameters. The CPU cost is high. The mobile-roaming experience is bad.
2. WireGuard fixes those problems by being small (kernel module is ~4 000 lines), opinionated (one cipher suite, no negotiation), and stateless (peers are identified by cryptographic key, not by certificate chain or pre-shared secret hierarchy).
3. The protocol is built on the **Noise framework**'s IK pattern. The handshake is one round-trip. The packet format is fixed at 60 bytes of overhead per packet. The cryptographic primitives are **Curve25519** for ECDH, **ChaCha20-Poly1305** for AEAD, **BLAKE2s** for hashing, **SipHash24** for the key index.
4. The implementation lives in the kernel for performance. Userspace implementations exist (`wireguard-go`, `boringtun`) for platforms where in-kernel is impossible (macOS pre-Sonoma, Windows pre-2021).

The paper is required reading. The rest of this lecture is the operator's view: how to deploy it.

---

## 3. The mental model

In OpenVPN, a connection has a *client* and a *server*. The server holds a CA certificate; the client presents its certificate; the TLS handshake negotiates a session.

In WireGuard, there are no clients and no servers. There are only **peers**. Each peer is identified by its **public key**. Each peer's configuration lists the other peers it is willing to talk to, by public key, with the IP address or hostname at which to find each. Authentication is by key alone; there is no challenge, no certificate, no PKI.

Practically, in a remote-access deployment one peer is configured to *listen* on a UDP port (we call it "the server" for clarity) and other peers are configured with that port and address as their endpoint (we call them "clients"). But that is convention, not protocol — the same WireGuard binary on the same machine could be both.

The implication: **the entire identity of a peer is its keypair**. Lose the private key, lose the identity. Compromise the private key, the attacker is that peer. Re-key by generating a new keypair and distributing the new public key to every peer in the topology.

---

## 4. Keypair generation

Three commands:

```bash
# Make a directory with paranoid permissions.
mkdir -p ~/wg && chmod 700 ~/wg && cd ~/wg

# Generate a private key. The `umask 077` ensures the file is mode 600.
umask 077
wg genkey > server.private

# Derive the public key from the private key.
wg pubkey < server.private > server.public

# Inspect.
cat server.public
# Output: a base64 32-byte string, ~44 characters.
```

The private key is 32 bytes of high-entropy randomness. The public key is the Curve25519 point you get by multiplying the standard base point by the private key. Standard public-key cryptography; familiar primitives; nothing exotic.

A keypair takes microseconds to generate. The cost is the *handling*: the private key must never appear in a commit, must never travel over an unencrypted channel, must live on the host that uses it. The mini-project enforces this with a `.gitignore` rule that excludes `*private*` files and a pre-commit check that fails the PR if any base64 string sneaks into a tracked file.

A **pre-shared key** (PSK) can optionally be added to a peer relationship for *defence in depth* against future quantum-computer attacks against Curve25519. The PSK is symmetric and is also 32 bytes. Generate with `wg genpsk > peer.psk`. The PSK is required to be the same value on both peers of a relationship. Most home/lab deployments skip the PSK; an enterprise deployment with a 30-year confidentiality horizon includes it.

---

## 5. The server configuration

A minimal server config, `wg0.conf`, lives at `/etc/wireguard/wg0.conf`:

```ini
[Interface]
# The server's own private key. Treat this file as sensitive.
PrivateKey = SERVER_PRIVATE_KEY_HERE

# The IP address of the server *inside* the VPN overlay.
Address = 10.10.0.1/24

# The UDP port the server listens on. 51820 is the conventional default.
ListenPort = 51820

# PostUp / PostDown can run shell commands after the interface comes up
# or before it goes down. Use sparingly; prefer a separate nftables config.
PostUp   = nft add rule inet filter forward iifname wg0 ct state new accept
PostDown = nft delete rule inet filter forward handle <h>

[Peer]
# Laptop owned by Carlos.
PublicKey = CARLOS_LAPTOP_PUBLIC_KEY_HERE
AllowedIPs = 10.10.0.2/32

[Peer]
# Phone owned by Carlos.
PublicKey = CARLOS_PHONE_PUBLIC_KEY_HERE
AllowedIPs = 10.10.0.3/32

[Peer]
# Laptop owned by Maria.
PublicKey = MARIA_LAPTOP_PUBLIC_KEY_HERE
AllowedIPs = 10.10.0.4/32
```

Notes:

- `AllowedIPs` on the server side restricts which source IPs that peer is allowed to send from inside the tunnel. `10.10.0.2/32` means "Carlos's laptop is only allowed to claim the address 10.10.0.2; if it sends a packet with any other source address, drop it." This is the **cryptographic-routing** property that makes WireGuard's authorisation model so simple.
- `Address = 10.10.0.1/24` declares the server's own VPN-overlay address and the subnet the overlay uses.
- `ListenPort = 51820` is the UDP port. Use the well-known WireGuard port unless you have a reason to vary; many ISPs and corporate networks blocklist common VPN ports, so you may end up moving to 443/UDP in practice. The protocol does not care.

Start it with:

```bash
sudo systemctl enable --now wg-quick@wg0
sudo wg show
```

`wg-quick` reads the config, brings up the `wg0` interface, sets the address, adds the routes, and (with `[Interface] PostUp`/`PostDown`) runs the firewall side-effects.

---

## 6. The client configuration

A client config, also `wg0.conf` but on the client machine:

```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY_HERE
Address = 10.10.0.2/24

# Send all DNS queries through the tunnel to a resolver on the VPN.
DNS = 10.10.0.1

[Peer]
# The server.
PublicKey = SERVER_PUBLIC_KEY_HERE
Endpoint = vpn.example.com:51820

# Full-tunnel: route every packet through the VPN.
AllowedIPs = 0.0.0.0/0, ::/0

# For NAT'd clients (most phones, most laptops on public Wi-Fi).
PersistentKeepalive = 25
```

Notes:

- `AllowedIPs = 0.0.0.0/0, ::/0` makes this a **full-tunnel** client — every packet, IPv4 and IPv6, goes through the VPN. Useful for "trust the home network, not the coffee shop".
- For a **split-tunnel** client (only lab traffic over the VPN; the rest direct):
  ```ini
  AllowedIPs = 10.10.0.0/24, 192.168.1.0/24
  ```
  Now only traffic destined for those two subnets crosses the tunnel.
- `Endpoint` is the *public* address of the server. A hostname resolves on every `wg-quick up`; if the server's IP changes, the client follows after a reconnect.
- `PersistentKeepalive = 25` sends an empty packet every 25 seconds. Without it, a NAT gateway between the client and the server will lose the UDP mapping after 30 seconds of silence and the tunnel will appear broken until the client sends something. 25 seconds is the standard advice.

On the client, the same `wg-quick up wg0` command starts the tunnel. On phones, the WireGuard mobile app reads a QR-coded version of the same config file.

---

## 7. WireGuard vs. OpenVPN vs. IPsec — the comparison

The case for migrating away from OpenVPN and IPsec to WireGuard, in numbers:

| Property                    | WireGuard                | OpenVPN                | IPsec (strongSwan)         |
|-----------------------------|--------------------------|------------------------|----------------------------|
| Kernel-resident             | yes (Linux 5.6+)         | no (userspace)         | yes                        |
| Code size                   | ~4 000 LOC               | ~60 000 LOC + OpenSSL  | ~100 000 LOC strongSwan    |
| Cipher negotiation          | none (one fixed suite)   | yes (long list)        | yes (very long list)       |
| Handshake round-trips       | 1                        | several (TLS)          | several (IKE)              |
| Configuration files         | 1 per peer               | 2–4 + a CA infra       | 4+ + a CA infra            |
| Mobile roaming              | sub-second               | minutes (reconnect)    | seconds                    |
| Throughput on commodity CPU | ~1 Gbps                  | ~300 Mbps              | ~700 Mbps                  |
| Audit surface               | small, well-reviewed     | large, well-reviewed   | large, well-reviewed       |
| Standardisation             | no (designed by Donenfeld) | yes (de-facto)       | yes (RFC 4301 et seq.)     |

The trade-offs that argue *against* WireGuard in some deployments:

- **No standard.** WireGuard is not an IETF standard. For some regulated industries (defence, certain financial verticals) this is disqualifying. IPsec/IKEv2 is the answer in those cases.
- **No identity binding to a user.** WireGuard authenticates *devices* by keypair; it does not, by itself, authenticate *users*. If you need user-level identity (RADIUS, SAML, OIDC), you have to layer it on top, typically by gating the resources behind a separate authentication step inside the tunnel. OpenVPN's PKI can encode user identity in the certificate; IPsec can hook into EAP for the same.
- **UDP only.** WireGuard is UDP. Some restrictive corporate networks block all UDP except DNS, which makes WireGuard unreachable. OpenVPN can fall back to TCP; the cost is throughput, but the connectivity works.

For this course's purposes — a small office network, a few laptops, a few phones, a Pi-class server — WireGuard is the right answer on every axis.

---

## 8. The cryptography, briefly

WireGuard's cryptographic suite is fixed: there is no negotiation. The suite is:

- **Curve25519** for elliptic-curve Diffie-Hellman. The peers' public keys are Curve25519 points.
- **ChaCha20-Poly1305** for AEAD encryption. ChaCha20 is the stream cipher; Poly1305 is the authentication tag.
- **BLAKE2s** for hashing in the handshake and in key derivation.
- **HKDF** for key derivation, instantiated with BLAKE2s.
- **SipHash24** for the small index that identifies a session in subsequent packets.

The handshake follows the **Noise IK** pattern: the initiator knows the responder's static public key in advance, so the first handshake message can be encrypted to the responder, which reduces round-trips and provides resistance against passive observers identifying the responder.

The packet format adds 60 bytes of overhead per data packet: 4 bytes type, 4 bytes session index, 8 bytes counter, 16 bytes Poly1305 tag, plus IP + UDP headers. Over a 1 500-byte MTU link, you spend roughly 4% on tunnel overhead — a useful number to remember when sizing MTUs (set the tunnel MTU to 1 420 to avoid fragmentation).

The honest gap in the WireGuard cryptographic story is **post-quantum**. ChaCha20 and Poly1305 are believed to be quantum-resistant; Curve25519 is not (Shor's algorithm breaks ECC on a sufficiently large quantum computer). The mitigation, today, is the optional **pre-shared key** that adds a symmetric layer no quantum attack breaks. The longer-term direction is a post-quantum hybrid mode in a future WireGuard version; as of 2026 it is research-grade and not in mainline.

---

## 9. Routing inside the tunnel

A common mental confusion: "I am connected to the VPN; why can't I reach the office printer at `192.168.1.42`?"

The answer is the `AllowedIPs` field on the client. `AllowedIPs` is, on the client side, *the list of destination addresses that get routed into the tunnel*. If you only put `10.10.0.0/24` in `AllowedIPs`, that is the only destination the client will route over the VPN. To reach `192.168.1.42`, you need `192.168.1.0/24` in `AllowedIPs` (split-tunnel) or `0.0.0.0/0` (full-tunnel).

The server side cooperates: the server needs to be configured to route between the VPN overlay and the office LAN. The two pieces:

1. `sysctl net.ipv4.ip_forward=1` (and the IPv6 equivalent) so the kernel routes between interfaces.
2. An nftables `forward` rule that permits the flow:
   ```nft
   chain forward {
       type filter hook forward priority filter; policy drop;
       iifname wg0 oifname eth0 ct state new accept
       ct state established,related accept
   }
   ```
3. A `postrouting` NAT rule that masquerades VPN traffic onto the LAN, so the LAN hosts see traffic coming from the gateway and do not need a route back to the VPN subnet:
   ```nft
   chain postrouting {
       type nat hook postrouting priority srcnat;
       iifname wg0 oifname eth0 masquerade
   }
   ```

The mini-project's reference architecture sets all three.

---

## 10. Operating a WireGuard deployment

The operational tasks that come up in practice:

- **Add a peer.** Generate a keypair on the new device, write a client config, add a `[Peer]` block to the server config, restart the server's `wg0` (or use `wg syncconf` for atomic reload). Total time: about 90 seconds. Exercise 5 builds the keypair-generation script that makes this fast.
- **Revoke a peer.** Remove the `[Peer]` block from the server, restart. There is no "revocation list" in the OpenVPN sense; removing the public key *is* the revocation. The peer's private key is now useless against your network.
- **Re-key the server.** Replace the server's keypair, update *every* client's `[Peer] PublicKey`. This is the inconvenient operation; the mitigation is to rotate keys on a schedule (annually, e.g.) so the operational muscle is real.
- **Move the server.** WireGuard's roaming makes this trivial on the client side — the client just sets `Endpoint` to the new address — but you have to push the new endpoint to every client. The mini-project's runbook scripts both.
- **Audit the active sessions.** `sudo wg show` lists every peer with their latest handshake time and bytes-in/bytes-out. A peer that has not handshaken in days is probably offline; a peer with anomalous traffic volume is worth investigating.

---

## 11. Network segmentation — the conceptual map

The firewall and the VPN are about *who is allowed where*. Segmentation is about *how the network is divided so the wrong who cannot reach the wrong where*.

```
+-------------------------------------------------------------------+
|                          INTERNET                                 |
+-----------------------------------+-------------------------------+
                                    |
                                    | (WAN)
                                    v
                           +--------+-------+
                           |   GATEWAY      |   nftables + Suricata + WireGuard
                           +-+-----+-----+--+
                             |     |     |
              +--------------+     |     +---------------+
              |                    |                     |
              v                    v                     v
       +--------------+     +-------------+      +---------------+
       |   DMZ        |     |  TRUSTED    |      |   GUEST       |
       |  10.0.20.0/24|     | 10.0.10.0/24|      | 10.0.30.0/24  |
       |              |     |             |      |               |
       | web server   |     | admin       |      | IoT / smart   |
       | mail relay   |     | workstations|      | TV / guests   |
       +-+--+---------+     +------+------+      +-------+-------+
         |  |                      |                     |
         |  | (return to gateway)  |                     |
         v  v                      v                     v
        ... (segment-specific rules) ...
                            +-------------+
                            |    VPN      |
                            | 10.10.0.0/24|
                            +-------------+
```

The segments, in order of trust:

- **DMZ** (Demilitarised Zone). Hosts that accept inbound traffic from the internet — your web server, your mail relay. The DMZ can be reached *from* the internet (with firewall constraints); it can *not* initiate connections to the trusted segment. If a DMZ host is compromised, the blast radius is limited to the DMZ.
- **Trusted.** Your administrative workstations, your file server, your home directory. Can reach the DMZ for administration; cannot be reached *from* the DMZ except for replies to existing connections.
- **Guest / IoT.** Devices you do not control or do not trust: smart TVs that phone home, guest devices, untrusted-vendor IoT. Can reach the internet; cannot reach any other segment.
- **VPN.** Authenticated remote users. Reaches the trusted segment subject to a *jump-host* rule (section 12).

Each segment is a separate VLAN on the switch (or a separate physical network on small deployments), with its own subnet, its own DHCP scope, and its own row in the gateway's firewall ruleset.

The rule pattern in nftables:

```nft
# inet filter forward chain
ct state established,related accept

# DMZ may only reply, never initiate to trusted.
iifname dmz_iface oifname trusted_iface drop

# Guest may only reach the internet, never any other LAN segment.
iifname guest_iface oifname { trusted_iface, dmz_iface } drop
iifname guest_iface oifname wan_iface accept

# VPN may reach trusted only via the jump host.
iifname wg0 oifname trusted_iface ip daddr 10.0.10.5 accept
iifname wg0 oifname trusted_iface drop

# Trusted may reach anywhere.
iifname trusted_iface accept

# Default-deny catches everything else.
```

Exercise 2 and the mini-project both extend this template.

---

## 12. The jump host (bastion)

The **jump host** is a single hardened SSH server that is the only legitimate entry point for administrative SSH into the trusted segment. Every other host's SSH is reachable *only from the jump host*. The motivation: most credential-theft attacks against SSH start with credentials harvested from a phishing campaign or a compromised laptop; if there are 200 SSH-listening servers, the attacker has 200 chances. If there is one, the attacker has one — and that one can be hardened to a degree that 200 cannot.

The jump host's hardening:

- SSH on a non-default port (low value; advertised port scans find anything; do it for the noise-reduction).
- Public-key authentication only (`PasswordAuthentication no` in `sshd_config`).
- 2FA (TOTP via `libpam-google-authenticator`, or hardware token via U2F).
- Logged: every shell session recorded with `auditd` or with a dedicated tool like `sudosh2`.
- Monitored: Suricata signature on inbound SSH from outside the VPN subnet.
- Resource-restricted: low CPU and memory caps, so a compromise cannot host secondary payloads.
- Patched aggressively: `unattended-upgrades` is fine for the jump host even when it is not fine for the rest of the fleet.

In nftables terms the policy is one rule:

```nft
chain forward {
    iifname wg0 oifname trusted_iface tcp dport 22 ip daddr 10.0.10.5 accept
    iifname wg0 oifname trusted_iface drop
}
```

VPN users SSH to `10.0.10.5` (the jump host) and from there `ssh` to the actual target. The two-hop path is preserved in the SSH config with `ProxyJump`:

```ssh-config
Host *.lab
    ProxyJump bastion
    User admin

Host bastion
    HostName 10.0.10.5
    User admin
```

Now `ssh fileserver.lab` automatically proxies through the bastion.

---

## 13. Zero-trust, mentioned

The segment-based model in section 11 is *perimeter-based*: the network has an inside and an outside, and the boundary is the firewall. The successor model is **zero trust**, in which there is no inside and no outside — every flow is authenticated and authorised per-request, at the application layer, regardless of network position. NIST SP 800-207 is the canonical free description; read pages 1–20.

Zero-trust is the direction the industry is moving for enterprise deployments. The implementations (Google BeyondCorp, Cloudflare Access, Tailscale's ACLs, the various commercial *zero-trust network access* products) are commercially mature in 2026. The operational cost is real: every service has to know how to do per-request authentication; the identity provider has to be hardened; the audit story has to be in place.

For this week's lab, the segment-based model is the right scope. The mini-project's plan can reference zero-trust as the future-direction; the implementation stays segmented. A later course explores zero-trust deployment in depth.

---

## 14. The full reference architecture

Stitched together: a small office network with everything from this week's lectures applied.

```
                            INTERNET
                                |
                       (ISP-provided router,
                        in bridge mode if possible)
                                |
                                v
+-------------------------------------------------------------------+
|              GATEWAY (Linux box or a Pi 5)                        |
|                                                                   |
|  - WAN iface:     eth0  (DHCP from ISP)                           |
|  - LAN iface:     eth1  (trunks all VLANs to switch)              |
|  - VPN iface:     wg0   (10.10.0.0/24, UDP 51820)                 |
|  - Suricata on:   eth0  (passive monitoring of WAN)               |
|                                                                   |
|  nftables: default-deny input + forward; egress-allowlist output  |
|  Suricata: IDS mode, ET Open ruleset, eve.json                    |
|  WireGuard: server on UDP 51820, allows three peers               |
+-------------------------------------------------------------------+
                                |
                                v
+-------------------------------------------------------------------+
|                         L2 / L3 SWITCH                            |
|                       (VLAN-capable)                              |
+---+-----+--------------+--------------+---------------+-----------+
    |     |              |              |               |
    v     v              v              v               v
   VLAN  VLAN          VLAN           VLAN            VLAN
   10    20            30             40              99
 trusted DMZ          guest          IoT          management
 10.0.10 10.0.20      10.0.30        10.0.40      10.0.99
```

The mini-project's `topology-template.md` ships this diagram for you to adapt.

---

## 15. The deliverables, in plain English

By the end of this week, you have produced:

- An nftables ruleset that enforces default-deny on inbound and forwarded traffic, with an egress allowlist on at least one server.
- A Suricata sensor running ET Open, with a tuning pass that has disabled at least three irrelevant categories and suppressed at least three noisy signatures.
- A WireGuard server with at least two clients (one full-tunnel laptop, one split-tunnel phone), each with its own keypair, no private key committed to git.
- A network plan documenting at least three segments (trusted, guest, DMZ; the mini-project allows adding IoT and management as a fourth and fifth), an allowed-flow matrix, and a three-operation runbook.

The mini-project is the integration of all four into a single defensible plan that an auditor would read and accept.

---

## 16. Summary

- A **VPN** is the answer to "how do authorised users reach the inside of the network from outside". **WireGuard** is the modern free answer.
- WireGuard's design — fixed cipher suite, key-as-identity, one config file, kernel-resident — makes it dramatically simpler to deploy than OpenVPN or IPsec for greenfield networks.
- Donenfeld's 2017 paper is 12 pages and is required reading.
- **Segmentation** divides the network into trust tiers. The minimum useful set: trusted, DMZ, guest. The maximum useful set for a small environment: trusted, DMZ, guest, IoT, management.
- A **jump host** is a single hardened SSH bastion; it limits the SSH attack surface from "every host" to "one host".
- **Zero-trust** is the conceptual successor; deferred for depth.
- The deliverable this week is *plans and rules and configs*, not "I clicked some buttons in a UI". An auditor or a future-you should be able to read the artefacts and rebuild the network.

Next: the exercises, the challenges, and the mini-project.

---

## References cited inline

- Donenfeld, Jason A. *WireGuard: Next Generation Kernel Network Tunnel.* NDSS 2017. https://www.wireguard.com/papers/wireguard.pdf
- WireGuard project. *Quick Start.* https://www.wireguard.com/quickstart/
- WireGuard project. *Cross-Platform.* https://www.wireguard.com/install/
- Dowling, B. and Paterson, K. *A Cryptographic Analysis of the WireGuard Protocol.* 2018. https://www.wireguard.com/formal-verification/
- NIST. *Special Publication 800-207, Zero Trust Architecture.* August 2020. https://doi.org/10.6028/NIST.SP.800-207
- NIST. *Special Publication 800-46 Rev. 2, Guide to Enterprise Telework, Remote Access, and BYOD Security.* https://doi.org/10.6028/NIST.SP.800-46r2
- strongSwan project. https://www.strongswan.org/
- OpenVPN project. https://community.openvpn.net/openvpn/wiki
