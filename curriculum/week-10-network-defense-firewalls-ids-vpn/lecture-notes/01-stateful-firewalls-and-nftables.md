# Lecture 1 — Stateful Firewalls and nftables

> *A firewall is a policy enforcement point. The policy is the question "which flows are allowed"; the enforcement is the kernel saying yes or no to each packet. This lecture is about how the Linux kernel decides, and how you write the policy.*

---

## 1. What a firewall actually is

A firewall sits between two network regions and decides, for each packet, whether the packet is allowed to cross. That is the entire idea. Everything else — chains, tables, hooks, state, rate limits — is *implementation detail* of the same idea.

The thing to internalise early is that "firewall" is not a product, it is a behaviour. The Linux kernel has *been* a firewall on every machine you have ever run Linux on. The question is whether you have configured it to *act* like one.

In the Linux kernel, the subsystem that does this is called **netfilter**. Netfilter has been part of the kernel since 2.4 (released January 2001). It exposes a set of *hooks* — `PREROUTING`, `INPUT`, `FORWARD`, `OUTPUT`, `POSTROUTING` — that the kernel calls for every packet as it traverses the stack. A firewall ruleset, regardless of which command-line tool wrote it, ultimately registers callbacks against those hooks.

For two decades the front-end tool was **iptables**. Since 2014 the supported front-end is **nftables**, which talks to the same hooks via a newer kernel API (`nf_tables`) that fixes structural problems with iptables: separate `iptables` and `ip6tables` binaries, sequential rule evaluation, no first-class sets or maps, no atomic ruleset reloads. nftables fixes all four.

This course teaches nftables. iptables still works; you will see it on legacy hosts; you should be able to read it. But the rules you *write* this week are nftables rules.

---

## 2. Stateless vs. stateful

Imagine the firewall as a doorman. The doorman has a list of who is allowed in and who is allowed out.

The **stateless** doorman checks each person at the door against the list, in isolation. Carlos shows up, the list says "Carlos may enter", in he goes. Later Carlos walks out, the list says "Carlos may leave", out he goes. So far so good.

The problem with the stateless doorman: imagine Carlos went in to ask a question and the answer is a reply Carlos carries back out. The doorman has to authorise *both directions* — Carlos walking in, and the reply walking out. If the doorman only has rules for one direction, the conversation deadlocks. So the policy ends up listing every direction of every conversation. That works for two or three flows; it does not work for the real internet, where the firewall is the doorman for thousands of simultaneous conversations.

The **stateful** doorman keeps a small notebook. When Carlos walks in legitimately, the notebook gets an entry: "Carlos entered at 14:23 for a conversation". When the *reply* to Carlos's conversation tries to leave, the doorman checks the notebook, sees the entry, and waves it through *without* needing a separate list entry. The conversation is *tracked*.

That notebook, in the Linux kernel, is called **conntrack** (connection tracking). It is the engine that makes a stateful firewall stateful.

```
+--------------+        request           +-------------+
|   inside     |  -------------------->   |   outside   |
|  host        |        reply             |             |
|              |  <--------------------   |             |
+--------------+                          +-------------+
       ^                                         ^
       |                                         |
       +----+   STATEFUL FIREWALL  +-------------+
            |                     |
            |  conntrack notebook |
            |  [tuple] -> state   |
            +---------------------+
```

The five-tuple that keys the conntrack table:

- **source IP**
- **destination IP**
- **source port** (or "type" for ICMP)
- **destination port** (or "code" for ICMP)
- **protocol** (TCP, UDP, ICMP, SCTP, ...)

The states the kernel tracks:

- `NEW` — the first packet of a flow that conntrack has not seen before.
- `ESTABLISHED` — packets belonging to a flow that conntrack has seen in both directions.
- `RELATED` — packets that are not part of the original flow but are *related* to one (FTP data channel for an FTP control connection; ICMP "destination unreachable" responses; etc.).
- `INVALID` — packets that conntrack cannot fit into any tracked flow.
- `UNTRACKED` — packets that the operator has explicitly excluded from tracking via the `raw` table.

The single most-copied line in modern Linux firewall rulesets:

```nft
ct state established,related accept
```

That line, placed at the top of an `input` chain, lets through every reply to every conversation the host initiated. It is the line that makes the rest of the ruleset short.

---

## 3. The nftables data model

nftables has a tree-shaped object model.

```
nft
├── table        (a container — chosen by address family)
│   ├── chain    (a hook + a default policy + a list of rules)
│   │   ├── rule (a match + a verdict)
│   │   ├── rule
│   │   └── ...
│   ├── set      (a named collection — IP addresses, ports, ...)
│   ├── map      (a named keyed lookup — verdict map, NAT map, ...)
│   └── counter  (a named statistics counter)
└── table
    └── ...
```

**Families.** A table belongs to one of these families:

- `ip` — IPv4 only.
- `ip6` — IPv6 only.
- `inet` — IPv4 and IPv6 in the same table. *Use this unless you have a reason not to.*
- `arp` — for ARP packets.
- `bridge` — for L2 packets traversing a Linux bridge.
- `netdev` — for very-early-stage filtering at the device driver layer.

For everything in this week, `inet` is the right family.

**Chain types and hooks.** A chain has a *type* and a *hook*:

- Type `filter`: drop/accept/log.
- Type `nat`: source/destination NAT.
- Type `route`: change routing decisions.

- Hook `prerouting`: before the routing decision (used for DNAT).
- Hook `input`: packets destined for the host.
- Hook `forward`: packets routed through the host.
- Hook `output`: packets originated by the host.
- Hook `postrouting`: after the routing decision (used for SNAT).

A chain also has a **priority** (a small integer) and a **policy** (`accept` or `drop`).

---

## 4. The minimal ruleset

Here is the smallest non-trivial nftables ruleset that does something useful — a workstation firewall.

```nft
#!/usr/sbin/nft -f

# Wipe whatever was there before. Atomic — the kernel swaps the new
# ruleset in only after the whole file parses.
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # Loopback is always trusted on a workstation.
        iif lo accept

        # Replies to outbound conversations.
        ct state established,related accept

        # Drop garbage.
        ct state invalid drop

        # ICMP ping (low rate, IPv4 + IPv6).
        icmp type echo-request limit rate 5/second accept
        icmpv6 type echo-request limit rate 5/second accept

        # IPv6 router advertisements and neighbour discovery — required.
        icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

Five things to notice about that file.

**One.** It is a *file*, not a sequence of `nft add rule` commands. The recommended workflow is to keep the ruleset in `/etc/nftables.conf` (or any other file) under version control, and apply it with `sudo nft -f /etc/nftables.conf`. The whole file applies atomically — either it all parses and the new ruleset replaces the old in one syscall, or nothing changes.

**Two.** `flush ruleset` at the top is non-negotiable. Without it, applying the file *appends* the rules to whatever was loaded before; reapply twice and you have duplicates.

**Three.** `policy drop` on `input` and `forward` is the **default-deny** posture. The chain executes top-to-bottom; if no rule explicitly accepts the packet, the policy applies. Default-accept on `output` is the workstation pattern — the host can talk to anything; the network controls egress at a different policy point. For a server, you flip `output` to `policy drop` and add an explicit egress allowlist.

**Four.** The order matters. `iif lo accept` first, because loopback traffic is most-trusted and most-frequent. `ct state established,related accept` second, because the bulk of accepted packets are replies. `ct state invalid drop` third, because the cheapest thing to do with a malformed packet is drop it without further evaluation.

**Five.** No rule explicitly accepts SSH. This is a deliberate choice for the workstation example: a workstation that does not need to accept inbound SSH should not. When you want to add SSH, you add one line — and then test it — and then test what happens when you make a typo. Section 8 covers the test pattern.

---

## 5. Verbs, matches, and verdicts

A rule has the shape:

```
[<match>] [<match>] ... <verdict>
```

A **match** narrows the set of packets the rule applies to. Examples:

- `ip saddr 192.168.1.0/24` — source IP in the /24.
- `tcp dport 22` — TCP destination port 22.
- `udp dport { 53, 67, 68 }` — UDP destination port in the anonymous set.
- `meta l4proto icmp` — protocol is ICMP.
- `ct state established,related` — conntrack state.
- `iif eth0` — input interface.
- `oif wg0` — output interface.

A **verdict** is the action:

- `accept` — let the packet through; stop evaluating this chain.
- `drop` — discard silently; stop evaluating this chain.
- `reject` — discard with an ICMP "administratively prohibited" reply (or a TCP RST for TCP).
- `queue` — hand to userspace (used by `suricata` in IPS mode, next lecture).
- `log` — log the packet to the kernel ring buffer; *do not stop evaluating*. Useful in front of a `drop` to record what was dropped.
- `counter` — increment a counter; *do not stop evaluating*. Useful for ad-hoc statistics.
- `jump <chain>` — jump to a user-defined chain. Returns when the called chain finishes.
- `goto <chain>` — like `jump` but does not return.
- `return` — return from a user-defined chain.

A small example combining several:

```nft
# Inbound SSH from the management subnet only, logged and rate-limited.
ip saddr 10.0.10.0/24 tcp dport 22 limit rate 10/minute log prefix "ssh-accept: " accept
```

That single rule does five things. It matches source IPv4 addresses in `10.0.10.0/24`, matches TCP destination port 22, rate-limits to ten per minute, logs every accepted packet with the prefix `ssh-accept: `, and accepts.

---

## 6. Sets and maps

The feature that makes nftables a real improvement over iptables is **named sets** and **named maps**. They make rulesets readable.

**Set** (a collection):

```nft
set trusted_admins {
    type ipv4_addr
    elements = { 10.0.10.5, 10.0.10.7, 10.0.10.12 }
}

chain input {
    type filter hook input priority filter; policy drop;
    ip saddr @trusted_admins tcp dport 22 accept
}
```

When you add a new admin, you edit the set, not the rules.

**Map** (a key-to-verdict lookup):

```nft
map port_to_verdict {
    type inet_service : verdict
    elements = {
        22  : accept,
        80  : accept,
        443 : accept,
        25  : drop,
    }
}

chain input {
    type filter hook input priority filter; policy drop;
    tcp dport vmap @port_to_verdict
}
```

A single `vmap` rule replaces a long ladder of `if dport == X then accept`.

Sets and maps can be **dynamic** — populated at runtime — which is how rate-limit-per-source rules work:

```nft
set ssh_offenders {
    type ipv4_addr
    flags dynamic, timeout
    timeout 1h
}

chain input {
    type filter hook input priority filter; policy drop;

    # If we already know this address is offending, drop.
    ip saddr @ssh_offenders drop

    # If we see more than five new SSH attempts in a minute from
    # the same source, add it to the offenders set and drop.
    tcp dport 22 ct state new \
        meter ssh_meter { ip saddr limit rate 5/minute } accept

    tcp dport 22 ct state new add @ssh_offenders { ip saddr timeout 1h } drop
}
```

The `meter` keyword tracks per-source rates without you having to write a custom datastructure. Exercise 3 walks this rule pattern in detail.

---

## 7. Default-deny, in detail

The **default-deny** posture is the single most important architectural decision in a firewall ruleset. It is the difference between "I have to think about every threat I want to block" and "I have to think about every flow I want to allow".

The first formulation is hopeless: the threat surface is unbounded, you cannot enumerate it. The second is tractable: the set of flows your host actually needs is small, you *can* enumerate it.

The mechanics in nftables: set `policy drop` on the chain, and only the rules that explicitly accept will let traffic through.

The **server-style egress filter** is the same posture applied to the `output` chain:

```nft
chain output {
    type filter hook output priority filter; policy drop;

    # Loopback.
    oif lo accept

    # Replies to inbound conversations.
    ct state established,related accept

    # DNS to the resolver.
    ip daddr 10.0.0.53 udp dport 53 accept
    ip daddr 10.0.0.53 tcp dport 53 accept

    # NTP to two well-known pools.
    ip daddr { 162.159.200.1, 162.159.200.123 } udp dport 123 accept

    # HTTPS to the upstream package mirror and the monitoring endpoint only.
    ip daddr @allowed_https_destinations tcp dport 443 accept

    # Everything else: drop, with a log line for the operator to read.
    log prefix "egress-drop: " drop
}
```

That ruleset is the practical mitigation for half the modern attacker playbook. An adversary who lands a shell on this host *cannot* phone home to a command-and-control server they did not pre-register in `allowed_https_destinations`. The cost is operational: you have to keep the allowlist up to date as legitimate destinations change.

The cost is real but bounded. The benefit is enormous. Exercise 2 walks the construction of an `allowed_https_destinations` set for a small Linux server.

---

## 8. Testing rulesets without locking yourself out

Every network engineer has applied a firewall ruleset to a remote host and discovered, two seconds later, that they cannot log back in. The recovery options are: drive to the data centre, ask the cloud provider for serial console access, or wait for a reboot to restore a known-good config.

The canonical pattern that avoids the lockout:

```bash
# Step 1: stage the new ruleset in a file.
sudo cp /etc/nftables.conf /etc/nftables.conf.bak
sudo cp new-ruleset.nft /etc/nftables.conf

# Step 2: schedule a revert in ten minutes.
# If we cancel the at job inside ten minutes, the revert never happens.
echo 'nft -f /etc/nftables.conf.bak' | sudo at now + 10 minutes

# Step 3: apply the new ruleset.
sudo nft -f /etc/nftables.conf

# Step 4: re-connect from a fresh terminal, verify SSH works,
# verify the services you need work. THEN:
sudo atrm <the-job-id>   # the id printed by step 2

# If you cannot reconnect in step 4, do nothing — the at job
# will revert in ten minutes and you can try again.
```

The pattern is a *belt-and-braces* recovery. It does not save you from a kernel panic and it does not save you from a rule that drops the `at` daemon's own UDP traffic. It saves you from the 95% case of "I forgot to allow port 22".

Exercise 1 ships this pattern as a small shell wrapper. The mini-project's runbook section includes it.

---

## 9. Connection tracking deep-dive

The conntrack table is the engine; it is worth thirty minutes of attention.

**Inspecting the live table.** Install `conntrack-tools` (`sudo apt install conntrack`) and run:

```bash
sudo conntrack -L
```

The output is one line per tracked flow. The columns: protocol, protocol-number, timeout-remaining, state, then two repeated "five-tuple" blocks — one for the original direction, one for the reply direction.

```
tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=140.82.114.4 sport=51230 dport=443 \
                              src=140.82.114.4 dst=10.0.0.5 sport=443 dport=51230 \
                              [ASSURED] mark=0 use=2
```

That line means: a TCP flow from `10.0.0.5:51230` to `140.82.114.4:443` is established; the reply direction is `140.82.114.4:443 -> 10.0.0.5:51230`; the flow is marked `ASSURED` (both directions have seen real traffic, so the entry will not be evicted under pressure).

**Memory.** The table has a maximum size. On a stock kernel, `nf_conntrack_max` defaults to about 65 536 entries on a small system and 262 144 on a larger one. Each entry costs roughly 300 bytes; a saturated table costs about 80 MB on a small system. Workloads that exceed the limit get the `nf_conntrack: table full, dropping packet.` message in `dmesg`. The fix is to raise `nf_conntrack_max` via `sysctl`.

**Timeouts.** The kernel evicts conntrack entries when they idle past a timeout. The defaults:

- TCP ESTABLISHED: 5 days (`nf_conntrack_tcp_timeout_established`)
- TCP CLOSE_WAIT: 60 seconds
- UDP: 30 seconds (`nf_conntrack_udp_timeout`)
- ICMP: 30 seconds

The 5-day TCP timeout is a historical default. Modern advice is to drop it to 1 day or even 1 hour for hosts with high connection churn.

**Disabling conntrack.** The `raw` table in nftables can mark packets as untracked, which bypasses conntrack entirely:

```nft
table inet raw {
    chain prerouting {
        type filter hook prerouting priority raw;
        ip daddr 10.0.0.10 tcp dport 443 notrack
    }
}
```

This is a *performance* optimisation for very-high-throughput servers (load balancers, CDN edge nodes, DNS resolvers) where the connection-tracking cost is the dominant overhead. It is *not* something a workstation or a small server should do, because every notrack rule is a hole in your stateful policy.

---

## 10. NAT — briefly

NAT is the mechanism that lets multiple internal addresses share one external address. It is the reason your home network has hosts at `192.168.1.5` and `192.168.1.7` but the internet sees only your ISP-assigned address.

NAT is *not* a security control. It is a routing trick. The reason it sometimes looks like a security control is that the home router that does the NAT is *also* a stateful firewall, and the firewall does the security work.

In nftables, NAT is a chain type:

```nft
table inet nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;
        # Destination NAT: forward inbound port 80 to an internal server.
        iif eth0 tcp dport 80 dnat to 192.168.1.10:80
    }

    chain postrouting {
        type nat hook postrouting priority srcnat;
        # Source NAT: rewrite outbound traffic to use the gateway's IP.
        oif eth0 masquerade
    }
}
```

The `masquerade` verdict is the canonical "rewrite the source IP to whatever this interface's current address is" — the home-router pattern. The `dnat to <addr>:<port>` verdict is the canonical "port-forward" pattern.

NAT is in the lecture because the mini-project's gateway uses it. NAT is not in the lecture as a security control, because it is not one.

---

## 11. Rate-limiting in the cold light of day

The `limit` keyword and the `meter` keyword are how nftables expresses "no more than N packets per unit time".

```nft
# At most ten ICMP echo-requests per second, with a burst of five.
icmp type echo-request limit rate 10/second burst 5 packets accept

# Per-source limit: at most three new SSH connections per minute per source IP.
tcp dport 22 ct state new \
    meter ssh_meter { ip saddr limit rate 3/minute } accept
```

The honest caveat: rate-limiting hardens against the noise floor. A casual scanner that probes a thousand hosts per minute will get caught. A targeted attacker who probes once per hour from a fresh IP, day after day, will not. A distributed botnet that probes once per source IP will not.

The right way to think about a rate-limit: it shifts the attacker's economics from "free" to "have to coordinate across N IPs". For ambient-internet noise, that shift is enough. For motivated targeted attack, it is not. Combine rate-limits with: an IDS that catches the slow attempts in aggregate (Lecture 2), strong authentication that survives a successful connection (key-based SSH, 2FA), and segmentation that limits what an authenticated session can reach (Lecture 3).

---

## 12. Observability

A firewall you cannot inspect is one you cannot trust.

**See the live ruleset:**

```bash
sudo nft list ruleset
```

The output is a re-rendering of the loaded ruleset in nftables syntax. It is the source of truth for what the kernel is currently enforcing.

**See rule hit counters:**

```bash
sudo nft list ruleset -a
```

The `-a` adds the rule handle. Add `counter` to a rule (`counter accept`) and the count of packets/bytes hit by that rule will appear in `list ruleset -a` output.

**Live tail of dropped traffic, when you have `log` rules:**

```bash
sudo journalctl -kf | grep nft-drop
```

A `log prefix "nft-drop: "` rule in the chain logs to the kernel ring buffer; `journalctl -k` shows the kernel ring buffer; `-f` follows it.

**See conntrack live:**

```bash
sudo conntrack -E    # stream events as they happen
sudo conntrack -L    # snapshot of the table
```

Build a habit during Exercise 1: every time you change a rule, immediately run `nft list ruleset` to confirm the kernel sees what you intended. The cost is two seconds; the cost of *not* doing it is a four-hour debugging session.

---

## 13. nftables vs. iptables — translating the canonical patterns

| Pattern                                | iptables                                          | nftables                                                       |
|----------------------------------------|---------------------------------------------------|----------------------------------------------------------------|
| Drop everything inbound                | `iptables -P INPUT DROP`                          | `chain input { policy drop; }` in the file                     |
| Allow loopback                         | `iptables -A INPUT -i lo -j ACCEPT`               | `iif lo accept`                                                |
| Allow established                      | `iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT` | `ct state established,related accept`           |
| Allow SSH                              | `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`   | `tcp dport 22 accept`                                          |
| Masquerade outbound on eth0            | `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE` | `chain postrouting { oif eth0 masquerade }`                |
| Save rules across reboot               | `iptables-save > /etc/iptables/rules.v4`          | `systemctl enable --now nftables` reads `/etc/nftables.conf`   |
| IPv6 equivalents                       | parallel `ip6tables` commands                     | same `inet` rule applies to both families                      |

The translation is usually straightforward. The cases where it is not — `xtables` extensions that nftables does not have a direct equivalent for — are increasingly rare. The nftables wiki has a dedicated migration page that lists every iptables module and its nftables equivalent.

---

## 14. Where iptables still appears

Three places. Know them so they do not surprise you.

**One: Docker.** Docker writes iptables rules to implement container networking. Modern Docker (24.x+) understands nftables but still emits iptables-compatible rules through the `iptables-nft` shim. You can usually leave Docker alone and run your own nftables ruleset alongside; the shim makes them coexist.

**Two: Kubernetes.** Kubernetes' `kube-proxy` in iptables mode writes iptables rules. The `nftables` mode for `kube-proxy` shipped in Kubernetes 1.29 (December 2023) and is stable enough to use as of 2026. Most clusters still default to iptables mode.

**Three: fail2ban.** fail2ban historically emits iptables commands; modern versions (1.0+) support nftables natively via the `nftables-allports` and `nftables-multiport` actions. Configure fail2ban to use nftables on a host that uses nftables for its base ruleset, or the two will fight each other.

---

## 15. One canonical workstation ruleset

The ruleset below is the one you should be able to write from memory by the end of this week. It is the starting point for Exercise 1 and the baseline that the mini-project's host policies extend.

```nft
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    set scanners {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1h
    }

    chain input {
        type filter hook input priority filter; policy drop;

        iif lo accept
        ct state established,related accept
        ct state invalid counter drop

        # ICMP echo, IPv4 and IPv6, rate-limited.
        icmp type echo-request limit rate 5/second accept
        icmpv6 type echo-request limit rate 5/second accept
        icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query } accept

        # Auto-add scanners (anyone connecting to closed ports too often)
        # to the timeout-set, and drop them on sight.
        ip saddr @scanners drop
        ct state new tcp dport != { 22 } limit rate over 10/second add @scanners { ip saddr timeout 1h } drop

        # SSH from the management subnet only, rate-limited.
        ip saddr 10.0.10.0/24 tcp dport 22 ct state new limit rate 5/minute accept

        # Log everything that falls through, then policy drop catches it.
        limit rate 5/second log prefix "nft-drop: "
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

Read each line, decide whether you would add it to a host you own, and edit the ruleset accordingly. The exercise asks you to do exactly that.

---

## 16. Summary

- A firewall is a policy-enforcement point. The policy is a list of allowed flows; the enforcement is the kernel.
- Linux's firewall subsystem is **netfilter**; the modern front-end is **nftables**; the legacy front-end is **iptables**.
- **Stateful** firewalls track flows in the **conntrack** table; **stateless** firewalls do not. Every modern host firewall is stateful.
- The **default-deny** posture is the only sane starting point for a non-trivial ruleset.
- **Egress filtering** on a server is the highest-leverage single control against modern attacker tradecraft.
- **Rate-limits** harden against ambient noise; they do not stop motivated attack.
- **Test rulesets** with a scheduled-revert pattern. Every network engineer has locked themselves out at least once; you can plan for it.
- **Read your ruleset live** with `nft list ruleset`, your conntrack with `conntrack -L`, your drops with `journalctl -kf | grep nft-drop`. Observability you cannot afford to skip.

Next: Lecture 2 on Suricata. The firewall decides whether to *let a packet through*. Suricata decides whether to *alert on a packet that went through*. They are complementary.

---

## References cited inline

- The Netfilter Project. *nftables Wiki.* https://wiki.nftables.org/
- The Netfilter Project. *netfilter Documentation.* https://netfilter.org/documentation/
- Linux kernel documentation, netfilter sysctl. https://www.kernel.org/doc/html/latest/networking/netfilter-sysctl.html
- Leblond, Eric. *Why you will love nftables.* 2014. https://home.regit.org/2014/01/why-you-will-love-nftables/
- conntrack-tools project. https://conntrack-tools.netfilter.org/
- NIST Special Publication 800-41 Rev. 1, *Guidelines on Firewalls and Firewall Policy.* https://doi.org/10.6028/NIST.SP.800-41r1
