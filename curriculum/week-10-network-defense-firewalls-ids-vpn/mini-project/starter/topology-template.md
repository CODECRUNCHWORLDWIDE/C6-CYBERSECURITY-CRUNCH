# Topology and Addressing Plan — TEMPLATE

> AUTHORIZED USE ONLY. This document describes a network the author owns or is authorised to administer. See week README.

---

## Network: TODO — name your network here (e.g., "Home, Apt 4C")

Owner: TODO — your name or handle.
Last revised: TODO — ISO 8601 date.

---

## Topology

```
                    +-------------------+
                    |  ISP / WAN        |
                    +---------+---------+
                              |
                              v
              +---------------+---------------+
              |  GATEWAY (Linux box / Pi 5)   |
              |  WAN: eth0  (DHCP from ISP)   |
              |  LAN: eth1  (VLAN trunk)      |
              |  VPN: wg0   (UDP/51820)       |
              |  Sensor: suricata on eth0     |
              +-+-----+-----+-----+-----------+
                |     |     |     |
                v     v     v     v
              VLAN  VLAN  VLAN  VLAN
              10    20    30    40
            trusted DMZ  guest IoT
            10.0.10 10.0.20 10.0.30 10.0.40

         + WireGuard overlay: 10.10.0.0/24
         + jump host on trusted: 10.0.10.5
```

TODO: redraw this diagram so it matches **your** network. Remove the segments you do not have; add the ones you do.

---

## Addressing plan

| Segment   | VLAN | Subnet            | Gateway      | DHCP range                    | DNS         |
|-----------|-----:|-------------------|--------------|-------------------------------|-------------|
| trusted   | 10   | 10.0.10.0/24      | 10.0.10.1    | 10.0.10.100 – 10.0.10.200     | 10.0.10.1   |
| dmz       | 20   | 10.0.20.0/24      | 10.0.20.1    | 10.0.20.100 – 10.0.20.110     | 10.0.10.1   |
| guest     | 30   | 10.0.30.0/24      | 10.0.30.1    | 10.0.30.100 – 10.0.30.200     | 1.1.1.1     |
| iot       | 40   | 10.0.40.0/24      | 10.0.40.1    | 10.0.40.100 – 10.0.40.200     | 10.0.10.1   |
| vpn       |  —   | 10.10.0.0/24      | 10.10.0.1    | (static per peer)             | 10.0.10.1   |

TODO: edit subnets to match your environment. Choose subnets that do not collide with common defaults (192.168.0.0/24, 192.168.1.0/24, 10.0.0.0/24) so that VPN clients on other networks do not have routing conflicts.

---

## Interface inventory

| Interface | Role               | MTU  | Notes                                                |
|-----------|--------------------|-----:|------------------------------------------------------|
| eth0      | WAN                | 1500 | DHCP from ISP                                        |
| eth1      | LAN trunk          | 1500 | 802.1Q trunk to switch, VLANs 10/20/30/40            |
| eth1.10   | trusted (sub-if)   | 1500 |                                                      |
| eth1.20   | dmz (sub-if)       | 1500 |                                                      |
| eth1.30   | guest (sub-if)     | 1500 |                                                      |
| eth1.40   | iot (sub-if)       | 1500 |                                                      |
| wg0       | WireGuard overlay  | 1420 | UDP/51820; 1420 to leave 60 bytes for tunnel overhead |
| lo        | loopback           | 65536|                                                      |

---

## Host inventory (high-trust hosts only — do NOT list every device)

| Host         | Segment | Address     | Role                                   |
|--------------|---------|-------------|----------------------------------------|
| gateway      | (all)   | per-segment | nftables + Suricata + WireGuard        |
| bastion      | trusted | 10.0.10.5   | jump host for VPN-originated SSH       |
| TODO         | TODO    | TODO        | TODO                                   |

---

## Allowed-flow matrix

See `allowed-flows-template.md` (or paste here if you prefer a single document).

---

## Changes log

| Date       | Change                                        | By            |
|------------|-----------------------------------------------|---------------|
| YYYY-MM-DD | Initial revision                              | TODO          |
| YYYY-MM-DD | Added IoT segment                             | TODO          |

Maintain this log. Every edit to the ruleset that opens or closes a flow should add a row.
