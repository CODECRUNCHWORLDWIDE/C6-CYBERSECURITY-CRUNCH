# Allowed-Flow Matrix — TEMPLATE

> Square matrix of permitted flows between segments. Cell value is one of: `any`, `deny`, `via jump host`, or a specific protocol+port list. Each "allow" must be justifiable by a business or operational need; each "deny" must be intentional, not an omission.

---

## Matrix

|                | trusted          | dmz              | guest    | iot              | vpn              | WAN                            |
|----------------|------------------|------------------|----------|------------------|------------------|--------------------------------|
| **trusted**    | any              | tcp 22 / app     | deny     | tcp 631, 9100    | tcp 22 → jump    | tcp 80,443, udp 53, udp 123    |
| **dmz**        | deny             | any              | deny     | deny             | deny             | tcp 80,443, udp 53, udp 123    |
| **guest**      | deny             | deny             | any      | deny             | deny             | tcp 80,443, udp 53             |
| **iot**        | tcp 631,9100 ack | deny             | deny     | any              | deny             | tcp 443, udp 53                |
| **vpn**        | via jump host    | deny             | deny     | deny             | n/a              | full or split (see policy)     |

(The matrix above is a worked example for a four-segment + VPN home network. **Edit it to match your network.** Delete rows for segments you do not have.)

---

## Justification per row

### trusted → *

- **trusted → trusted: any.** Workstations talk to each other freely (printer, file sharing).
- **trusted → dmz: tcp 22 + app ports.** Administrators reach the DMZ-hosted services to administer them.
- **trusted → guest: deny.** No reason for trusted hosts to reach the guest network.
- **trusted → iot: tcp 631 (CUPS) and 9100 (HP JetDirect).** Print to networked printers on the IoT segment.
- **trusted → vpn: tcp 22 → jump host.** Trusted hosts may SSH to the jump host (admins iterating from the office).
- **trusted → WAN: tcp 80,443, udp 53, udp 123.** Web browsing, DNS, NTP.

TODO: edit each justification to match your environment. Delete justifications for flows you have set to `deny`.

### dmz → *

- **dmz → trusted: deny.** Compromise of the DMZ must not reach the trusted segment.
- **dmz → dmz: any.** Internal DMZ flows.
- **dmz → guest: deny.** No business reason.
- **dmz → iot: deny.** No business reason.
- **dmz → vpn: deny.** No business reason.
- **dmz → WAN: tcp 80,443, udp 53, udp 123.** Updates and time.

### guest → *

- **guest → trusted: deny.** Guests must not reach internal infrastructure.
- **guest → dmz: deny.** Guests are not authorised to administer.
- **guest → guest: any.** Guests may talk to each other (or you can deny — your call).
- **guest → iot: deny.** No reason; IoT is more sensitive than it sounds.
- **guest → vpn: deny.** Guests cannot bridge into the VPN.
- **guest → WAN: tcp 80,443, udp 53.** General internet. *NTP is optional.*

### iot → *

- **iot → trusted: only tcp 631 and 9100 (printer return traffic — established only).** Treat as a deny except for the established connection back from the printer.
- **iot → dmz: deny.** No reason.
- **iot → guest: deny.** No reason.
- **iot → iot: any.** Internal IoT broadcasts (Apple Bonjour, etc.).
- **iot → vpn: deny.** No reason.
- **iot → WAN: tcp 443, udp 53.** IoT vendors phone home over HTTPS. *Acknowledge the limitation:* you have no visibility into what data is in the HTTPS flows; the mitigation at this layer is incomplete.

### vpn → *

- **vpn → trusted: via jump host only.** The only legitimate entry-point for VPN admin is the bastion at `10.0.10.5`.
- **vpn → dmz: deny.** VPN clients should not administer DMZ services directly.
- **vpn → guest: deny.** No reason.
- **vpn → iot: deny.** No reason.
- **vpn → WAN: full or split.** Depends on the client config; see `wg0-*-template.conf`.

---

## Flows that are *not* in the matrix

This is the place to enumerate flows that you considered and decided not to allow, *with the reasoning*. Examples:

- *iot → trusted: bidirectional SMB for backup-to-NAS.* Considered; rejected because the backup-to-NAS device on the IoT segment is a black-box vendor product that has shown CVEs in the past. Mitigation: take backups from the trusted segment pulling from the IoT device, not pushing.

TODO: add at least three considered-but-rejected flows. They are evidence of deliberate design.
