# Week 10 — Homework

> Five graded exercises. The homework is the bridge between the worked exercises (which you should finish first) and the mini-project (which integrates everything). Each exercise has a defined deliverable; the pass criterion is in plain language at the bottom of each item. Submit by pull request to your fork.

---

## H1 — Document your current network (1 hour)

Before you change anything, write down what you have.

**Deliverable:** A file `homework/H1-current-state.md` containing:

- A topology diagram (ASCII is fine) of your current home or lab network. ISP, router, switch (if any), wireless access points, every device.
- An inventory table: device name, MAC address (last 6 hex digits are enough; do not commit full MAC if it identifies you in person), IP address, role, segment (or "flat" if you have only one).
- The current firewall posture. If you have a consumer router, "default — NAT only, no outbound filtering, no inbound except UPnP-opened ports" is the honest answer.
- A short paragraph identifying the **three highest-impact gaps** between your current state and the reference architecture in `lecture-notes/03`.

**Pass criterion:** A reviewer can read this document and form a mental model of your network in under two minutes. The three gaps are *specific* (e.g., "no segmentation; IoT thermostat shares a subnet with the laptop holding tax records") rather than abstract ("not enough security").

---

## H2 — Apply Exercise 1's ruleset to one host (45 minutes)

Take the `exercise-01-host-firewall.nft` ruleset, edit the `mgmt_v4` set to your real management subnet, and apply it to one host you own. Use the scheduled-revert pattern from Lecture 1 section 8.

**Deliverable:** A file `homework/H2-host-firewall.md` containing:

- The exact ruleset you applied (paste from your `/etc/nftables.conf`).
- The output of `sudo nft list ruleset` after applying.
- A short paragraph describing what changed for you operationally. (Anything broke? Anything you had to add to the allowlist? Anything you did not realise was reaching the host until it stopped reaching it?)

**Pass criterion:** The ruleset is default-deny on `input` and `forward`; SSH from your management subnet still works; the `@scanners` set exists and is populated by your test.

---

## H3 — Stand up Suricata on one interface (90 minutes)

Install Suricata on a host or a VM. Configure it to monitor one interface (your WAN, your LAN, or — if you have one — a span port). Pull the ET Open ruleset with `suricata-update`. Run Suricata for at least one full hour with real traffic on the network. Apply the tuning from Exercise 4 (disable irrelevant categories, suppress three noisy SIDs).

**Deliverable:** A file `homework/H3-suricata.md` containing:

- The `interface:` line from your `suricata.yaml` (with the actual interface name).
- The output of `sudo systemctl status suricata` confirming the service is healthy.
- A table of the top-10 alert SIDs by frequency after one hour of running, *before* tuning.
- A table of the top-10 alert SIDs by frequency after one hour of running, *after* tuning.
- A short paragraph describing what you tuned and why.

**Pass criterion:** The "after" table contains fewer pure-noise alerts than the "before" table. Three specific SIDs are explained in the paragraph: which categories they came from, why you decided to suppress or threshold them.

---

## H4 — Generate a WireGuard keypair and write the configs (45 minutes)

Use the keygen script from Exercise 5 to generate a keypair for a single new peer. Write the server `[Peer]` block. Write the client `wg0.conf`. Verify the modes on the private-key file. Do **not** commit any file with `private` or `psk` in the name.

**Deliverable:** A file `homework/H4-wireguard.md` containing:

- The command line you ran (with the *server's* public key redacted for posting, if you want; replace with `<SERVER-PUBKEY>` placeholder).
- The output of `ls -la ~/wg/peers/` showing the modes on the files.
- The server `[Peer]` block, with the peer's public key visible (public keys are not secrets).
- The client `wg0.conf`, with the **private** key redacted to `<CLIENT-PRIVKEY>` placeholder.
- A short paragraph: did the peer connect? `sudo wg show` output (you may redact the public keys to last 8 chars if you prefer).

**Pass criterion:** Mode on the `.private` file is `0600`. Mode on the `.public` file is `0644`. No private key or PSK is in the homework Markdown file. The `wg show` output shows a recent handshake.

---

## H5 — Write a 500-word "what I would change about my network" essay (60 minutes)

Now that you have done H1 through H4, write a short essay (target 500 words, hard cap 1 000) on the gap between where your network is now and where it would be if you took the reference architecture seriously. The essay should cover:

- **One thing you already do well.** Be honest; it is rarely zero.
- **The single highest-leverage change** you would make next, and why. Choose one. Be specific.
- **The biggest blocker** to making that change. (Cost? Time? Equipment? A family member who insists on a flat network? Lease restrictions on running cables?)
- **A timeline.** When could you, realistically, make the change? "Within a month" is fine; "in the next two years when I move" is fine; "never, because the constraint is permanent" is a legitimate answer if you justify it.

**Deliverable:** `homework/H5-roadmap.md`.

**Pass criterion:** The essay names *specific* changes, not abstract ones. "I would segment the network" is not specific. "I would put my smart TV and my Roomba on a separate VLAN by replacing my router with an OPNsense box on a 4-port mini-PC I have not yet ordered, and the blocker is that the cable from the closet to the living room runs through a wall I cannot drill into" is specific.

---

## Submission

A pull request to your fork of the curriculum repository, branch `week-10-homework-<your-handle>`, that adds the five files above under `week-10-network-defense-firewalls-ids-vpn/homework/`. The PR description summarises H5 in two sentences.

Do not commit:

- Any file with `private`, `psk`, or `secret` in the name.
- The full output of `sudo wg show` if it includes private keys (newer wg versions print the private key on the first line; redact before committing).
- Your full MAC addresses or your home's public IP, if those are identifying.

The graders are humans; if you are not sure whether something is OK to commit, ask in the channel before pushing.

---

## Time budget

If you spend more than seven hours on the homework set, you are over-engineering. The pass criteria are deliberately modest. The mini-project, which integrates these into a single network plan, is where the deeper work happens.
