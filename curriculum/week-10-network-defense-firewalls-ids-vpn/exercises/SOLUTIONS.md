# Week 10 — Exercise Solutions

> Walkthroughs, expected output, and the most-common debugging paths for each of the five exercises. Read the corresponding exercise file before reading the solution; the goal of the solution is to confirm your work, not to substitute for the attempt.

---

## Exercise 1 — Workstation Host Firewall

### What the exercise asks

Produce a default-deny nftables ruleset for a Linux workstation that:

- permits inbound replies to outbound conversations,
- permits inbound SSH from a single management subnet,
- permits ICMP echo (ping) at a sane rate,
- permits IPv6 neighbour discovery,
- logs and drops everything else,
- auto-populates a dynamic `@scanners` set for repeat offenders.

### What "done" looks like

After applying the ruleset:

```bash
sudo nft list ruleset
```

shows the `inet filter` table with the four sets (`scanners`, `mgmt_v4`) and three chains (`input` with `policy drop`, `forward` with `policy drop`, `output` with `policy accept`).

From a host *inside* the management subnet, `ssh user@your-host` succeeds. From a host *outside* the management subnet, `ssh user@your-host` hangs or refuses; after five attempts within a minute the source IP appears in `@scanners`:

```bash
sudo nft list set inet filter scanners
# Expect to see the offending IP with a timeout countdown.
```

`ping your-host` succeeds at a low rate. `ping -f your-host` (flood ping) shows packet loss past five per second.

`sudo journalctl -kf | grep nft-drop-in` streams drop events.

### Common pitfalls

- **Locked yourself out of SSH.** The `at`-job pattern from Lecture 1 section 8 is the recovery: `echo 'nft flush ruleset' | sudo at now + 10 minutes` *before* the apply. If you skipped it and locked out, you wait for the next reboot or you cancel the rule from the console.
- **Forgot `iif lo accept`.** Many local services (DNS resolver stub, systemd-resolved, postgres on a Unix socket, etc.) actually depend on loopback IP traffic. Without `iif lo accept`, those break in surprising ways.
- **Default-policy on `output` set to `drop`.** This is the *server* pattern (Exercise 2), not the *workstation* pattern. On a workstation, `output` should be `accept`. Setting it to `drop` here will break your network access without you understanding why.
- **`ct state established,related accept` placed after a `drop` rule.** Order matters. The established-replies rule has to be near the top.

### Verifying behaviour

```bash
# Apply, with a scheduled revert.
sudo cp /etc/nftables.conf /etc/nftables.conf.bak 2>/dev/null
echo "nft flush ruleset; nft -f /etc/nftables.conf.bak 2>/dev/null || true" \
    | sudo at now + 10 minutes
sudo nft -f exercise-01-host-firewall.nft

# Verify.
sudo nft list ruleset
sudo ss -tunlp     # processes listening on ports
sudo ss -tn state established   # established connections

# Generate some drops.
ping -c 200 -f 127.0.0.1 || true        # local flood ping (rate-limit fires)
nmap -p 22,80,443 your-host             # from a non-mgmt host

# Inspect the scanner set.
sudo nft list set inet filter scanners

# Cancel the revert.
sudo atq                # find the job id
sudo atrm <job-id>
```

If everything above behaves as described, the exercise is done.

---

## Exercise 2 — Server-Style Egress Allowlist

### What the exercise asks

Produce an nftables ruleset for a small Linux server that enforces default-deny on **both** input *and* output, with an explicit allowlist of egress destinations.

### What "done" looks like

After applying:

- `sudo apt update` works (the package mirror is in `@allowed_mirror`).
- `ntpdate -q time.cloudflare.com` works (Cloudflare time is in `@allowed_ntp`).
- The application the server hosts responds to inbound requests (port 80/443 accepted on `input`).
- `curl https://random-internet-host.example/` fails with a timeout or "no route to host", and a `nft-drop-egress:` line appears in the kernel ring buffer.

### The fully-worked allowlist

The exercise leaves four sets for you to fill (`allowed_dns`, `allowed_ntp`, `allowed_https`, `allowed_mirror`). A worked example for an Ubuntu 24.04 web server:

```nft
set allowed_dns {
    type ipv4_addr
    elements = { 10.0.0.53, 1.1.1.1, 9.9.9.9 }
}

set allowed_ntp {
    type ipv4_addr
    elements = { 162.159.200.1, 162.159.200.123 }
}

set allowed_https {
    type ipv4_addr
    elements = {
        # Your monitoring backend.  TODO: pin actual IPs after a DNS
        # lookup, refresh on a schedule.
        # Example placeholder addresses:
        140.82.112.0/20,    # GitHub (for git clones, if needed)
        185.199.108.0/22    # GitHub Pages / api
    }
}

set allowed_mirror {
    type ipv4_addr
    elements = {
        91.189.91.81,
        91.189.91.82,
        185.125.190.36,
        185.125.190.39
    }
}
```

### The right way to populate the sets

DNS-resolve the destinations once on a known-good host:

```bash
dig +short archive.ubuntu.com
dig +short security.ubuntu.com
dig +short monitor.example.com
```

Pin those IPs into the allowlist. Refresh on a schedule (weekly is fine for most mirrors); rotate the set with `nft replace element` or with `suricata-update`-style tooling that rewrites the whole set atomically.

### Common pitfalls

- **Pinning IPs that drift.** Cloud-hosted destinations (S3, GitHub) change IPs frequently. The honest mitigation is to allow a `/16` or `/22` range — losing some isolation — or to refresh the set on a schedule.
- **Forgetting outbound NTP.** Time drift breaks TLS certificate validation. If clocks drift more than a few minutes, every HTTPS connection fails with a confusing error. Include NTP in the allowlist.
- **Forgetting outbound DNS.** Without DNS, nothing else works. Verify the resolver IP is correct *before* applying. If you use systemd-resolved with a local stub (127.0.0.53), the queries go to loopback first and then to the upstream resolver; allow loopback and the upstream.

### Verifying behaviour

```bash
# Apply (with the at-revert pattern from Exercise 1).
sudo nft -f exercise-02-egress-allowlist.nft

# Should work:
sudo apt update
sudo ntpdate -q time.cloudflare.com
curl https://monitor.example.com/health

# Should NOT work (and should log):
curl --max-time 5 https://random-internet-host.example/  ; echo "exit=$?"
# expect exit != 0; expect log line
sudo journalctl -kf | grep nft-drop-egress
```

---

## Exercise 3 — SSH Rate-Limit Driver

### What the exercise asks

Apply a per-source SSH rate-limit in nftables; simulate a burst; confirm the offender lands in `@scanners`; tear the rule down on exit.

### What "done" looks like

The script runs end-to-end without error. The early "attempt 1..5" complete; the later "attempt 6..10" are blocked. The final `nft list set` output shows `127.0.0.1` (or your local test IP) with a timeout countdown of just under 1 hour.

### Why the localhost test is fragile

A subtlety the exercise's own README warns about: depending on kernel configuration, packets to `127.0.0.1` may bypass the `input` chain of the `inet` family because they never traverse the netfilter input hook for an external interface. The reliable test is from a *second host*:

```bash
# From a second host on the LAN, against the host that applied the rule:
for i in {1..10}; do
    timeout 2 nc -zv target-host 22
done

# On the target host:
sudo nft list set inet exercise03 scanners
```

If you only have one host, the exercise still demonstrates the *mechanic* (the rule is loaded, the meter exists, the set exists) even if the burst does not always trip the meter on the loopback path.

### Common pitfalls

- **Running as a non-root user.** `nft` requires CAP_NET_ADMIN. The script checks at startup and exits cleanly; you should not see the error past the pre-flight.
- **Stale table from a prior run.** The `trap cleanup EXIT` deletes the table at exit; if a prior run was force-killed (`Ctrl-C` repeatedly, `kill -9`), the table may remain. Remove with `sudo nft delete table inet exercise03` and retry.
- **`meter` syntax errors on older nftables.** The `meter` keyword requires nftables 0.9 or newer. Check with `nft --version`; the modern syntax is what the script uses.

### What the exercise is *not* a demonstration of

The script proves that a single-source brute-force trips the rule. It does *not* prove resilience against a distributed brute-force from a botnet. The "honest caveat" note in the script's output is the take-away: rate-limiting is one of several layers.

---

## Exercise 4 — Suricata Tuning

### What the exercise asks

Apply tuning fragments to `suricata.yaml`, `disable.conf`, and `threshold.config`. Restart Suricata. Verify the alert stream is smaller and more relevant.

### What "done" looks like

`sudo systemctl status suricata` is healthy.

`sudo journalctl -u suricata --since "5 minutes ago"` shows no parse errors.

`/var/log/suricata/eve.json` contains alert records.

The top-10 signatures by frequency, queried after one hour of running, no longer include any of the categories you disabled or the SIDs you suppressed:

```bash
sudo tail -n 200000 /var/log/suricata/eve.json \
    | jq -r 'select(.event_type=="alert") | .alert.signature_id' \
    | sort | uniq -c | sort -rn | head -10
```

### The first tuning iteration, walked

After day one, you will see a top-10 that looks something like:

```
   142 2010935   ET SCAN Suspicious inbound to mySQL port 3306
    96 2022071   ET POLICY Possible HTTP 401 XMLHttpRequest (Brute Force)
    87 2027865   ET INFO Observed DNS over HTTPS Domain (cloudflare-dns.com)
    71 2024897   ET INFO Possible SSL Server Header
    65 2030013   ET SCAN Nmap NSE Heartbleed Response
    ...
```

For each, decide:

- **2010935 (mySQL scan).** If you do not run MySQL on the perimeter, the alert is informational; threshold it to one alert per source per hour:
  ```
  event_filter gen_id 1, sig_id 2010935, type both, track by_src, count 1, seconds 3600
  ```
- **2022071 (HTTP 401 XMLHttpRequest).** This often fires on a SPA's normal auth-check path. Suppress when source is your own users:
  ```
  suppress gen_id 1, sig_id 2022071, track by_src, ip 10.0.10.0/24
  ```
- **2027865 (DNS-over-HTTPS to Cloudflare).** Almost certainly your own browsers. Suppress entirely if DoH is policy on your network:
  ```
  suppress gen_id 1, sig_id 2027865
  ```
- **2024897 (SSL server header).** Pure information; suppress:
  ```
  suppress gen_id 1, sig_id 2024897
  ```
- **2030013 (Nmap NSE Heartbleed Response).** Real signal — *someone is probing you for Heartbleed*. Leave enabled. If it is your own pentesting from inside the management subnet, suppress for that source only.

After three of these iterations, the top-10 reduces to handful of alerts per day that genuinely deserve attention.

### Common pitfalls

- **YAML indentation errors.** Suricata uses standard YAML; tab characters and inconsistent indentation are silent landmines. Validate with `yamllint suricata.yaml` before restarting Suricata.
- **`HOME_NET` left at the default.** The default lists every private IP space. Narrow it to the subnets you actually use; signatures depend on it for direction.
- **Forgot to run `suricata-update`.** Editing `disable.conf` has no effect until `suricata-update` re-merges the rule files. Run it on a cron — daily is the recommendation.

---

## Exercise 5 — WireGuard Keygen

### What the exercise asks

Run the keygen script. Inspect the output. Use the printed snippets to onboard a new peer to a WireGuard deployment.

### What "done" looks like

```bash
python3 exercise-05-wireguard-keygen.py "carlos-laptop" \
    --output-dir ~/wg/peers \
    --client-address 10.10.0.5/32 \
    --server-endpoint vpn.example.com:51820 \
    --server-public-key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX= \
    --full-tunnel
```

prints a server `[Peer]` block and a client `wg0.conf`. The files in `~/wg/peers/` are:

```
carlos-laptop.private  (mode 0600)
carlos-laptop.public   (mode 0644)
```

The mode check at the end of the script output reads `0600` for the private key. If it reads `0644`, the umask hijacked the write; the script's `os.chmod` re-enforce should prevent this — if it does not, your filesystem may not support POSIX modes (overlayfs in some container setups loses mode information).

### Onboarding the peer

1. Run the script with the right arguments.
2. Append the printed `[Peer]` block to `/etc/wireguard/wg0.conf` on the server.
3. Atomic reload: `sudo wg syncconf wg0 <(wg-quick strip wg0)`. The `syncconf` form adds the new peer without disrupting existing tunnels.
4. Copy the printed client `wg0.conf` to the peer device (USB drive, signal-message, QR code generated with `qrencode -t ansiutf8 < wg0.conf`).
5. On the client device, `sudo wg-quick up wg0`.
6. Verify: `sudo wg show` on both sides; the new peer has a recent handshake.

### Common pitfalls

- **`wg` not installed.** The script checks at startup. Install `wireguard-tools`.
- **Wrong server public key.** The most-common typo is to paste the *server's private* key into `--server-public-key`. The script validates the shape (43 base64 chars + `=`) but cannot tell a private key from a public key — both are 32 bytes base64. Double-check on the server: `sudo cat /etc/wireguard/wg0.conf` shows the server's private key; the public key is what `wg pubkey < /etc/wireguard/server.private` prints.
- **`--client-address` outside the server's overlay.** If the server config is `Address = 10.10.0.1/24`, then the client address must be in `10.10.0.0/24`. If you give a client `10.20.0.5/32`, the tunnel comes up but nothing routes.
- **Committed the private-key file.** The repository's `.gitignore` excludes `*private*` patterns. If you write a private key to a path that does not match the pattern, you can commit it by accident. The mini-project README has a `git-secrets`-style pre-commit hook that fails on any 32-byte base64 string.

### Authorisation reminder

The script's `--help` output ends with the authorised-use disclaimer. Read it once on first run. Onboarding a peer to a network you do not own is exactly the unauthorised-deployment scenario the README's banner warns against.

---

## Summary table

| # | File                                | Pass criterion                                                              |
|---|-------------------------------------|-----------------------------------------------------------------------------|
| 1 | `exercise-01-host-firewall.nft`     | Default-deny applies; SSH works from mgmt subnet; ping rate-limit fires.    |
| 2 | `exercise-02-egress-allowlist.nft`  | Allowed destinations reach; unallowed destinations log + drop.              |
| 3 | `exercise-03-ssh-rate-limit.sh`     | Script runs clean; offender lands in `@scanners`; cleanup runs on exit.     |
| 4 | `exercise-04-suricata-tuning.yaml`  | Suricata restarts clean; top-10 noise SIDs reduce after one tuning cycle.   |
| 5 | `exercise-05-wireguard-keygen.py`   | Keypair written with 0600/0644 modes; server + client snippets render OK.   |

When all five pass, move to the challenges.
