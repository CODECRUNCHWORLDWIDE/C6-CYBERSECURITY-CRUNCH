#!/usr/bin/env bash
#
# Exercise 3 — SSH Rate-Limiting Driver
#
# AUTHORIZED USE ONLY.  Run this only against a host you own and
# administer.  See the week README banner.
#
# Goal: apply an SSH-brute-force mitigation in nftables and verify
# it works.  The rule pattern auto-populates a dynamic set with any
# source IP that exceeds five new SSH connection attempts per minute,
# and drops every subsequent packet from that source for an hour.
#
# This script:
#   1. Applies a small nftables fragment that adds the rate-limit rule.
#   2. Simulates a brute-force from localhost by making rapid SSH
#      connection attempts to port 22.
#   3. Inspects the @scanners dynamic set to confirm the offender
#      was caught.
#   4. Tears the test rule down on exit.
#
# USAGE:
#   sudo ./exercise-03-ssh-rate-limit.sh
#
# REQUIREMENTS:
#   nft >= 1.0, nc (netcat), bash >= 4
#
# REFERENCE: nftables wiki — https://wiki.nftables.org/
#            man 8 nft

set -euo pipefail

# ----- Pre-flight ------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: this script must be run as root (it modifies nftables)."
    echo "       sudo $0"
    exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
    echo "ERROR: 'nft' not found.  Install nftables (apt install nftables)."
    exit 1
fi

if ! command -v nc >/dev/null 2>&1; then
    echo "ERROR: 'nc' not found.  Install netcat (apt install netcat-openbsd)."
    exit 1
fi

echo "==> Pre-flight checks passed."

# ----- The nftables fragment -----------------------------------------

# We use a *named, throwaway* table so we cannot collide with the
# host's existing ruleset.  All inserts go into 'exercise03' and we
# delete that table at exit.
TABLE_NAME="exercise03"

cleanup() {
    echo "==> Cleaning up: deleting table '${TABLE_NAME}'."
    nft delete table inet "${TABLE_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Installing rate-limit ruleset into table '${TABLE_NAME}'."

nft -f - <<EOF
table inet ${TABLE_NAME} {
    set scanners {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1h
    }

    chain input {
        type filter hook input priority filter - 10; policy accept;

        # If we have already flagged the source, drop.
        ip saddr @scanners counter drop

        # Track new SSH attempts.  meter limits per-source rate.
        # An IP that exceeds five new SSH connections per minute is
        # added to the scanners set and all its future traffic dropped.
        tcp dport 22 ct state new \
            meter ssh_meter { ip saddr limit rate 5/minute } accept

        tcp dport 22 ct state new \
            add @scanners { ip saddr timeout 1h } \
            counter drop
    }
}
EOF

echo "==> Current ruleset (filtered to our table):"
nft list table inet "${TABLE_NAME}"

# ----- The simulated brute-force -------------------------------------

echo
echo "==> Simulating an SSH brute-force from localhost (10 attempts)."
echo "    The first five SHOULD succeed (TCP handshake).  Attempts six"
echo "    through ten SHOULD be dropped before the handshake completes."
echo

for i in $(seq 1 10); do
    # Use a very short timeout so each attempt does not block long.
    # We connect to 127.0.0.1:22 — even if sshd is not running, the
    # kernel will accept the TCP handshake then RST, which is enough
    # to count against our meter.
    if timeout 2 nc -zv 127.0.0.1 22 2>&1 | head -1; then
        echo "  attempt $i: TCP completed"
    else
        echo "  attempt $i: blocked or refused"
    fi
done

# ----- Inspect the result --------------------------------------------

echo
echo "==> Contents of the @scanners set after the burst:"
nft list set inet "${TABLE_NAME}" scanners

echo
echo "==> Counter on the drop rule (packets blocked because we flagged):"
nft list chain inet "${TABLE_NAME}" input

# ----- Verify a single explicit drop ---------------------------------

echo
echo "==> Sleeping 2 seconds so any final attempt is well past the rate."
sleep 2

echo
echo "==> Final attempt — should be in the dropped path:"
if timeout 2 nc -zv 127.0.0.1 22 2>&1 | head -1; then
    echo "  WARNING: final attempt completed — the rate-limit did not catch"
    echo "  it.  Inspect the meter and the timing.  Possible causes: localhost"
    echo "  may bypass the input chain depending on your kernel; try from a"
    echo "  remote host with a TCP client (e.g. nmap -p22 <this-host>) for a"
    echo "  more realistic test."
else
    echo "  final attempt blocked as expected."
fi

# ----- Honest caveat -------------------------------------------------

cat <<'NOTE'

NOTE on what this exercise demonstrates and what it does not:

  This rate-limit catches a single-source brute-force.  It does NOT
  catch a distributed brute-force from a botnet that uses a fresh IP
  per attempt — the per-source rate stays below the threshold by
  design.  In production you combine this control with:

    - SSH password authentication disabled (`PasswordAuthentication no`)
    - Key-only auth with a strong key (Ed25519 256-bit)
    - 2FA on the SSH login (libpam-google-authenticator or U2F)
    - An IDS signature on inbound SSH from outside the management subnet
    - A jump host (lecture 3 section 12) that is the only legitimate
      SSH-entry point for the network

  Rate-limiting is one layer of several.  Treat it as such.

NOTE
