#!/usr/bin/env python3
"""Exercise 5 — WireGuard Keypair Generator.

AUTHORIZED USE ONLY.  Deploy WireGuard only on a network you own and
administer, or for which you hold written authorisation from the
owner.  See the week README banner.

This script automates the keypair-generation step of onboarding a new
WireGuard peer.  It:

  1. Generates an Ed25519-style keypair using the local ``wg`` tool
     (Curve25519 under the hood for WireGuard).
  2. Writes the private key to a file with mode 0600 in a directory
     with mode 0700.
  3. Writes the public key to a file with mode 0644.
  4. Optionally generates a PSK for defence-in-depth against future
     quantum-computer attacks against Curve25519.
  5. Prints a starter ``[Peer]`` block ready to paste into the server
     config plus a starter client config ready to drop on the device.

USAGE
-----
    python3 exercise-05-wireguard-keygen.py NAME \
        --output-dir ~/wg/peers \
        --client-address 10.10.0.5/32 \
        --server-endpoint vpn.example.com:51820 \
        --server-public-key BASE64KEY... \
        [--psk]                # generate and include a PSK
        [--full-tunnel]        # client routes 0.0.0.0/0 through VPN

NAME is the peer name.  It is used as a filename prefix and as a
comment in the printed config; it does NOT appear in the cryptographic
identity (which is the public key alone).

REQUIREMENTS
------------
    - wireguard-tools (``wg`` on the path).
    - Python 3.11 or later.
    - The user running this script must have write access to
      ``--output-dir``.

REFERENCE
---------
    Donenfeld 2017 — https://www.wireguard.com/papers/wireguard.pdf
    wg(8) man page  — installed with wireguard-tools
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

WG_PRIVATE_KEY_MODE: int = 0o600
WG_PUBLIC_KEY_MODE: int = 0o644
WG_DIR_MODE: int = 0o700

# WireGuard keys are 32 bytes base64-encoded -> 44 characters (including
# trailing '=').  This regex matches a well-formed key.
WG_KEY_REGEX: re.Pattern[str] = re.compile(r"^[A-Za-z0-9+/]{43}=$")

DEFAULT_PERSISTENT_KEEPALIVE: int = 25
DEFAULT_DNS: str = "10.10.0.1"


# ---------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class Keypair:
    """A WireGuard keypair (and optional PSK).

    Fields are base64-encoded 32-byte values.  The PSK is symmetric;
    if present, it must be configured identically on both peers of a
    relationship.
    """

    private_key: str
    public_key: str
    psk: str | None = None


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def assert_wg_present() -> None:
    """Exit with a clear message if the ``wg`` tool is not installed."""
    if shutil.which("wg") is None:
        sys.stderr.write(
            "ERROR: the 'wg' tool is not on the PATH.  Install with:\n"
            "  Debian/Ubuntu: sudo apt install wireguard-tools\n"
            "  Fedora:        sudo dnf install wireguard-tools\n"
            "  macOS:         brew install wireguard-tools\n"
        )
        sys.exit(1)


def validate_key(key: str, *, label: str) -> str:
    """Validate a base64 WireGuard key.  Returns the key unchanged."""
    stripped: str = key.strip()
    if not WG_KEY_REGEX.match(stripped):
        sys.stderr.write(
            f"ERROR: {label} does not look like a valid WireGuard key.\n"
            f"  Expected 43 base64 chars followed by '=' (44 total).\n"
            f"  Got: {stripped!r}\n"
        )
        sys.exit(2)
    return stripped


def validate_cidr(cidr: str) -> str:
    """Validate that ``cidr`` looks like an IPv4 CIDR.  Returns it unchanged.

    We deliberately do not import ``ipaddress`` and parse strictly;
    we only sanity-check the shape so an obvious typo is caught.
    """
    match: re.Match[str] | None = re.match(
        r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$",
        cidr,
    )
    if not match:
        sys.stderr.write(
            f"ERROR: '{cidr}' does not look like an IPv4 CIDR (a.b.c.d/n).\n"
        )
        sys.exit(2)
    return cidr


def validate_endpoint(endpoint: str) -> str:
    """Validate the ``host:port`` form of the server endpoint."""
    if ":" not in endpoint:
        sys.stderr.write(
            f"ERROR: '{endpoint}' is not in host:port form.\n"
        )
        sys.exit(2)
    host, _, port_str = endpoint.rpartition(":")
    if not host or not port_str.isdigit():
        sys.stderr.write(
            f"ERROR: '{endpoint}' is not in host:port form.\n"
        )
        sys.exit(2)
    port: int = int(port_str)
    if not (1 <= port <= 65535):
        sys.stderr.write(
            f"ERROR: port {port} is out of range (1..65535).\n"
        )
        sys.exit(2)
    return endpoint


def run_wg(args: list[str], *, stdin: str | None = None) -> str:
    """Run ``wg`` with ``args``; return stdout stripped of whitespace."""
    result: subprocess.CompletedProcess[str] = subprocess.run(
        ["wg", *args],
        check=True,
        capture_output=True,
        text=True,
        input=stdin,
    )
    return result.stdout.strip()


def generate_keypair(*, with_psk: bool) -> Keypair:
    """Generate a fresh WireGuard keypair (and optional PSK)."""
    private_key: str = run_wg(["genkey"])
    public_key: str = run_wg(["pubkey"], stdin=private_key)
    psk: str | None = run_wg(["genpsk"]) if with_psk else None
    return Keypair(
        private_key=validate_key(private_key, label="generated private key"),
        public_key=validate_key(public_key, label="derived public key"),
        psk=validate_key(psk, label="generated PSK") if psk else None,
    )


def secure_mkdir(path: Path) -> None:
    """Create ``path`` if missing and harden its permissions to 0700."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, WG_DIR_MODE)


def write_secret(path: Path, value: str, *, mode: int) -> None:
    """Write a secret atomically with ``mode`` permissions.

    We open the file with O_CREAT|O_WRONLY|O_TRUNC and ``mode`` so the
    file is never visible to anyone else for an instant, even between
    creation and chmod.
    """
    fd: int = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        mode,
    )
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(value)
            if not value.endswith("\n"):
                handle.write("\n")
    except Exception:
        # If write fails after fd was assigned to fdopen, fd is owned
        # by the context manager and is already closed.
        raise
    # Belt-and-braces: enforce the mode again in case umask changed it.
    os.chmod(path, mode)


def file_mode(path: Path) -> str:
    """Return the file mode of ``path`` as a four-character octal string."""
    return f"{stat.S_IMODE(path.stat().st_mode):04o}"


# ---------------------------------------------------------------------
# Config rendering
# ---------------------------------------------------------------------


def render_server_peer_block(
    *,
    name: str,
    public_key: str,
    psk: str | None,
    client_address: str,
) -> str:
    """Render the ``[Peer]`` block to paste into the server config."""
    lines: list[str] = [
        f"# Peer: {name}",
        "[Peer]",
        f"PublicKey = {public_key}",
        f"AllowedIPs = {client_address}",
    ]
    if psk is not None:
        lines.append(f"PresharedKey = {psk}")
    return "\n".join(lines) + "\n"


def render_client_config(
    *,
    name: str,
    private_key: str,
    psk: str | None,
    client_address: str,
    server_public_key: str,
    server_endpoint: str,
    full_tunnel: bool,
    dns: str | None,
) -> str:
    """Render the wg0.conf the peer drops on the client device."""
    allowed_ips: str
    if full_tunnel:
        allowed_ips = "0.0.0.0/0, ::/0"
    else:
        # Split-tunnel: route only the VPN overlay.  Edit this list
        # if the peer should reach additional internal subnets.
        allowed_ips = "10.10.0.0/24"

    interface_lines: list[str] = [
        f"# Client config for: {name}",
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {client_address}",
    ]
    if dns is not None:
        interface_lines.append(f"DNS = {dns}")

    peer_lines: list[str] = [
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
    ]
    if psk is not None:
        peer_lines.append(f"PresharedKey = {psk}")
    peer_lines.extend(
        [
            f"Endpoint = {server_endpoint}",
            f"AllowedIPs = {allowed_ips}",
            f"PersistentKeepalive = {DEFAULT_PERSISTENT_KEEPALIVE}",
        ]
    )

    return "\n".join(interface_lines + peer_lines) + "\n"


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser used by ``main``."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Generate a WireGuard keypair and render starter configs.",
        epilog=(
            "AUTHORIZED USE ONLY.  Deploy WireGuard only on a network "
            "you own or are authorised to administer."
        ),
    )
    parser.add_argument(
        "name",
        help="Peer name (used for filenames and comments only).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.home() / "wg" / "peers",
        help="Directory to write the keypair files into.",
    )
    parser.add_argument(
        "--client-address",
        required=True,
        help="The address the peer claims inside the VPN overlay (CIDR).",
    )
    parser.add_argument(
        "--server-endpoint",
        required=True,
        help="The server's public endpoint, host:port form.",
    )
    parser.add_argument(
        "--server-public-key",
        required=True,
        help="The server's base64 public key.",
    )
    parser.add_argument(
        "--dns",
        default=DEFAULT_DNS,
        help=f"DNS resolver address for the client (default {DEFAULT_DNS}).",
    )
    parser.add_argument(
        "--full-tunnel",
        action="store_true",
        help="Route all client traffic through the VPN (vs. split-tunnel).",
    )
    parser.add_argument(
        "--psk",
        action="store_true",
        help="Generate and include a pre-shared key.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the keygen workflow.  Returns a shell-style exit code."""
    assert_wg_present()

    parser: argparse.ArgumentParser = build_arg_parser()
    args: argparse.Namespace = parser.parse_args(argv)

    name: str = args.name
    output_dir: Path = args.output_dir.expanduser()
    client_address: str = validate_cidr(args.client_address)
    server_endpoint: str = validate_endpoint(args.server_endpoint)
    server_public_key: str = validate_key(
        args.server_public_key,
        label="server public key",
    )

    # Prepare the output directory with hardened permissions before
    # writing anything secret into it.
    secure_mkdir(output_dir)

    # Generate the keypair.
    keypair: Keypair = generate_keypair(with_psk=args.psk)

    # Write the keypair to disk.
    safe_name: str = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    priv_path: Path = output_dir / f"{safe_name}.private"
    pub_path: Path = output_dir / f"{safe_name}.public"
    psk_path: Path | None = (
        output_dir / f"{safe_name}.psk"
        if keypair.psk is not None
        else None
    )

    write_secret(priv_path, keypair.private_key, mode=WG_PRIVATE_KEY_MODE)
    write_secret(pub_path, keypair.public_key, mode=WG_PUBLIC_KEY_MODE)
    if psk_path is not None and keypair.psk is not None:
        write_secret(psk_path, keypair.psk, mode=WG_PRIVATE_KEY_MODE)

    # Render the config snippets.
    server_block: str = render_server_peer_block(
        name=name,
        public_key=keypair.public_key,
        psk=keypair.psk,
        client_address=client_address,
    )
    client_config: str = render_client_config(
        name=name,
        private_key=keypair.private_key,
        psk=keypair.psk,
        client_address=client_address,
        server_public_key=server_public_key,
        server_endpoint=server_endpoint,
        full_tunnel=args.full_tunnel,
        dns=args.dns,
    )

    # Print summary.
    print(f"==> Generated keypair for peer: {name}")
    print(f"    private key: {priv_path} (mode {file_mode(priv_path)})")
    print(f"    public key:  {pub_path}  (mode {file_mode(pub_path)})")
    if psk_path is not None:
        print(f"    psk:         {psk_path}     (mode {file_mode(psk_path)})")

    print()
    print("==> Paste the following into the SERVER /etc/wireguard/wg0.conf:")
    print("------ begin server [Peer] block ------")
    print(server_block, end="")
    print("------ end server [Peer] block --------")

    print()
    print(
        "==> Drop the following on the CLIENT as /etc/wireguard/wg0.conf "
        "(or import it into the WireGuard mobile app):"
    )
    print("------ begin client wg0.conf ------")
    print(client_config, end="")
    print("------ end client wg0.conf --------")

    print()
    print(
        "==> Reminder: never commit any file with 'private' or 'psk' in "
        "its name to git.  The repository's .gitignore should already "
        "exclude them; verify before pushing."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
