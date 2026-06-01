#!/usr/bin/env python3
"""
02_recon/03_client_pnl.py — Collect the Preferred Network List (PNL) from clients.

The minimal, slide-sized probe-request sniffer. When a phone isn't connected
to anything, it gets impatient and starts asking — out loud, by name — for
every network it remembers: "Is MEO-1234 here? Is Marriott_Lisbon here? Is
my-home-wifi here?" That list of remembered networks is the PNL.

This is the "2.2 — Recolher a PNL dos clientes" demo, and it shows concretely
*why* KARMA / known-beacons attacks work: the client tells you exactly which
SSID to impersonate to make it connect to you. For the full analyzer with
vendor lookup, randomization stats and JSON export, see 02_recon/04_probe_analyzer.py.

Usage:
    sudo python3 02_recon/03_client_pnl.py --iface wlan1mon

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import sys

try:
    from scapy.all import sniff, Dot11, Dot11ProbeReq
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    require_root,
    require_monitor_mode,
    add_iface_arg,
    get_ssid,
    is_randomized,
    mask_mac,
)


def handle(pkt):
    """Print every directed probe request — client asking for a named SSID."""
    if not pkt.haslayer(Dot11ProbeReq):
        return

    ssid = get_ssid(pkt)
    if not ssid:          # wildcard probe (no SSID) — skip, it tells us nothing
        return

    client = pkt[Dot11].addr2
    if client is None:
        return

    flag = "🎲" if is_randomized(client) else "  "
    print(f"  {flag} {mask_mac(client)} procura -> {ssid}")


def main():
    parser = argparse.ArgumentParser(
        description="Collect client Preferred Network Lists (PNL) from probe requests.",
    )
    add_iface_arg(parser)
    args = parser.parse_args()

    require_root("02_recon/03_client_pnl.py")
    require_monitor_mode(args.iface)

    print(f"\n=== 2.2 Client PNL | iface={args.iface} ===")
    print("[*] Listening for probe requests. 🎲 = randomized MAC. Ctrl-C to stop.\n")

    try:
        sniff(iface=args.iface, prn=handle, store=0)
    except KeyboardInterrupt:
        pass

    print("\n[+] Done. Every SSID above is one the attacker could impersonate.")


if __name__ == "__main__":
    main()
