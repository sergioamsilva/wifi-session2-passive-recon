#!/usr/bin/env python3
"""
05_defense/04_pmf_detector.py — Which APs are immune to your deauth, and which aren't.

Protected Management Frames (802.11w / PMF) cryptographically protect deauth
and disassoc frames. Against an AP with PMF *required*, the deauth attack in
04_attacks/03_deauth.py and 04_attacks/02_deauth_demo.py simply does nothing — the forged frame is
ignored. This script tells you, before you waste time, exactly which networks
are still vulnerable to the classic kick and which have closed that door.

  required  → deauth-immune. Your forged frames are dropped.
  capable   → negotiated per-client. Some clients protected, some not.
  disabled  → wide open to deauth. The 2010-era attack still works.

Passive. The defender's view of the attacker's favourite trick.

Usage:
    sudo python3 05_defense/04_pmf_detector.py --iface wlan1mon
    sudo python3 05_defense/04_pmf_detector.py --iface wlan1mon --vulnerable-only

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 4
"""

import argparse
import sys
import time

try:
    from scapy.all import sniff, Dot11, Dot11Beacon
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    require_root, require_monitor_mode, add_iface_arg, add_duration_arg,
    get_ssid, get_channel, classify_security,
)

PMF_ICON = {"required": "🛡️  immune  ", "capable": "〜 partial  ",
            "disabled": "💥 VULNERABLE"}

aps: dict[str, dict] = {}
_start = time.time()
_vuln_only = False


def handle(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return
    bssid = pkt[Dot11].addr3
    if not bssid:
        return
    bssid = bssid.lower()
    if bssid in aps:
        return

    sec = classify_security(pkt)
    # Open / WEP / WPA1 networks have no RSN PMF concept — always deauth-able.
    pmf = sec["pmf"] if sec["label"] not in ("Open", "WEP", "WPA1") else "disabled"
    info = {"ssid": get_ssid(pkt) or "<hidden>", "channel": get_channel(pkt),
            "label": sec["label"], "pmf": pmf}
    aps[bssid] = info

    if _vuln_only and pmf != "disabled":
        return
    print(f"  {PMF_ICON.get(pmf, pmf)}  {info['ssid']:<22} {bssid}  "
          f"ch{str(info['channel'] or '?'):>3}  {info['label']}")


def summary():
    elapsed = int(time.time() - _start)
    req = sum(1 for a in aps.values() if a["pmf"] == "required")
    cap = sum(1 for a in aps.values() if a["pmf"] == "capable")
    dis = sum(1 for a in aps.values() if a["pmf"] == "disabled")
    print(f"\n{'═' * 66}")
    print(f"  {len(aps)} APs | {elapsed}s")
    print(f"  🛡️  PMF required  (deauth-immune)    : {req}")
    print(f"  〜 PMF capable   (per-client)        : {cap}")
    print(f"  💥 PMF disabled  (deauth-vulnerable) : {dis}")
    print(f"{'═' * 66}")


def main():
    global _vuln_only
    parser = argparse.ArgumentParser(
        description="Map which APs enforce PMF (802.11w) and which are deauth-able.",
    )
    add_iface_arg(parser)
    add_duration_arg(parser)
    parser.add_argument("--vulnerable-only", action="store_true",
                        help="Only show APs with PMF disabled (deauth-vulnerable).")
    args = parser.parse_args()
    _vuln_only = args.vulnerable_only

    require_root("05_defense/04_pmf_detector.py")
    require_monitor_mode(args.iface)

    print(f"\n=== 05_defense/04_pmf_detector.py | iface={args.iface} ===")
    print("[*] Passive. Reading beacons for 802.11w status. Ctrl-C to stop.\n")

    timeout = args.duration if args.duration > 0 else None
    try:
        sniff(iface=args.iface, prn=handle, store=0, timeout=timeout,
              lfilter=lambda p: p.haslayer(Dot11Beacon))
    except KeyboardInterrupt:
        pass

    summary()


if __name__ == "__main__":
    main()
