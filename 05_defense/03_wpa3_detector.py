#!/usr/bin/env python3
"""
05_defense/03_wpa3_detector.py — Detect WPA3, SAE, OWE and the dangerous transition mode.

WPA3 fixed a lot: SAE (Dragonfly) kills offline dictionary attacks, and
mandatory PMF kills deauth. But adoption is messy. The most interesting thing
this script finds is **transition mode**: an AP that advertises WPA3-SAE *and*
WPA2-PSK in the same RSN IE so old clients still work. A transition-mode
network is only as strong as its weakest mode — an attacker can often force a
WPA2 downgrade and attack that instead. It's WPA3 with a WPA2-shaped back door.

Passive. Sends nothing. Reads beacons and reports each AP's real security.

Usage:
    sudo python3 05_defense/03_wpa3_detector.py --iface wlan1mon
    sudo python3 05_defense/03_wpa3_detector.py --iface wlan1mon --duration 30

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

aps: dict[str, dict] = {}   # bssid -> info
_start = time.time()


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
    info = {
        "ssid": get_ssid(pkt) or "<hidden>",
        "channel": get_channel(pkt),
        **sec,
    }
    aps[bssid] = info

    flag = ""
    if info["transition"]:
        flag = "  ⚠ TRANSITION — WPA2 downgrade possible"
    elif info["wpa3"]:
        flag = "  ✓ WPA3"

    print(f"  {info['ssid']:<22} {bssid}  ch{str(info['channel'] or '?'):>3}  "
          f"{info['label']:<22} PMF:{info['pmf']:<9}{flag}")


def summary():
    elapsed = int(time.time() - _start)
    wpa3 = sum(1 for a in aps.values() if a["wpa3"])
    trans = sum(1 for a in aps.values() if a["transition"])
    pmf_req = sum(1 for a in aps.values() if a["pmf"] == "required")
    print(f"\n{'═' * 70}")
    print(f"  {len(aps)} APs | {elapsed}s")
    print(f"  WPA3-capable        : {wpa3}")
    print(f"  Transition mode     : {trans}   ← downgrade-attackable")
    print(f"  PMF required        : {pmf_req}   ← deauth-immune")
    print(f"{'═' * 70}")
    if trans:
        print("\n  Transition-mode APs (advertise SAE *and* PSK together):")
        for bssid, a in aps.items():
            if a["transition"]:
                print(f"    {a['ssid']:<22} {bssid}  ch{a['channel']}")


def main():
    parser = argparse.ArgumentParser(
        description="Detect WPA3 / SAE / OWE and WPA3-transition-mode APs.",
    )
    add_iface_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    require_root("05_defense/03_wpa3_detector.py")
    require_monitor_mode(args.iface)

    print(f"\n=== 05_defense/03_wpa3_detector.py | iface={args.iface} ===")
    print("[*] Passive. Reading beacons. ⚠ marks WPA3 transition mode. Ctrl-C to stop.\n")

    timeout = args.duration if args.duration > 0 else None
    try:
        sniff(iface=args.iface, prn=handle, store=0, timeout=timeout,
              lfilter=lambda p: p.haslayer(Dot11Beacon))
    except KeyboardInterrupt:
        pass

    summary()


if __name__ == "__main__":
    main()
