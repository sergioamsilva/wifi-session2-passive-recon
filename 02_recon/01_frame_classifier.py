#!/usr/bin/env python3
"""
02_recon/01_frame_classifier.py — Watch the three 802.11 frame types fly by, live.

Session 1 is all theory: management, control, data. This script makes that
theory tangible. It sits in monitor mode and tallies every frame by type and
subtype, refreshing a live table. Beacons, probe requests, ACKs, RTS/CTS,
QoS data — see the actual proportions of what fills the air around you.

Spoiler: it's almost all beacons and ACKs. The "interesting" frames are rare.

Usage:
    sudo python3 02_recon/01_frame_classifier.py --iface wlan1mon
    sudo python3 02_recon/01_frame_classifier.py --iface wlan1mon --duration 30

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 1
"""

import argparse
import sys
import time
from collections import Counter

try:
    from scapy.all import sniff, Dot11
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    require_root, require_monitor_mode, add_iface_arg, add_duration_arg,
)

TYPE_NAMES = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}

# subtype → name, per frame type. IEEE 802.11-2020 Table 9-1.
SUBTYPE_NAMES = {
    0: {0: "Assoc-Req", 1: "Assoc-Resp", 2: "Reassoc-Req", 3: "Reassoc-Resp",
        4: "Probe-Req", 5: "Probe-Resp", 8: "Beacon", 9: "ATIM",
        10: "Disassoc", 11: "Auth", 12: "Deauth", 13: "Action"},
    1: {7: "Wrapper", 8: "Block-Ack-Req", 9: "Block-Ack", 10: "PS-Poll",
        11: "RTS", 12: "CTS", 13: "ACK", 14: "CF-End", 15: "CF-End+Ack"},
    2: {0: "Data", 4: "Null", 8: "QoS-Data", 12: "QoS-Null"},
}

counts = Counter()       # (type, subtype) -> n
type_counts = Counter()  # type -> n
_start = time.time()
_total = 0


def handle(pkt):
    global _total
    if not pkt.haslayer(Dot11):
        return
    d = pkt[Dot11]
    counts[(d.type, d.subtype)] += 1
    type_counts[d.type] += 1
    _total += 1
    if _total % 50 == 0:
        render()


def render():
    elapsed = max(1, int(time.time() - _start))
    print("\033[2J\033[H", end="")   # clear screen, cursor home
    print(f"=== 1.1 Frame classifier ===  {_total} frames | {elapsed}s | "
          f"{_total // elapsed}/s\n")
    if not _total:
        return
    for t in (0, 1, 2, 3):
        if not type_counts[t]:
            continue
        pct = 100 * type_counts[t] / _total
        print(f"  {TYPE_NAMES.get(t, t):<12} {type_counts[t]:>8}  {pct:5.1f}%")
        subs = [(k, v) for k, v in counts.items() if k[0] == t]
        for (_, st), v in sorted(subs, key=lambda x: -x[1]):
            name = SUBTYPE_NAMES.get(t, {}).get(st, f"subtype-{st}")
            print(f"      {name:<16} {v:>8}")
    print("\n  Ctrl-C to stop.")


def main():
    parser = argparse.ArgumentParser(
        description="Classify live 802.11 frames by type/subtype — Session 1 demo.",
    )
    add_iface_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    require_root("02_recon/01_frame_classifier.py")
    require_monitor_mode(args.iface)

    print(f"\n=== 1.1 Frame classifier | iface={args.iface} ===")
    print("[*] Counting frames. Live table refreshes every 50 frames.\n")

    timeout = args.duration if args.duration > 0 else None
    try:
        sniff(iface=args.iface, prn=handle, store=0, timeout=timeout)
    except KeyboardInterrupt:
        pass

    render()
    print(f"\n[+] Done. {_total} frames classified.")


if __name__ == "__main__":
    main()
