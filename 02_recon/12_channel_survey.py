#!/usr/bin/env python3
"""
02_recon/12_channel_survey.py — Which channels are crowded, which are clear.

Before you capture or stand up a lab AP, you want to know where the noise is.
This dwells on each channel in turn, counts frames and unique APs, and prints a
congestion bar — a quick spectrum survey without a dedicated analyzer.

Read it like a site survey: pick the emptiest non-overlapping channel (1/6/11
on 2.4 GHz) for your own AP, or the busiest one if you're hunting for targets.

Passive. Sends nothing — it just listens, channel by channel.

Usage:
    sudo python3 02_recon/12_channel_survey.py --iface wlan1mon
    sudo python3 02_recon/12_channel_survey.py --iface wlan1mon --band 5 --dwell 3
    sudo python3 02_recon/12_channel_survey.py --iface wlan1mon --band both

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import subprocess
import sys

try:
    from scapy.all import sniff, Dot11, Dot11Beacon
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import require_root, require_monitor_mode, add_iface_arg

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64,
              100, 104, 108, 112, 116, 132, 136, 140,
              149, 153, 157, 161, 165]


def set_channel(iface: str, ch: int) -> bool:
    r = subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                       capture_output=True, text=True)
    return r.returncode == 0


def survey_channel(iface: str, dwell: int) -> dict:
    """Listen on the current channel for `dwell` seconds; tally activity."""
    stats = {"frames": 0, "bytes": 0, "aps": set()}

    def cb(pkt):
        if not pkt.haslayer(Dot11):
            return
        stats["frames"] += 1
        stats["bytes"] += len(pkt)
        if pkt.haslayer(Dot11Beacon) and pkt[Dot11].addr3:
            stats["aps"].add(pkt[Dot11].addr3.lower())

    sniff(iface=iface, prn=cb, store=0, timeout=dwell)
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Survey per-channel congestion (frames + AP count) — a mini site survey.",
    )
    add_iface_arg(parser)
    parser.add_argument("--band", choices=["2.4", "5", "both"], default="2.4",
                        help="Which band to survey. (default: 2.4)")
    parser.add_argument("--dwell", type=int, default=2, metavar="SEC",
                        help="Seconds to listen per channel. (default: 2)")
    args = parser.parse_args()

    require_root("02_recon/12_channel_survey.py")
    require_monitor_mode(args.iface)

    if args.band == "2.4":
        channels = CHANNELS_24
    elif args.band == "5":
        channels = CHANNELS_5
    else:
        channels = CHANNELS_24 + CHANNELS_5

    print(f"\n=== 02_recon/12_channel_survey.py | iface={args.iface} | band={args.band} ===")
    print(f"[*] {args.dwell}s per channel, {len(channels)} channels "
          f"(~{args.dwell * len(channels)}s total). Passive. Ctrl-C to stop.\n")

    results: dict[int, dict] = {}
    try:
        for ch in channels:
            if not set_channel(args.iface, ch):
                print(f"  ch{ch:>3}  (unavailable — regulatory/DFS, skipped)")
                continue
            s = survey_channel(args.iface, args.dwell)
            results[ch] = s
            print(f"  ch{ch:>3}  {s['frames']:>5} frames  "
                  f"{len(s['aps']):>2} APs  ({s['bytes'] // 1024} KiB)")
    except KeyboardInterrupt:
        print("\n[!] Interrupted — showing what we have.")

    if not results:
        print("\n[!] No channels surveyed.")
        return

    peak = max((s["frames"] for s in results.values()), default=1) or 1
    print(f"\n{'═' * 60}")
    print(f"  CONGESTION  (bar = frames relative to busiest channel)")
    print(f"{'═' * 60}")
    for ch in sorted(results, key=lambda c: -results[c]["frames"]):
        s = results[ch]
        filled = int(40 * s["frames"] / peak)
        bar = "█" * filled + "·" * (40 - filled)
        print(f"  ch{ch:>3} [{bar}] {s['frames']:>5}f / {len(s['aps'])}AP")

    quiet = min(results, key=lambda c: results[c]["frames"])
    busy = max(results, key=lambda c: results[c]["frames"])
    print(f"\n  Quietest: ch{quiet}   Busiest: ch{busy}")
    if args.band in ("2.4", "both"):
        non_overlap = {c: results[c]["frames"] for c in (1, 6, 11) if c in results}
        if non_overlap:
            best = min(non_overlap, key=non_overlap.get)
            print(f"  Best non-overlapping 2.4 GHz channel for your AP: ch{best}")


if __name__ == "__main__":
    main()
