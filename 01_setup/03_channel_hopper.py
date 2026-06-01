#!/usr/bin/env python3
"""
01_setup/03_channel_hopper.py — Restlessly jump between Wi-Fi channels so your
                        capture tools never miss a packet.

Think of this as the ADD kid of wireless tools — it cannot sit still,
and that is exactly what we want. While it hops, scripts 03 and 04
collect everything that falls out.

Run this in Terminal A. Run your capture tool in Terminal B.
Do not run this and the capture tool on the same channel-locked session —
that defeats the point entirely.

Usage:
    sudo python3 01_setup/03_channel_hopper.py --iface wlan1 --band 2.4
    sudo python3 01_setup/03_channel_hopper.py --iface wlan1 --band 5
    sudo python3 01_setup/03_channel_hopper.py --iface wlan1 --band both --dwell 0.3
    sudo python3 01_setup/03_channel_hopper.py --iface wlan1 --channels 1,6,11 --dwell 1.0

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import signal
import subprocess
import sys
import time

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import require_root, require_monitor_mode, add_iface_arg, add_duration_arg

# ──────────────────────────────────────────────
# Channel maps
# ──────────────────────────────────────────────

# EU/PT 2.4 GHz — channels 1-13 (the USA stops at 11, because freedom)
CHANNELS_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

# 5 GHz — grouped by UNII band. DFS channels (52-140) may be blocked
# by your chipset, your regulatory domain, or a bureaucrat somewhere.
CHANNELS_5 = [
    36, 40, 44, 48,               # UNII-1  — indoor, non-DFS, friendly
    52, 56, 60, 64,               # UNII-2  — DFS, may vanish mysteriously
    100, 104, 108, 112, 116,      # UNII-2e — also DFS, also dramatic
    120, 124, 128, 132, 136, 140,
    149, 153, 157, 161, 165,      # UNII-3  — outdoor, the wild west
]

_running = True  # flipped to False by Ctrl-C; the loop respects this


def set_channel(iface: str, channel: int) -> bool:
    """
    Politely ask the kernel to tune to a channel.
    Returns True if it listened. Returns False if it had opinions.
    """
    result = subprocess.run(
        ["iw", "dev", iface, "set", "channel", str(channel)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def build_channel_list(band: str, custom: list[int] | None) -> list[int]:
    """
    Assemble the hop list. Custom list wins over band if both are provided —
    because you know what you want and we respect that.
    """
    if custom:
        return custom
    if band == "2.4":
        return CHANNELS_24
    if band == "5":
        return CHANNELS_5
    # "both" — the completionist option
    return CHANNELS_24 + CHANNELS_5


def handle_sigint(sig, frame):
    """
    Ctrl-C handler. We exit gracefully, like someone who planned to leave anyway.
    """
    global _running
    _running = False


def main():
    global _running

    require_root()

    parser = argparse.ArgumentParser(
        description="Wi-Fi channel hopper — never stops, never rests, very dedicated.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 01_setup/03_channel_hopper.py --iface wlan1 --band 2.4\n"
            "  sudo python3 01_setup/03_channel_hopper.py --iface wlan1 --channels 1,6,11 --dwell 1.0\n\n"
            "Pro tip: pair with 02_recon/04_probe_analyzer.py or 03_capture/01_handshake_catcher.py\n"
            "         in a second terminal for full-spectrum coverage."
        ),
    )
    add_iface_arg(parser)
    add_duration_arg(parser)
    parser.add_argument("--band", choices=["2.4", "5", "both"], default="2.4",
                        help="Band to hop. 'both' is thorough but slow (default: 2.4)")
    parser.add_argument("--channels", default=None,
                        help="Override --band with a comma-separated channel list, e.g. 1,6,11")
    parser.add_argument("--dwell", type=float, default=0.5,
                        help="Seconds per channel. Too short = miss packets. "
                             "Too long = miss channels. 0.5s is the Goldilocks value. (default: 0.5)")
    args = parser.parse_args()

    require_monitor_mode(args.iface)

    # Parse custom channel list if provided
    custom_channels = None
    if args.channels:
        try:
            custom_channels = [int(c.strip()) for c in args.channels.split(",")]
        except ValueError:
            print("[!] --channels expects integers separated by commas, e.g.  1,6,11")
            sys.exit(1)

    channels = build_channel_list(args.band, custom_channels)

    signal.signal(signal.SIGINT, handle_sigint)

    print(f"\n=== 01_setup/03_channel_hopper.py ===")
    print(f"    Interface : {args.iface}")
    print(f"    Channels  : {channels}")
    print(f"    Dwell     : {args.dwell}s")
    print(f"    Total     : {len(channels)} channels | "
          f"cycle time ≈ {len(channels) * args.dwell:.1f}s")
    print("    Press Ctrl-C to stop\n")

    hops    = 0
    fails   = 0
    start   = time.time()

    while _running:
        for ch in channels:
            if not _running:
                break

            ok = set_channel(args.iface, ch)
            band_label = "2.4G" if ch <= 14 else "5G  "
            tick       = "✓" if ok else "✗"
            elapsed    = int(time.time() - start)

            if ok:
                hops += 1
            else:
                fails += 1

            print(
                f"\r  [{tick}] {band_label}  CH {ch:3d}  |  "
                f"hops: {hops:5d}  skipped: {fails}  elapsed: {elapsed:4d}s   ",
                end="",
                flush=True,
            )
            time.sleep(args.dwell)

    elapsed = int(time.time() - start)
    print(f"\n\n[+] Stopped after {elapsed}s.  Hops: {hops}  |  Skipped: {fails}")
    print(f"    The interface is still on whatever channel it landed on.")
    print(f"    Lock it manually with:  iw dev {args.iface} set channel <N>")


if __name__ == "__main__":
    main()
