#!/usr/bin/env python3
"""
02_recon/02_discover_networks.py — Discover nearby networks by sniffing beacons.

The slide-sized AP scanner. Every access point in range shouts its name into
the void roughly ten times a second; we sit there and write down who's shouting.
No packets sent — pure eavesdropping.

Because a monitor-mode card sits on ONE channel at a time, this would otherwise
only see APs on that single channel. So it hops the 2.4 GHz channels (1-13) in
the background by default (that's what "discover" needs) — disable with --no-hop
if you're already running 01_setup/03_channel_hopper.py in another terminal.

For the full-featured map (encryption, vendor, signal, 5 GHz), see
02_recon/05_ap_scanner.py.

Usage:
    sudo python3 02_recon/02_discover_networks.py --iface wlan1mon
    sudo python3 02_recon/02_discover_networks.py --iface wlan1mon --no-hop   # external hopper

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import subprocess
import sys
import threading
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
    require_root,
    require_monitor_mode,
    add_iface_arg,
    add_duration_arg,
    get_ssid,
    get_rssi,
    get_channel,
)

CHANNELS_24 = list(range(1, 14))   # 2.4 GHz channels 1-13 (EU/PT)

# Beacons we've already printed — one line per AP, not one per beacon.
seen: set = set()
_stop = threading.Event()


def hopper(iface: str, channels: list[int], dwell: float):
    """Background thread: tune the card across channels so we see all of them."""
    while not _stop.is_set():
        for ch in channels:
            if _stop.is_set():
                return
            subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                           capture_output=True)
            time.sleep(dwell)


def handle(pkt):
    """Called for every captured frame; we only care about beacons."""
    if not pkt.haslayer(Dot11Beacon):
        return

    bssid = pkt[Dot11].addr2
    if bssid is None or bssid in seen:
        return
    seen.add(bssid)

    ssid = get_ssid(pkt) or "<hidden>"
    dbm = get_rssi(pkt)
    dbm_str = f"{dbm} dBm" if dbm is not None else "? dBm"
    ch = get_channel(pkt)
    ch_str = f"ch{ch}" if ch is not None else "ch?"

    print(f"  {ssid:<25} {bssid}  {ch_str:>5}  {dbm_str}")


def main():
    parser = argparse.ArgumentParser(
        description="Discover nearby Wi-Fi networks by passively sniffing beacons.",
    )
    add_iface_arg(parser)
    parser.add_argument("--dwell", type=float, default=0.5,
                        help="Seconds per channel while hopping. (default: 0.5)")
    parser.add_argument("--no-hop", action="store_true",
                        help="Don't hop — stay on the current channel "
                             "(use if 01_setup/03_channel_hopper.py is running elsewhere).")
    add_duration_arg(parser)
    args = parser.parse_args()

    require_root("02_recon/02_discover_networks.py")
    require_monitor_mode(args.iface)

    channels = CHANNELS_24

    print(f"\n=== 2.1 Discover networks | iface={args.iface} ===")
    if args.no_hop:
        print("[*] Not hopping (--no-hop): seeing only the current channel.")
    else:
        print(f"[*] Hopping 2.4 GHz channels 1-13, "
              f"{args.dwell}s each (~{len(channels) * args.dwell:.0f}s/cycle).")
    print("[*] Listening for beacons. One line per new AP. Ctrl-C to stop.\n")
    print(f"  {'SSID':<25} {'BSSID':<17}  {'CH':>5}  SIGNAL")
    print("  " + "─" * 58)

    hop_thread = None
    if not args.no_hop:
        hop_thread = threading.Thread(target=hopper,
                                      args=(args.iface, channels, args.dwell),
                                      daemon=True)
        hop_thread.start()

    timeout = args.duration if args.duration > 0 else None
    try:
        sniff(iface=args.iface, prn=handle, store=0, timeout=timeout)
    except KeyboardInterrupt:
        pass
    finally:
        _stop.set()

    print(f"\n[+] Done. {len(seen)} unique access points seen.")


if __name__ == "__main__":
    main()
