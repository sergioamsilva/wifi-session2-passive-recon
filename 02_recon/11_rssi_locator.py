#!/usr/bin/env python3
"""
02_recon/11_rssi_locator.py — A Wi-Fi Geiger counter. Walk toward a target, watch it heat up.

Lock onto one BSSID or client MAC and this shows a live signal bar that rises as
you get closer and falls as you move away — plus a packets/second rate, the
other half of "am I getting warmer?". It's how you physically find a hidden
rogue AP, a stashed tracking device, or just which desk that printer is under.

Tip: a directional antenna turns this from "somewhere in this room" into
"behind that panel". Lock the channel (--channel) so you don't miss frames
while hopping.

Passive. Sends nothing.

Usage:
    sudo python3 02_recon/11_rssi_locator.py --iface wlan1mon --target AA:BB:CC:DD:EE:FF
    sudo python3 02_recon/11_rssi_locator.py --iface wlan1mon --target AA:BB:CC:DD:EE:FF --channel 6

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import subprocess
import sys
import time

try:
    from scapy.all import sniff, Dot11
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    require_root, require_monitor_mode, add_iface_arg, validate_mac, get_rssi,
)

COLD, HOT = -90, -30   # dBm range mapped onto the bar
WIDTH = 44

_target = ""
_ema = None            # exponential moving average of RSSI
_last = None
_max = -999
_count = 0
_window = []           # (timestamp) of recent hits for pkt/s


def handle(pkt):
    global _ema, _last, _max, _count
    if not pkt.haslayer(Dot11):
        return
    d = pkt[Dot11]
    if _target not in (str(d.addr1).lower(), str(d.addr2).lower(), str(d.addr3).lower()):
        return
    rssi = get_rssi(pkt)
    if rssi is None:
        return

    _last = rssi
    _max = max(_max, rssi)
    _ema = rssi if _ema is None else (0.3 * rssi + 0.7 * _ema)
    _count += 1
    _window.append(time.time())
    render()


def render():
    now = time.time()
    while _window and now - _window[0] > 1.0:
        _window.pop(0)
    pps = len(_window)

    frac = max(0.0, min(1.0, (_ema - COLD) / (HOT - COLD)))
    filled = int(frac * WIDTH)
    bar = "█" * filled + "·" * (WIDTH - filled)
    heat = "🔥 HOT " if frac > 0.75 else ("〜 warm" if frac > 0.4 else "❄ cold")
    print(f"\r  {_ema:6.1f} dBm avg (now {_last:>4}, max {_max:>4})  "
          f"[{bar}] {heat}  {pps:>3} pkt/s   ", end="", flush=True)


def main():
    global _target
    parser = argparse.ArgumentParser(
        description="Locate a target BSSID/client by live RSSI — a Wi-Fi Geiger counter.",
    )
    add_iface_arg(parser)
    parser.add_argument("--target", required=True, metavar="AA:BB:CC:DD:EE:FF",
                        help="BSSID or client MAC to home in on.")
    parser.add_argument("--channel", type=int, default=None,
                        help="Lock to this channel (strongly recommended).")
    args = parser.parse_args()

    try:
        _target = validate_mac(args.target)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    require_root("02_recon/11_rssi_locator.py")
    require_monitor_mode(args.iface)

    if args.channel:
        r = subprocess.run(["iw", "dev", args.iface, "set", "channel",
                            str(args.channel)], capture_output=True, text=True)
        if r.returncode == 0:
            print(f"[*] Locked to channel {args.channel}")

    print(f"\n=== 02_recon/11_rssi_locator.py | iface={args.iface} ===")
    print(f"[*] Homing in on {_target}. Higher bar = closer. Ctrl-C to stop.\n")

    try:
        sniff(iface=args.iface, prn=handle, store=0)
    except KeyboardInterrupt:
        pass

    print(f"\n\n[+] Done. {_count} frames from target. "
          f"Strongest signal seen: {_max} dBm.")


if __name__ == "__main__":
    main()
