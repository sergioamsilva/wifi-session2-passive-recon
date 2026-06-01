#!/usr/bin/env python3
"""
02_recon/10_client_tracker.py — Live map of which client is associated to which AP.

We have the AP's view (02_recon/05_ap_scanner.py) and the probe view (03_probe_analyzer
.py), but not the association graph: who is actually *talking to* whom right
now. This script builds that, live, from association requests and data-frame
direction bits — the missing station-side piece.

It answers questions like: how many clients are on that AP? Is anyone on the
guest network? Did a new device just join? Useful for both recon (count the
targets behind an AP) and defense (spot a device that shouldn't be there).

Passive. Sends nothing. MACs are masked in output.

Usage:
    sudo python3 02_recon/10_client_tracker.py --iface wlan1mon
    sudo python3 02_recon/10_client_tracker.py --iface wlan1mon --duration 60

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import sys
import time

try:
    from scapy.all import (sniff, Dot11, Dot11Beacon, Dot11ProbeResp,
                           Dot11AssoReq, Dot11ReassoReq)
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    require_root, require_monitor_mode, add_iface_arg, add_duration_arg,
    get_ssid, is_randomized, mask_mac, lookup_vendor, load_oui_db,
)

BROADCAST = "ff:ff:ff:ff:ff:ff"

ap_ssid: dict[str, str] = {}        # bssid -> ssid
ap_clients: dict[str, set] = {}     # bssid -> {sta}
client_ap: dict[str, str] = {}      # sta -> bssid
_oui: dict = {}
_start = time.time()


def _note_ap(bssid, pkt):
    ss = get_ssid(pkt)
    if ss:
        ap_ssid[bssid] = ss


def _bind(bssid, sta, how):
    if not bssid or not sta or bssid == BROADCAST or sta == BROADCAST:
        return
    bssid, sta = bssid.lower(), sta.lower()
    if client_ap.get(sta) == bssid:
        return  # already known on this AP
    client_ap[sta] = bssid
    ap_clients.setdefault(bssid, set()).add(sta)

    ssid = ap_ssid.get(bssid, "<?>")
    flag = "🎲" if is_randomized(sta) else "  "
    vendor = lookup_vendor(sta, _oui)
    print(f"  + {flag} {mask_mac(sta):<19} {vendor:<16} → {ssid} ({bssid})  [{how}]")


def handle(pkt):
    if not pkt.haslayer(Dot11):
        return
    d = pkt[Dot11]

    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        if d.addr3:
            _note_ap(d.addr3.lower(), pkt)
        return

    if pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
        _bind(d.addr3, d.addr2, "assoc")
        return

    if d.type == 2:  # data frame
        ds = d.FCfield & 0x03
        if ds == 0x01:      # ToDS
            _bind(d.addr1, d.addr2, "data")
        elif ds == 0x02:    # FromDS
            _bind(d.addr2, d.addr1, "data")


def summary():
    elapsed = int(time.time() - _start)
    print(f"\n{'═' * 70}")
    print(f"  ASSOCIATION MAP — {len(client_ap)} clients on "
          f"{len(ap_clients)} APs | {elapsed}s")
    print(f"{'═' * 70}")
    for bssid in sorted(ap_clients, key=lambda b: -len(ap_clients[b])):
        ssid = ap_ssid.get(bssid, "<hidden>")
        stas = ap_clients[bssid]
        print(f"\n  {ssid}  ({bssid})  —  {len(stas)} client(s)")
        for sta in sorted(stas):
            flag = "🎲" if is_randomized(sta) else "  "
            print(f"      {flag} {mask_mac(sta):<19} {lookup_vendor(sta, _oui)}")


def main():
    global _oui
    parser = argparse.ArgumentParser(
        description="Track live client↔AP associations from assoc + data frames.",
    )
    add_iface_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    require_root("02_recon/10_client_tracker.py")
    require_monitor_mode(args.iface)
    _oui = load_oui_db()

    print(f"\n=== 02_recon/10_client_tracker.py | iface={args.iface} ===")
    print("[*] Passive. New associations appear below. Ctrl-C to stop.\n")

    timeout = args.duration if args.duration > 0 else None
    try:
        sniff(iface=args.iface, prn=handle, store=0, timeout=timeout)
    except KeyboardInterrupt:
        pass

    summary()


if __name__ == "__main__":
    main()
