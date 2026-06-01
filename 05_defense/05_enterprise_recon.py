#!/usr/bin/env python3
"""
05_defense/05_enterprise_recon.py — Recon WPA2/WPA3-Enterprise (802.1X / EAP) networks.

Enterprise Wi-Fi authenticates with 802.1X + EAP against a RADIUS server
instead of a shared password. Two things this script surfaces, passively:

  1. Which nearby APs are Enterprise (AKM 802.1X) vs Personal (PSK/SAE).
  2. EAP identities in the clear. The *outer* EAP-Response/Identity is sent
     unencrypted before the TLS tunnel comes up — so usernames (or anonymous
     identities) are visible on the air. This is exactly what makes the
     enterprise Evil Twin / rogue-RADIUS attack possible when clients don't
     validate the server certificate.

⚠  EAP identities are personal data. Capture only with authorization, treat
   them as sensitive, and don't retain them beyond the engagement.

Passive. Sends nothing.

Usage:
    sudo python3 05_defense/05_enterprise_recon.py --iface wlan1mon
    sudo python3 05_defense/05_enterprise_recon.py --iface wlan1mon --duration 60

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 4
"""

import argparse
import sys
import time

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, EAP
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    require_root, require_monitor_mode, add_iface_arg, add_duration_arg,
    get_ssid, get_channel, classify_security, mask_mac,
)

# EAP method type → name (the inner method, seen in EAP-Request after identity)
EAP_METHODS = {
    1: "Identity", 2: "Notification", 4: "MD5-Challenge", 6: "GTC",
    13: "EAP-TLS", 17: "LEAP", 21: "EAP-TTLS", 25: "PEAP",
    43: "EAP-FAST", 18: "EAP-SIM", 23: "EAP-AKA", 50: "EAP-AKA'",
}

ent_aps: dict[str, dict] = {}     # bssid -> info
identities: dict[str, str] = {}   # client mac -> identity
methods_seen: set = set()
_start = time.time()


def handle(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr3
        if not bssid:
            return
        bssid = bssid.lower()
        if bssid in ent_aps:
            return
        sec = classify_security(pkt)
        if sec["enterprise"]:
            ent_aps[bssid] = {"ssid": get_ssid(pkt) or "<hidden>",
                              "channel": get_channel(pkt), "label": sec["label"],
                              "pmf": sec["pmf"]}
            print(f"  [AP] {ent_aps[bssid]['ssid']:<22} {bssid}  "
                  f"ch{ent_aps[bssid]['channel']}  {sec['label']}  PMF:{sec['pmf']}")
        return

    if pkt.haslayer(EAP) and pkt.haslayer(Dot11):
        raw = bytes(pkt[EAP])
        if len(raw) < 5:
            return
        code, etype = raw[0], raw[4]
        # code 2 = Response, type 1 = Identity → the username on the wire
        if code == 2 and etype == 1:
            client = (pkt[Dot11].addr2 or "").lower()
            identity = raw[5:].decode("utf-8", errors="replace").strip()
            if identity and client and client not in identities:
                identities[client] = identity
                print(f"  [EAP] {mask_mac(client)}  identity = {identity!r}")
        # code 1 = Request → reveals which inner method the server offers
        elif code == 1 and etype in EAP_METHODS and etype not in (1, 2):
            name = EAP_METHODS[etype]
            if name not in methods_seen:
                methods_seen.add(name)
                print(f"  [EAP] method offered: {name}")


def summary():
    elapsed = int(time.time() - _start)
    print(f"\n{'═' * 64}")
    print(f"  {elapsed}s | Enterprise APs: {len(ent_aps)} | "
          f"Identities: {len(identities)} | Methods: {len(methods_seen) or '—'}")
    if methods_seen:
        print(f"  EAP methods seen : {', '.join(sorted(methods_seen))}")
    if identities:
        print("  Captured identities (clients masked):")
        for mac, ident in identities.items():
            print(f"    {mask_mac(mac)}  ->  {ident}")
    print(f"{'═' * 64}")


def main():
    parser = argparse.ArgumentParser(
        description="Passive recon of 802.1X/EAP enterprise Wi-Fi + EAP identities.",
    )
    add_iface_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    require_root("05_defense/05_enterprise_recon.py")
    require_monitor_mode(args.iface)

    print(f"\n=== 05_defense/05_enterprise_recon.py | iface={args.iface} ===")
    print("[*] Passive. Looking for 802.1X APs and clear-text EAP identities.")
    print("[*] Identities are personal data — handle with care. Ctrl-C to stop.\n")

    timeout = args.duration if args.duration > 0 else None
    try:
        sniff(iface=args.iface, prn=handle, store=0, timeout=timeout,
              lfilter=lambda p: p.haslayer(Dot11Beacon) or p.haslayer(EAP))
    except KeyboardInterrupt:
        pass

    summary()


if __name__ == "__main__":
    main()
