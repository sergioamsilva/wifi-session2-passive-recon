#!/usr/bin/env python3
"""
02_recon/06_hidden_ssid_hunter.py — Reveal hidden SSIDs. Passively. Effortlessly.

Network admins who hide their SSIDs believe in security through obscurity.
This script politely disagrees.

When a client wants to connect to a hidden AP, it sends a Probe Request
with the SSID in plain text. The AP replies with a Probe Response —
also with the SSID in plain text. We simply wait and watch.

Hidden networks aren't secret. They're just loud in a different way.
Clients probe for them constantly. The SSID appears on the air within
seconds of any client attempt.

Usage:
    sudo python3 02_recon/06_hidden_ssid_hunter.py --iface wlan1
    sudo python3 02_recon/06_hidden_ssid_hunter.py --iface wlan1 --bssid AA:BB:CC:DD:EE:FF

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import signal
import sys
import time
from datetime import datetime

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, sniff
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid,
    require_root, require_monitor_mode,
    add_iface_arg, add_duration_arg,
    parse_bssid_arg,
)


# ──────────────────────────────────────────────
# State
# ──────────────────────────────────────────────

# BSSIDs broadcasting with empty SSID (hidden networks)
_hidden_aps:  dict[str, dict] = {}   # bssid → {first_seen, beacon_count}

# BSSIDs whose SSID we've revealed (from probe responses or directed probes)
_revealed:    dict[str, str]  = {}   # bssid → ssid

# Directed probe requests we've seen (client asking for a hidden network)
_probes_seen: dict[str, set]  = {}   # ssid → set of client MACs

_start_time = time.time()
_target_bssid: str | None = None


# ──────────────────────────────────────────────
# Address helper
# ──────────────────────────────────────────────

def _addr(pkt, field: str) -> str | None:
    """Safe accessor for Dot11 address fields."""
    try:
        val = getattr(pkt[Dot11], field, None)
        return val.lower() if val else None
    except Exception:
        return None


# ──────────────────────────────────────────────
# Packet handlers
# ──────────────────────────────────────────────

def _handle_beacon(pkt):
    """
    Track APs broadcasting with an empty SSID — these are 'hidden'.
    Some APs set SSID length = 0, others fill it with null bytes.
    Both are equally ineffective at hiding anything.
    """
    bssid = _addr(pkt, "addr3")
    if not bssid:
        return
    if _target_bssid and bssid != _target_bssid:
        return

    ssid = get_ssid(pkt)
    if ssid:
        # AP is broadcasting its SSID normally — not a hidden network
        # But if we previously saw it as hidden, update the record
        if bssid in _hidden_aps and bssid not in _revealed:
            _announce_reveal(bssid, ssid, source="beacon (AP changed config?)")
        return

    if bssid not in _hidden_aps:
        _hidden_aps[bssid] = {
            "first_seen":   datetime.now().isoformat(timespec="seconds"),
            "beacon_count": 0,
        }
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n  [{ts}] 👻 Hidden AP detected:")
        print(f"         BSSID : {bssid}")
        print(f"         SSID  : ??? (hidden)")
        print(f"         Waiting for a client to probe it ...\n")

    _hidden_aps[bssid]["beacon_count"] += 1


def _handle_probe_response(pkt):
    """
    Probe Responses from hidden APs contain the SSID in plain text.
    The moment a client asks to connect, the AP answers and reveals itself.
    This is the core of the 'hidden SSID is security theater' argument.
    """
    bssid = _addr(pkt, "addr3")
    ssid  = get_ssid(pkt)

    if not bssid or not ssid:
        return
    if _target_bssid and bssid != _target_bssid:
        return
    if bssid not in _hidden_aps:
        return  # not a hidden AP we're tracking
    if bssid in _revealed:
        return  # already got it

    _announce_reveal(bssid, ssid, source="Probe Response")


def _handle_probe_request(pkt):
    """
    Directed probe requests (with a specific SSID) from clients
    tell us which hidden network they're looking for.
    If we correlate this with a BSSID that replied, we've confirmed the SSID.
    """
    ssid   = get_ssid(pkt)
    client = _addr(pkt, "addr2")

    if not ssid or not client:
        return  # wildcard probe — not useful here

    if ssid not in _probes_seen:
        _probes_seen[ssid] = set()
    _probes_seen[ssid].add(client)

    # If any hidden AP was already tagged with this SSID through a response,
    # this probe just corroborates the finding. If not, it's a lead.
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\r  [{ts}] 📡 Client {client} probing for: \"{ssid}\"          ", flush=True)


def _announce_reveal(bssid: str, ssid: str, source: str):
    """Print the big reveal. This is the money moment."""
    _revealed[bssid] = ssid
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n\n  ╔═══════════════════════════════════════════╗")
    print(f"  ║  ✓ HIDDEN SSID REVEALED @ {ts}          ║")
    print(f"  ╠═══════════════════════════════════════════╣")
    print(f"  ║  BSSID  : {bssid:<33} ║")
    print(f"  ║  SSID   : {ssid[:33]:<33} ║")
    print(f"  ║  Source : {source[:33]:<33} ║")
    print(f"  ╚═══════════════════════════════════════════╝\n")
    print(f"  Wireshark filter to confirm:")
    print(f"  wlan.bssid == {bssid} && "
          f"(wlan.fc.type_subtype == 0x05 || wlan.fc.type_subtype == 0x04)\n")


def handle_packet(pkt):
    if not pkt.haslayer(Dot11):
        return
    dot11 = pkt[Dot11]

    if dot11.type == 0:  # management frame
        if dot11.subtype == 8:   # beacon
            _handle_beacon(pkt)
        elif dot11.subtype == 5: # probe response
            _handle_probe_response(pkt)
        elif dot11.subtype == 4: # probe request
            _handle_probe_request(pkt)


def print_summary():
    elapsed = int(time.time() - _start_time)
    print(f"\n\n{'═' * 55}")
    print(f"  SUMMARY — {elapsed}s capture")
    print(f"{'═' * 55}")
    print(f"  Hidden APs detected : {len(_hidden_aps)}")
    print(f"  SSIDs revealed      : {len(_revealed)}")
    print(f"  SSIDs still hidden  : {len(_hidden_aps) - len(_revealed)}")

    if _revealed:
        print(f"\n  Revealed:")
        for bssid, ssid in _revealed.items():
            print(f"    {bssid}  →  \"{ssid}\"")

    unrevealed = [b for b in _hidden_aps if b not in _revealed]
    if unrevealed:
        print(f"\n  Still hidden (no client probed during capture):")
        for bssid in unrevealed:
            print(f"    {bssid}  →  ???")
        print(f"\n  Tip: wait longer, or use 04_attacks/03_deauth.py in Session 3")
        print(f"       to force a reconnection and trigger the probe.")


def main():
    global _target_bssid

    require_root()

    parser = argparse.ArgumentParser(
        description="Passive hidden SSID revealer — patience required, deauth not.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The hidden network reveals itself the moment any client connects.\n"
            "In a busy environment this takes seconds. In an empty room, longer.\n\n"
            "Wireshark equivalent:\n"
            "  wlan.fc.type_subtype == 0x05  (Probe Responses)"
        ),
    )
    add_iface_arg(parser)
    parser.add_argument("--bssid", default=None, help="Focus on a specific hidden AP")
    add_duration_arg(parser)
    args = parser.parse_args()

    _target_bssid = parse_bssid_arg(args.bssid)

    require_monitor_mode(args.iface)

    print(f"\n=== 02_recon/06_hidden_ssid_hunter.py ===")
    print(f"    Interface  : {args.iface}")
    print(f"    Target     : {_target_bssid or 'any hidden AP'}")
    print(f"    Mode       : PASSIVE — sending NO frames")
    print()
    print("    Watching for:")
    print("    • Beacons with empty SSID  (hidden AP detected)")
    print("    • Probe Responses          (SSID revealed by AP)")
    print("    • Directed Probe Requests  (SSID revealed by client)")
    print("    Ctrl-C to stop.\n")

    def on_sigint(sig, frame):
        print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    timeout = args.duration if args.duration > 0 else None
    sniff(
        iface=args.iface,
        prn=handle_packet,
        store=False,
        timeout=timeout,
        lfilter=lambda p: (
            p.haslayer(Dot11) and p[Dot11].type == 0
            and p[Dot11].subtype in (4, 5, 8)
        ),
    )

    print_summary()


if __name__ == "__main__":
    main()
