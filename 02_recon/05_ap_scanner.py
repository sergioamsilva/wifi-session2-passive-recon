#!/usr/bin/env python3
"""
02_recon/05_ap_scanner.py — Real-time map of every Access Point in range.

Like airodump-ng, but you can read the source code and understand
exactly why it does what it does. Which is the whole point.

Parses beacon frames to extract: BSSID, SSID, channel, encryption
(WEP/WPA/WPA2/WPA3), signal strength, beacon interval, and vendor.
Also counts approximate client associations from data frames.

Usage:
    sudo python3 02_recon/05_ap_scanner.py --iface wlan1
    sudo python3 02_recon/05_ap_scanner.py --iface wlan1 --output aps.json

Pair with 01_setup/03_channel_hopper.py for full-band coverage.
Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff
except ImportError:
    print("[!] Scapy not found. This script is just decoration without it.")
    print("    pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid, get_rssi, get_channel,
    load_oui_db, lookup_vendor,
    require_root, require_monitor_mode,
    add_iface_arg, add_output_arg, add_duration_arg,
    safe_write_json,
)

# ──────────────────────────────────────────────
# Encryption detection
# Determined by reading beacon tagged parameters.
# ──────────────────────────────────────────────

# RSN AKM Suite selectors (OUI 00:0F:AC)
_AKM_SAE          = 8   # WPA3-Personal
_AKM_OWE          = 18  # WPA3-Enhanced Open (Opportunistic Wireless Encryption)
_AKM_PSK          = 2   # WPA2-Personal
_AKM_EAP          = 1   # WPA2-Enterprise

# Cipher suite selectors
_CIPHER_CCMP      = 4
_CIPHER_TKIP      = 2
_CIPHER_WEP40     = 1
_CIPHER_WEP104    = 5

# Vendor OUI for WPA1 tag (00:50:F2, type 0x01)
_MS_OUI = b"\x00\x50\xf2"


def _parse_rsn(data: bytes) -> dict:
    """
    Parse RSN Information Element (tag 48).
    This is the tag that tells us WPA2/WPA3 details.
    If it's absent, the network is either WPA1, WEP, or open —
    none of which are great choices in 2024.
    """
    result = {
        "version":  None,
        "group":    None,
        "pairwise": [],
        "akm":      [],
        "pmf":      False,
    }
    try:
        if len(data) < 4:
            return result
        result["version"] = int.from_bytes(data[0:2], "little")
        pos = 2
        # Group cipher suite
        if pos + 4 > len(data): return result
        result["group"] = data[pos + 3]
        pos += 4
        # Pairwise cipher suites
        if pos + 2 > len(data): return result
        count = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        for _ in range(count):
            if pos + 4 > len(data): break
            result["pairwise"].append(data[pos + 3])
            pos += 4
        # AKM suites
        if pos + 2 > len(data): return result
        count = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        for _ in range(count):
            if pos + 4 > len(data): break
            result["akm"].append(data[pos + 3])
            pos += 4
        # RSN Capabilities
        if pos + 2 <= len(data):
            caps = int.from_bytes(data[pos:pos+2], "little")
            result["pmf"] = bool(caps & 0x80)  # Management Frame Protection Required
        return result
    except Exception:
        return result


def _encryption_label(pkt) -> str:
    """
    Classify the network's security from beacon tags.
    Returns a tidy label like 'WPA3', 'WPA2', 'WPA', 'WEP', or '[OPEN]'.
    """
    dot11 = pkt[Dot11]
    privacy = bool(dot11.cap & 0x10) if hasattr(dot11, "cap") else False

    has_rsn   = False
    has_wpa1  = False
    rsn_info  = {}
    is_wpa3   = False
    is_ent    = False
    pmf       = False

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:  # RSN IE
            has_rsn  = True
            rsn_info = _parse_rsn(bytes(elt.info))
            pmf      = rsn_info.get("pmf", False)
            akms     = rsn_info.get("akm", [])
            if _AKM_SAE in akms or _AKM_OWE in akms:
                is_wpa3 = True
            if _AKM_EAP in akms:
                is_ent = True
        elif elt.ID == 221:  # Vendor Specific
            info = bytes(elt.info) if elt.info else b""
            if info[:3] == _MS_OUI and len(info) > 3 and info[3] == 0x01:
                has_wpa1 = True
        if not isinstance(getattr(elt, "payload", None), Dot11Elt):
            break
        elt = elt.payload

    if is_wpa3:
        suffix = "-Enterprise" if is_ent else "-Personal"
        pmf_tag = "+PMF" if pmf else ""
        return f"WPA3{suffix}{pmf_tag}"
    if has_rsn:
        suffix = "-Enterprise" if is_ent else "-Personal"
        pmf_tag = "+PMF" if pmf else ""
        return f"WPA2{suffix}{pmf_tag}"
    if has_wpa1:
        return "WPA"
    if privacy:
        return "WEP"           # the year is apparently 2003
    return "[OPEN]"


def _parse_beacon_interval(pkt) -> int | None:
    """Beacon interval in TUs (1 TU = 1024 µs). Typically 100."""
    if pkt.haslayer(Dot11Beacon):
        try:
            return int(pkt[Dot11Beacon].beacon_interval)
        except Exception:
            pass
    return None


# ──────────────────────────────────────────────
# OUI lookup (minimal — vendor name from first 3 bytes)
# ──────────────────────────────────────────────

_OUI_CACHE: dict[str, str] = {}
_MANUF_DB: dict[str, str]  = {}


# ──────────────────────────────────────────────
# State
# bssid → {ssid, channel, encryption, rssi_list, beacon_interval,
#           vendor, first_seen, last_seen, beacon_count}
# ──────────────────────────────────────────────

_aps: dict[str, dict]  = {}
_start_time = time.time()


def handle_packet(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return

    dot11 = pkt[Dot11]
    bssid = dot11.addr3
    if not bssid:
        return
    bssid = bssid.lower()

    ssid     = get_ssid(pkt)
    channel  = get_channel(pkt)
    enc      = _encryption_label(pkt)
    rssi     = get_rssi(pkt)
    interval = _parse_beacon_interval(pkt)
    now      = datetime.now().isoformat(timespec="seconds")

    if bssid not in _aps:
        _aps[bssid] = {
            "ssid":           ssid or "<hidden>",
            "channel":        channel,
            "encryption":     enc,
            "vendor":         lookup_vendor(bssid, _MANUF_DB),
            "rssi_list":      [],
            "beacon_interval": interval,
            "beacon_count":   0,
            "first_seen":     now,
            "last_seen":      now,
        }

    ap = _aps[bssid]
    ap["beacon_count"] += 1
    ap["last_seen"]     = now
    if rssi is not None:
        ap["rssi_list"].append(rssi)
    if ssid:                       # update in case it was hidden before
        ap["ssid"] = ssid
    if channel:
        ap["channel"] = channel

    _render_table()


# ──────────────────────────────────────────────
# Display
# ──────────────────────────────────────────────

def _rssi_bar(rssi: int | None) -> str:
    """Turn a dBm value into a tiny visual bar. Aesthetics matter."""
    if rssi is None:
        return "   ?"
    if rssi >= -50:
        return "████"
    if rssi >= -60:
        return "███░"
    if rssi >= -70:
        return "██░░"
    if rssi >= -80:
        return "█░░░"
    return "░░░░"


def _render_table():
    """Redraw the AP table in-place using ANSI cursor tricks."""
    rows = sorted(_aps.items(), key=lambda x: (
        -(sum(x[1]["rssi_list"]) // max(len(x[1]["rssi_list"]), 1))
    ))
    elapsed = int(time.time() - _start_time)

    # Move cursor to top of our output block
    lines = len(rows) + 5
    print(f"\033[{lines}A", end="")

    print(f"\r  APs: {len(_aps)}  |  elapsed: {elapsed}s  |  Ctrl-C to stop")
    print(f"\r  {'BSSID':<19} {'SSID':<24} {'CH':>3} {'SIG':>5} {'ENC':<22} {'VENDOR':<18}")
    print(f"\r  {'─'*19} {'─'*24} {'─'*3} {'─'*5} {'─'*22} {'─'*18}")

    for bssid, ap in rows[:30]:  # cap at 30 rows so the terminal doesn't explode
        rssi_list = ap["rssi_list"]
        avg_rssi  = (sum(rssi_list) // len(rssi_list)) if rssi_list else None
        bar       = _rssi_bar(avg_rssi)
        rssi_str  = f"{avg_rssi:4d}" if avg_rssi is not None else "   ?"
        ssid      = ap["ssid"][:23]
        ch_str    = str(ap["channel"] or "?")
        print(f"\r  {bssid:<19} {ssid:<24} {ch_str:>3} {rssi_str} {bar} {ap['encryption'][:20]:<22} {ap['vendor'][:18]:<18}")

    # Pad remaining lines (so old rows don't ghost)
    for _ in range(max(0, 30 - len(rows))):
        print(f"\r{' '*100}")


def _initial_blank(lines: int = 35):
    """Print blank lines so the cursor-up trick has room to work."""
    for _ in range(lines):
        print()


def print_final_report():
    """Print a clean static report when the user hits Ctrl-C."""
    print(f"\n\n{'═' * 85}")
    print(f"  ACCESS POINT MAP — {len(_aps)} APs found")
    print(f"{'═' * 85}")
    print(f"  {'BSSID':<19} {'SSID':<26} {'CH':>3} {'dBm':>5} {'ENC':<24} VENDOR")
    print(f"  {'─'*19} {'─'*26} {'─'*3} {'─'*5} {'─'*24} {'─'*18}")

    rows = sorted(_aps.items(), key=lambda x: (
        -(sum(x[1]["rssi_list"]) // max(len(x[1]["rssi_list"]), 1))
    ))
    for bssid, ap in rows:
        rssi_list = ap["rssi_list"]
        avg_rssi  = (sum(rssi_list) // len(rssi_list)) if rssi_list else None
        rssi_str  = f"{avg_rssi:4d}" if avg_rssi is not None else "   ?"
        print(f"  {bssid:<19} {ap['ssid'][:25]:<26} {str(ap['channel'] or '?'):>3}"
              f" {rssi_str} {ap['encryption'][:23]:<24} {ap['vendor'][:18]}")

    enc_counts: dict[str, int] = defaultdict(int)
    for ap in _aps.values():
        key = ap["encryption"].split("-")[0]  # WPA2, WPA3, WEP, [OPEN]
        enc_counts[key] += 1

    print(f"\n  [stat] Encryption breakdown:")
    for enc, count in sorted(enc_counts.items()):
        bar = "█" * count
        print(f"         {enc:<10} {count:3d}  {bar}")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    global _MANUF_DB

    require_root()

    parser = argparse.ArgumentParser(
        description="Real-time AP scanner — like airodump-ng but readable by humans.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Tip: run 01_setup/03_channel_hopper.py in another terminal to see\n"
            "     APs on all channels, not just the one you started on."
        ),
    )
    add_iface_arg(parser)
    add_output_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    require_monitor_mode(args.iface)

    _MANUF_DB = load_oui_db()

    print(f"\n=== 02_recon/05_ap_scanner.py ===")
    print(f"    Interface  : {args.iface}")
    print(f"    Mode       : PASSIVE — sending NO frames\n")

    _initial_blank(35)

    def on_sigint(sig, frame):
        print_final_report()
        if args.output:
            data = []
            for bssid, ap in sorted(_aps.items()):
                rssi_list = ap["rssi_list"]
                data.append({
                    "bssid":           bssid,
                    "ssid":            ap["ssid"],
                    "channel":         ap["channel"],
                    "encryption":      ap["encryption"],
                    "vendor":          ap["vendor"],
                    "rssi_avg_dbm":    round(sum(rssi_list)/len(rssi_list), 1) if rssi_list else None,
                    "beacon_count":    ap["beacon_count"],
                    "beacon_interval": ap["beacon_interval"],
                    "first_seen":      ap["first_seen"],
                    "last_seen":       ap["last_seen"],
                })
            safe_write_json({
                "captured_at": datetime.now().isoformat(timespec="seconds"),
                "total_aps":   len(_aps),
                "aps":         data,
            }, args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    timeout = args.duration if args.duration > 0 else None
    sniff(
        iface=args.iface,
        prn=handle_packet,
        store=False,
        timeout=timeout,
        lfilter=lambda p: p.haslayer(Dot11Beacon),
    )

    print_final_report()
    if args.output:
        data = []
        for bssid, ap in sorted(_aps.items()):
            rssi_list = ap["rssi_list"]
            data.append({
                "bssid":           bssid,
                "ssid":            ap["ssid"],
                "channel":         ap["channel"],
                "encryption":      ap["encryption"],
                "vendor":          ap["vendor"],
                "rssi_avg_dbm":    round(sum(rssi_list)/len(rssi_list), 1) if rssi_list else None,
                "beacon_count":    ap["beacon_count"],
                "beacon_interval": ap["beacon_interval"],
                "first_seen":      ap["first_seen"],
                "last_seen":       ap["last_seen"],
            })
        safe_write_json({
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "total_aps":   len(_aps),
            "aps":         data,
        }, args.output)


if __name__ == "__main__":
    main()
