#!/usr/bin/env python3
"""
02_recon/07_beacon_fingerprint.py — Deep-dive beacon analysis and AP fingerprinting.

Every beacon frame is a CV the AP broadcasts 10 times per second.
This script reads that CV very carefully.

Extracts: Wi-Fi generation (802.11 b/g/n/ac/ax), supported rates,
RSN details (ciphers, AKMs, PMF), WPS status, country code,
vendor-specific tags, and estimated AP manufacturer.

Usage:
    sudo python3 02_recon/07_beacon_fingerprint.py --iface wlan1
    sudo python3 02_recon/07_beacon_fingerprint.py --iface wlan1 --bssid AA:BB:CC:DD:EE:FF
    sudo python3 02_recon/07_beacon_fingerprint.py --iface wlan1 --output fingerprints.json

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import signal
import sys
import time
from datetime import datetime

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid, get_rssi, get_channel,
    require_root, require_monitor_mode,
    add_iface_arg, add_output_arg, add_duration_arg,
    parse_bssid_arg,
    safe_write_json,
)


# ──────────────────────────────────────────────
# Known vendor OUIs for tag 221 (Vendor Specific)
# These appear inside beacon frames and reveal the chipset/platform.
# ──────────────────────────────────────────────

_VENDOR_OUI: dict[bytes, str] = {
    b"\x00\x50\xf2": "Microsoft",      # WPA1, WPS, P2P
    b"\x00\x0f\xac": "IEEE 802.11",    # RSN standard OUI
    b"\x00\x17\xf2": "Apple",          # Apple-specific IE
    b"\x00\x90\x4c": "Epigram",        # Pre-standard 802.11n
    b"\x8c\xfd\xf0": "Apple",          # Apple vendor IE
    b"\x00\x13\x92": "Atheros",
    b"\x00\x03\x7f": "Atheros",
    b"\x00\x90\x4c": "Ralink",
    b"\x50\x6f\x9a": "Wi-Fi Alliance",  # P2P / Hotspot 2.0
    b"\x00\x1a\x11": "Google",
}

# Microsoft vendor tag subtypes
_MS_WPA1  = 0x01  # WPA1 IE
_MS_WMM   = 0x02  # WMM/WME
_MS_WPS   = 0x04  # Wi-Fi Protected Setup

# Wi-Fi generation labels based on tag presence
# We determine this from capability tags, not marketing.
_WIFI_GEN: dict[str, str] = {
    "ax":  "Wi-Fi 6 (802.11ax)",
    "ac":  "Wi-Fi 5 (802.11ac)",
    "n":   "Wi-Fi 4 (802.11n)",
    "g":   "802.11g",
    "b":   "802.11b",
    "a":   "802.11a",
}


# ──────────────────────────────────────────────
# Tag parsers
# ──────────────────────────────────────────────

def _parse_supported_rates(data: bytes) -> list[float]:
    """
    Decode supported rates from tags 1 and 50.
    Rates are encoded as (value & 0x7F) / 2 Mbps.
    Bit 7 = 'basic rate' (mandatory). We ignore that distinction here.
    """
    rates = []
    for b in data:
        mbps = (b & 0x7F) / 2.0
        rates.append(mbps)
    return sorted(set(rates))


def _parse_rsn_ie(data: bytes) -> dict:
    """
    Parse RSN Information Element (tag 48).
    This is where WPA2/WPA3 stores all the interesting security details.
    """
    result = {
        "version": None, "group_cipher": None,
        "pairwise_ciphers": [], "akm_suites": [],
        "pmf_capable": False, "pmf_required": False,
        "pmkid_count": 0,
    }
    CIPHER_NAMES = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104",
                    8: "GCMP-128", 9: "GCMP-256", 0: "Use Group"}
    AKM_NAMES    = {1: "EAP", 2: "PSK", 3: "FT-EAP", 4: "FT-PSK",
                    5: "EAP-SHA256", 6: "PSK-SHA256", 8: "SAE (WPA3)",
                    18: "OWE", 24: "SAE-EXT"}
    try:
        pos = 0
        if pos + 2 > len(data): return result
        result["version"] = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        if pos + 4 > len(data): return result
        result["group_cipher"] = CIPHER_NAMES.get(data[pos+3], f"?({data[pos+3]})")
        pos += 4
        if pos + 2 > len(data): return result
        count = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        for _ in range(count):
            if pos + 4 > len(data): break
            result["pairwise_ciphers"].append(CIPHER_NAMES.get(data[pos+3], f"?({data[pos+3]})"))
            pos += 4
        if pos + 2 > len(data): return result
        count = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        for _ in range(count):
            if pos + 4 > len(data): break
            result["akm_suites"].append(AKM_NAMES.get(data[pos+3], f"?({data[pos+3]})"))
            pos += 4
        if pos + 2 <= len(data):
            caps = int.from_bytes(data[pos:pos+2], "little")
            result["pmf_capable"]  = bool(caps & 0x0080)
            result["pmf_required"] = bool(caps & 0x0040)
            pos += 2
        if pos + 2 <= len(data):
            result["pmkid_count"] = int.from_bytes(data[pos:pos+2], "little")
    except Exception:
        pass
    return result


def _parse_wps_ie(data: bytes) -> dict:
    """
    Parse the WPS Information Element (vendor tag with MS OUI, type 0x04).
    WPS attributes are TLV-encoded. We extract the most useful ones.
    Returns version, device name, WPS state, and lockout status.
    """
    result = {"version": None, "state": None, "locked": False, "device_name": None,
              "manufacturer": None, "model": None, "uuid": None}
    WPS_ATTR = {
        0x1001: "ap_setup_locked",
        0x1008: "config_methods",
        0x1011: "device_name",
        0x1012: "device_password_id",
        0x1021: "manufacturer",
        0x1023: "model_name",
        0x1044: "wps_state",
        0x104a: "version",
        0x1049: "vendor_ext",
        0x1047: "uuid_e",
    }
    try:
        pos = 0
        while pos + 4 <= len(data):
            attr_id  = int.from_bytes(data[pos:pos+2], "big")
            attr_len = int.from_bytes(data[pos+2:pos+4], "big")
            pos += 4
            if pos + attr_len > len(data):
                break
            val = data[pos:pos+attr_len]
            pos += attr_len

            if attr_id == 0x104a:   # version
                result["version"] = f"{val[0] >> 4}.{val[0] & 0xF}" if val else None
            elif attr_id == 0x1044: # state: 1=unconfigured, 2=configured
                result["state"] = "configured" if val and val[0] == 2 else "unconfigured"
            elif attr_id == 0x1001: # AP setup locked
                result["locked"] = bool(val and val[0])
            elif attr_id == 0x1011: # device name
                result["device_name"] = val.decode("utf-8", errors="replace").strip()
            elif attr_id == 0x1021: # manufacturer
                result["manufacturer"] = val.decode("utf-8", errors="replace").strip()
            elif attr_id == 0x1023: # model
                result["model"] = val.decode("utf-8", errors="replace").strip()
            elif attr_id == 0x1047: # UUID-E
                result["uuid"] = val.hex()
    except Exception:
        pass
    return result


def _parse_ht_caps(data: bytes) -> dict:
    """HT Capabilities (tag 45) → 802.11n support details."""
    if not data or len(data) < 2:
        return {}
    caps = int.from_bytes(data[0:2], "little")
    return {
        "sgi_20":  bool(caps & 0x0020),   # Short Guard Interval 20MHz
        "sgi_40":  bool(caps & 0x0040),   # Short Guard Interval 40MHz
        "mimo_40": bool(caps & 0x0002),   # 40MHz channel support
    }


def _parse_vht_caps(data: bytes) -> dict:
    """VHT Capabilities (tag 191) → 802.11ac support."""
    if not data or len(data) < 4:
        return {}
    caps = int.from_bytes(data[0:4], "little")
    max_mcs = (caps >> 2) & 0x1FFF  # rough decode, not critical
    return {
        "max_mpdu": ["3895", "7991", "11454"][caps & 0x03] if (caps & 0x03) < 3 else "?",
        "su_beamformer": bool(caps & (1 << 11)),
        "mu_beamformer": bool(caps & (1 << 19)),
    }


def _parse_country(data: bytes) -> str | None:
    """Country Information Element (tag 7) — regulatory domain."""
    if not data or len(data) < 2:
        return None
    try:
        return data[:2].decode("ascii", errors="replace").strip()
    except Exception:
        return None


def _wifi_generation(has_he: bool, has_vht: bool, has_ht: bool, rates: list[float]) -> str:
    """
    Determine the highest supported Wi-Fi generation.
    The logic is simple but the marketing names are not.

    802.11a operates on 5 GHz with up to 54 Mbps, but cannot be identified
    by rates alone (802.11g also uses 54 Mbps on 2.4 GHz). A legacy 'a'
    band AP has no HT/VHT tags and operates on a channel above 14.
    Without channel context here we fall through to 'unknown' rather than
    guess incorrectly — which is better than silently lying.
    """
    if has_he:  return _WIFI_GEN["ax"]
    if has_vht: return _WIFI_GEN["ac"]
    if has_ht:  return _WIFI_GEN["n"]
    if 54.0 in rates: return _WIFI_GEN["g"]
    if 11.0 in rates: return _WIFI_GEN["b"]
    return "unknown"


# ──────────────────────────────────────────────
# Main parsing entry point
# ──────────────────────────────────────────────

def fingerprint_beacon(pkt) -> dict | None:
    """
    Extract everything interesting from a single beacon frame.
    Returns a dict or None if the frame is unusable.
    """
    if not pkt.haslayer(Dot11Beacon):
        return None
    dot11 = pkt[Dot11]
    bssid = dot11.addr3
    if not bssid:
        return None
    bssid = bssid.lower()

    fp: dict = {
        "bssid":       bssid,
        "ssid":        get_ssid(pkt) or "<hidden>",
        "channel":     get_channel(pkt),
        "country":     None,
        "wifi_gen":    None,
        "rates_mbps":  [],
        "has_ht":      False,
        "has_vht":     False,
        "has_he":      False,
        "ht_caps":     {},
        "vht_caps":    {},
        "rsn":         {},
        "has_wpa1":    False,
        "wps":         {},
        "vendor_tags": [],
        "pmf":         False,
        "rssi_dbm":    get_rssi(pkt),
        "timestamp":   datetime.now().isoformat(timespec="seconds"),
    }

    all_rates: list[float] = []

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        info = bytes(elt.info) if elt.info else b""

        if elt.ID == 1:  # Supported Rates
            all_rates += _parse_supported_rates(info)

        elif elt.ID == 50: # Extended Supported Rates
            all_rates += _parse_supported_rates(info)

        elif elt.ID == 7:  # Country
            fp["country"] = _parse_country(info)

        elif elt.ID == 45: # HT Capabilities → 802.11n
            fp["has_ht"]   = True
            fp["ht_caps"]  = _parse_ht_caps(info)

        elif elt.ID == 191: # VHT Capabilities → 802.11ac
            fp["has_vht"]  = True
            fp["vht_caps"] = _parse_vht_caps(info)

        elif elt.ID == 255: # Extension element → 802.11ax (HE)
            if info and info[0] == 35:  # Extension ID 35 = HE Capabilities
                fp["has_he"] = True

        elif elt.ID == 48:  # RSN IE → WPA2/WPA3
            fp["rsn"] = _parse_rsn_ie(info)
            fp["pmf"] = fp["rsn"].get("pmf_required", False)

        elif elt.ID == 221: # Vendor Specific
            if len(info) >= 4:
                oui      = info[:3]
                sub_type = info[3]
                oui_name = _VENDOR_OUI.get(oui, oui.hex(":"))

                if oui == b"\x00\x50\xf2":  # Microsoft OUI
                    if sub_type == _MS_WPA1:
                        fp["has_wpa1"] = True
                    elif sub_type == _MS_WPS:
                        fp["wps"] = _parse_wps_ie(info[4:])

                fp["vendor_tags"].append({
                    "oui":      oui.hex(":"),
                    "oui_name": oui_name,
                    "subtype":  sub_type,
                })

        if not isinstance(getattr(elt, "payload", None), Dot11Elt):
            break
        elt = elt.payload

    fp["rates_mbps"] = sorted(set(all_rates))
    fp["wifi_gen"]   = _wifi_generation(fp["has_he"], fp["has_vht"], fp["has_ht"], all_rates)
    return fp


# ──────────────────────────────────────────────
# State and display
# ──────────────────────────────────────────────

_fingerprints: dict[str, dict] = {}  # bssid → fingerprint
_target_bssid: str | None = None
_start_time = time.time()


def handle_packet(pkt):
    fp = fingerprint_beacon(pkt)
    if not fp:
        return
    if _target_bssid and fp["bssid"] != _target_bssid:
        return

    bssid  = fp["bssid"]
    is_new = bssid not in _fingerprints
    _fingerprints[bssid] = fp

    if is_new:
        _print_fingerprint(fp)


def _print_fingerprint(fp: dict):
    """Pretty-print a single AP fingerprint. The CV reading."""
    wps_str = ""
    if fp["wps"]:
        w = fp["wps"]
        locked = " 🔒LOCKED" if w.get("locked") else ""
        wps_str = (f"  WPS v{w.get('version','?')}"
                   f"  state:{w.get('state','?')}{locked}"
                   f"  device:{w.get('device_name') or w.get('manufacturer') or '?'}")

    rsn = fp["rsn"]
    akms = ", ".join(rsn.get("akm_suites", [])) or "none"
    ciphers = ", ".join(rsn.get("pairwise_ciphers", [])) or "none"
    pmf_str = "Required" if rsn.get("pmf_required") else ("Capable" if rsn.get("pmf_capable") else "Disabled")

    print(f"\n  {'─'*60}")
    print(f"  BSSID      : {fp['bssid']}")
    print(f"  SSID       : {fp['ssid']}")
    print(f"  Channel    : {fp['channel']}  |  Country: {fp['country'] or '?'}")
    print(f"  Generation : {fp['wifi_gen']}")
    print(f"  Rates      : {fp['rates_mbps']} Mbps")
    print(f"  Signal     : {fp['rssi_dbm']} dBm" if fp["rssi_dbm"] else "  Signal     : ?")

    if rsn:
        print(f"  RSN/WPA2+  : group={rsn.get('group_cipher','?')}  "
              f"pairwise={ciphers}")
        print(f"  AKM        : {akms}")
        print(f"  PMF        : {pmf_str}")
    elif fp["has_wpa1"]:
        print(f"  Security   : WPA1 (please update this router)")
    else:
        print(f"  Security   : [OPEN] or WEP (please have a word with the admin)")

    if fp["wps"]:
        print(f"  WPS        :{wps_str}")

    if fp["ht_caps"]:
        h = fp["ht_caps"]
        print(f"  HT caps    : SGI-20:{h['sgi_20']}  SGI-40:{h['sgi_40']}  "
              f"40MHz:{h['mimo_40']}")
    if fp["vht_caps"]:
        v = fp["vht_caps"]
        print(f"  VHT caps   : max MPDU:{v['max_mpdu']}  SU-BF:{v['su_beamformer']}  "
              f"MU-BF:{v['mu_beamformer']}")
    if fp["has_he"]:
        print(f"  HE (Wi-Fi6): ✓ supported")

    vendor_summary = ", ".join(
        set(t["oui_name"] for t in fp["vendor_tags"])
    ) or "none"
    print(f"  Vendor IEs : {vendor_summary}")


def print_summary():
    elapsed = int(time.time() - _start_time)
    print(f"\n\n{'═' * 60}")
    print(f"  FINGERPRINT SUMMARY — {len(_fingerprints)} APs | {elapsed}s")
    print(f"{'═' * 60}")

    gen_counts: dict[str, int] = {}
    wps_count  = 0
    open_count = 0
    for fp in _fingerprints.values():
        gen = fp["wifi_gen"] or "?"
        gen_counts[gen] = gen_counts.get(gen, 0) + 1
        if fp["wps"]:
            wps_count += 1
        if not fp["rsn"] and not fp["has_wpa1"]:
            open_count += 1

    print(f"\n  Wi-Fi generations:")
    for gen, count in sorted(gen_counts.items()):
        print(f"    {gen:<30} {count}")
    print(f"\n  WPS enabled         : {wps_count} APs")
    print(f"  Open / WEP          : {open_count} APs")


def main():
    global _target_bssid

    require_root()

    parser = argparse.ArgumentParser(
        description="Deep beacon fingerprinting — reads an AP's CV from the air.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Detects: Wi-Fi generation, encryption suite, PMF, WPS version,\n"
            "         vendor-specific capabilities, and regulatory domain.\n"
            "Useful for: threat modeling, misconfig detection, asset inventory."
        ),
    )
    add_iface_arg(parser)
    parser.add_argument("--bssid", default=None, help="Focus on a specific AP")
    add_output_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    _target_bssid = parse_bssid_arg(args.bssid)

    require_monitor_mode(args.iface)

    print(f"\n=== 02_recon/07_beacon_fingerprint.py ===")
    print(f"    Interface : {args.iface}")
    print(f"    Target    : {_target_bssid or 'all APs'}")
    print(f"    Mode      : PASSIVE — sending NO frames")
    print("    Ctrl-C to stop.\n")

    def on_sigint(sig, frame):
        print_summary()
        if args.output:
            safe_write_json({
                "captured_at": datetime.now().isoformat(timespec="seconds"),
                "total_aps":   len(_fingerprints),
                "fingerprints": list(_fingerprints.values()),
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

    print_summary()
    if args.output:
        safe_write_json({
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "total_aps":   len(_fingerprints),
            "fingerprints": list(_fingerprints.values()),
        }, args.output)


if __name__ == "__main__":
    main()
