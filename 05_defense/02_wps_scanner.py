#!/usr/bin/env python3
"""
05_defense/02_wps_scanner.py — Detect APs with WPS enabled and assess their vulnerability.

Wi-Fi Protected Setup was a great idea in 2006 if you've never heard of
the Pixie Dust attack, the PIN brute-force attack, or basic threat modeling.

The WPS PIN is 8 digits. The AP validates the first 4 and second 4 digits
separately, which reduces the search space from 10^8 (100,000,000) to
10^4 + 10^3 (11,000). Tools like reaver and bully can crack it in hours.

The Pixie Dust attack (2014) works in seconds on vulnerable chipsets
by exploiting weak random number generation in the WPS exchange.

WPS 2.0 introduced lockout mechanisms. Many APs implement them poorly.

This script passively identifies WPS-enabled APs from beacon frames,
extracts version and configuration data, and flags vulnerable configurations.

Usage:
    sudo python3 05_defense/02_wps_scanner.py --iface wlan1
    sudo python3 05_defense/02_wps_scanner.py --iface wlan1 --output wps.json

Pair with 01_setup/03_channel_hopper.py for full coverage.
Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 3
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
    get_ssid,
    get_rssi,
    get_channel,
    require_root,
    require_monitor_mode,
    add_iface_arg,
    add_output_arg,
    add_duration_arg,
    safe_write_json,
)


# ──────────────────────────────────────────────
# WPS Information Element constants
#
# WPS IE = Vendor Specific tag (ID 221) with OUI 00:50:F2, subtype 0x04
# Inside: TLV-encoded attributes
# ──────────────────────────────────────────────

_MS_OUI   = b"\x00\x50\xf2"
_WPS_TYPE = 0x04

# WPS attribute IDs we care about
_WPS_VERSION             = 0x104A
_WPS_STATE               = 0x1044  # 1=unconfigured, 2=configured
_WPS_AP_SETUP_LOCKED     = 0x1001  # 0x01 = locked after too many fails
_WPS_DEVICE_NAME         = 0x1011
_WPS_MANUFACTURER        = 0x1021
_WPS_MODEL_NAME          = 0x1023
_WPS_MODEL_NUMBER        = 0x1024
_WPS_SERIAL_NUMBER       = 0x1042
_WPS_UUID_E              = 0x1047
_WPS_CONFIG_METHODS      = 0x1008  # bitmask of supported config methods
_WPS_RESPONSE_TYPE       = 0x103B
_WPS_SELECTED_REGISTRAR  = 0x1041  # 0x01 = active registrar session open
_WPS_DEVICE_PWD_ID       = 0x1012  # 0x0000=default PIN, 0x0004=push button

# Config method bitmask (partial)
_CONFIG_PUSH_BUTTON = 0x0080
_CONFIG_DISPLAY     = 0x0008
_CONFIG_LABEL_PIN   = 0x0004
_CONFIG_KEYPAD      = 0x0100

# Chipsets known to be vulnerable to Pixie Dust (partial list)
# Based on public Pixie Dust attack research — Dominique Bongard, 2014
_PIXIE_DUST_VENDORS = {
    "Ralink", "MediaTek", "Realtek", "Broadcom",
    "RaLink", "Atheros", "Qualcomm Atheros",
}


def _parse_wps_ie(data: bytes) -> dict:
    """
    Decode the WPS Information Element (TLV format).
    Returns a dict of all attributes we found and care about.
    """
    result = {
        "version":         None,
        "version2":        None,
        "state":           None,
        "locked":          False,
        "registrar_open":  False,
        "device_name":     None,
        "manufacturer":    None,
        "model_name":      None,
        "model_number":    None,
        "serial":          None,
        "uuid":            None,
        "config_methods":  [],
        "device_pwd_id":   None,
        "raw_attrs":       {},
    }

    try:
        pos = 0
        while pos + 4 <= len(data):
            attr_id  = int.from_bytes(data[pos:pos+2], "big")
            attr_len = int.from_bytes(data[pos+2:pos+4], "big")
            pos += 4
            if pos + attr_len > len(data):
                break
            val = data[pos: pos + attr_len]
            pos += attr_len

            if attr_id == _WPS_VERSION:
                if val:
                    result["version"] = f"{val[0] >> 4}.{val[0] & 0x0F}"

            elif attr_id == _WPS_STATE:
                result["state"] = "configured" if (val and val[0] == 2) else "unconfigured"

            elif attr_id == _WPS_AP_SETUP_LOCKED:
                result["locked"] = bool(val and val[0])

            elif attr_id == _WPS_SELECTED_REGISTRAR:
                result["registrar_open"] = bool(val and val[0])

            elif attr_id == _WPS_DEVICE_NAME:
                result["device_name"] = val.decode("utf-8", errors="replace").strip()

            elif attr_id == _WPS_MANUFACTURER:
                result["manufacturer"] = val.decode("utf-8", errors="replace").strip()

            elif attr_id == _WPS_MODEL_NAME:
                result["model_name"] = val.decode("utf-8", errors="replace").strip()

            elif attr_id == _WPS_MODEL_NUMBER:
                result["model_number"] = val.decode("utf-8", errors="replace").strip()

            elif attr_id == _WPS_SERIAL_NUMBER:
                result["serial"] = val.decode("utf-8", errors="replace").strip()

            elif attr_id == _WPS_UUID_E:
                result["uuid"] = val.hex()

            elif attr_id == _WPS_CONFIG_METHODS:
                methods = []
                if val and len(val) >= 2:
                    cm = int.from_bytes(val, "big")
                    if cm & _CONFIG_PUSH_BUTTON: methods.append("PBC")
                    if cm & _CONFIG_DISPLAY:     methods.append("Display")
                    if cm & _CONFIG_LABEL_PIN:   methods.append("Label-PIN")
                    if cm & _CONFIG_KEYPAD:      methods.append("Keypad")
                result["config_methods"] = methods

            elif attr_id == _WPS_DEVICE_PWD_ID:
                if val and len(val) >= 2:
                    dpid = int.from_bytes(val, "big")
                    result["device_pwd_id"] = {
                        0x0000: "Default PIN",
                        0x0004: "Push Button (PBC)",
                        0x000A: "Registrar-specified",
                        0x000B: "NFC",
                    }.get(dpid, f"0x{dpid:04x}")

            # WPS 2.0 extension (inside vendor ext attribute)
            elif attr_id == 0x1049:
                # Walk the extensions looking for WFA ext (OUI 00:37:2A)
                ep = 0
                while ep + 4 <= len(val):
                    ext_id  = val[ep]
                    ext_len = val[ep + 1]
                    ep += 2
                    ext_val = val[ep: ep + ext_len]
                    ep += ext_len
                    if ext_id == 0x00 and len(ext_val) >= 4:
                        if ext_val[:3] == b"\x00\x37\x2a":
                            sub = ext_val[3]
                            if sub == 0x00:  # Version2
                                if len(ext_val) > 4:
                                    v = ext_val[4]
                                    result["version2"] = f"{v >> 4}.{v & 0x0F}"

    except Exception:
        pass

    return result


def _assess_risk(wps: dict) -> tuple[str, list[str]]:
    """
    Produce a risk label and list of findings for this WPS configuration.
    Honest, not alarmist. But also: genuinely alarming where warranted.
    """
    findings = []
    risk     = "LOW"

    if wps["locked"]:
        findings.append("WPS is locked — previous brute-force attempts likely")
        # Locked is actually good — means it resisted attack (or someone tried)
        return "INFO", findings

    if wps["registrar_open"]:
        findings.append("Active WPS registrar session open — WPS PIN exchange in progress")
        risk = "HIGH"

    if wps["version"] and wps["version"].startswith("1"):
        findings.append(f"WPS version {wps['version']} — vulnerable to PIN brute-force (reaver/bully)")
        risk = "HIGH"
        mfr = wps.get("manufacturer") or ""
        for vendor in _PIXIE_DUST_VENDORS:
            if vendor.lower() in mfr.lower():
                findings.append(f"Manufacturer '{mfr}' is on the Pixie Dust vulnerable list")
                findings.append("Try: reaver --pixie-dust (may crack in seconds)")
                risk = "CRITICAL"
                break

    if wps["version2"] or (wps["version"] and wps["version"].startswith("2")):
        findings.append(f"WPS 2.0 detected — lockout mechanism present (but often misconfigured)")
        if risk == "LOW":
            risk = "MEDIUM"

    if not wps["state"] or wps["state"] == "unconfigured":
        findings.append("WPS state: unconfigured — AP may accept any registrar")
        risk = "HIGH"

    if "PBC" in wps.get("config_methods", []):
        findings.append("Push Button Config (PBC) enabled — physical access = instant join")

    if not findings:
        findings.append("WPS enabled with no obvious misconfiguration")
        risk = "LOW"

    return risk, findings


# ──────────────────────────────────────────────
# State
# ──────────────────────────────────────────────

_wps_aps: dict[str, dict] = {}   # bssid → {ssid, wps_data, risk, findings, ...}
_start_time = time.time()


def handle_packet(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return

    dot11 = pkt[Dot11]
    bssid = dot11.addr3
    if not bssid:
        return
    bssid = bssid.lower()

    if bssid in _wps_aps:
        return  # already processed this AP

    # Walk vendor-specific tags looking for WPS IE
    wps_data: dict | None = None
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 221:
            info = bytes(elt.info) if elt.info else b""
            if len(info) >= 4 and info[:3] == _MS_OUI and info[3] == _WPS_TYPE:
                wps_data = _parse_wps_ie(info[4:])
                break
        if not isinstance(getattr(elt, "payload", None), Dot11Elt):
            break
        elt = elt.payload

    if not wps_data:
        return  # no WPS IE in this beacon — AP doesn't support WPS (lucky them)

    ssid    = get_ssid(pkt)
    channel = get_channel(pkt)
    rssi    = get_rssi(pkt)
    risk, findings = _assess_risk(wps_data)

    _wps_aps[bssid] = {
        "bssid":      bssid,
        "ssid":       ssid or "<hidden>",
        "channel":    channel,
        "rssi_dbm":   rssi,
        "wps":        wps_data,
        "risk":       risk,
        "findings":   findings,
        "found_at":   datetime.now().isoformat(timespec="seconds"),
    }

    _print_ap(bssid, _wps_aps[bssid])


_RISK_COLOR = {
    "CRITICAL": "\033[95m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[92m",
}
_RESET = "\033[0m"


def _print_ap(bssid: str, ap: dict):
    wps  = ap["wps"]
    col  = _RISK_COLOR.get(ap["risk"], "")
    rssi = f"{ap['rssi_dbm']} dBm" if ap["rssi_dbm"] else "?"

    print(f"\n  {'─'*60}")
    print(f"  {col}[{ap['risk']}]{_RESET}  {bssid}  CH{ap['channel']}  {rssi}")
    print(f"  SSID       : {ap['ssid']}")
    print(f"  WPS ver    : {wps['version'] or '?'}  (2.0: {wps['version2'] or 'no'})")
    print(f"  State      : {wps['state'] or '?'}  |  Locked: {wps['locked']}")
    print(f"  Device     : {wps['manufacturer'] or '?'} / {wps['model_name'] or '?'} / {wps['model_number'] or '?'}")
    print(f"  Cfg method : {', '.join(wps['config_methods']) or '?'}")
    if wps["uuid"]:
        print(f"  UUID       : {wps['uuid']}")
    print(f"  Findings:")
    for f in ap["findings"]:
        print(f"    • {f}")


def print_summary():
    elapsed = int(time.time() - _start_time)
    print(f"\n\n{'═' * 60}")
    print(f"  WPS SCAN SUMMARY — {len(_wps_aps)} WPS-enabled APs | {elapsed}s")
    print(f"{'═' * 60}")

    risk_counts: dict[str, int] = {}
    for ap in _wps_aps.values():
        r = ap["risk"]
        risk_counts[r] = risk_counts.get(r, 0) + 1

    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = risk_counts.get(risk, 0)
        if count:
            col = _RISK_COLOR.get(risk, "")
            print(f"  {col}{risk:<10}{_RESET} : {count} AP(s)")

    if not _wps_aps:
        print("  No WPS-enabled APs detected.")
        print("  Either they've all disabled it, or you need more channel hops.")


def main():
    require_root()

    parser = argparse.ArgumentParser(
        description="Passive WPS scanner — identify and risk-rate WPS-enabled APs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Detection is purely passive — reads beacon frames, sends nothing.\n\n"
            "Risk levels:\n"
            "  CRITICAL — likely Pixie Dust vulnerable (crack in seconds)\n"
            "  HIGH     — PIN brute-force feasible (hours with reaver/bully)\n"
            "  MEDIUM   — WPS 2.0 with lockout, but often misconfigured\n"
            "  LOW      — WPS enabled but no specific known weakness\n"
            "  INFO     — WPS locked (probably already attacked)"
        ),
    )
    add_iface_arg(parser)
    add_output_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    require_monitor_mode(args.iface)

    print(f"\n=== 05_defense/02_wps_scanner.py ===")
    print(f"    Interface  : {args.iface}")
    print(f"    Mode       : PASSIVE — sending NO frames")
    print("    Ctrl-C to stop.\n")

    def on_sigint(sig, frame):
        print_summary()
        if args.output:
            safe_write_json({
                "captured_at": datetime.now().isoformat(timespec="seconds"),
                "total_wps_aps": len(_wps_aps),
                "aps": list(_wps_aps.values()),
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
            "total_wps_aps": len(_wps_aps),
            "aps": list(_wps_aps.values()),
        }, args.output)


if __name__ == "__main__":
    main()
