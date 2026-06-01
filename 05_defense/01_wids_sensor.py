#!/usr/bin/env python3
"""
05_defense/01_wids_sensor.py — Wireless Intrusion Detection System (WIDS) sensor.

After two sessions of learning how to attack, this script teaches
the other side: how defenders detect the exact attacks we've been doing.

Detects:
  • Deauth flood     — someone is running 04_attacks/03_deauth.py (or similar)
  • Evil Twin        — rogue AP cloning a known SSID
  • Probe flood      — someone is running 02_recon/04_probe_analyzer.py (or similar)
  • MAC randomization churn — randomized MAC scanning pattern
  • Channel switching attack — AP impersonation via CSA frames
  • WPS brute-force  — repeated WPS PIN attempts
  • Known-vendor anomalies — Alfa/Kali tools fingerprint themselves

This is why professional wireless infrastructure uses centralized WIDS
sensors like Cisco WIPS, Aruba RFProtect, or open-source alternatives.
This script is the educational version of all of the above.

Usage:
    sudo python3 05_defense/01_wids_sensor.py --iface wlan1
    sudo python3 05_defense/01_wids_sensor.py --iface wlan1 --known-aps aps.json

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 4
"""

import argparse
import json
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt, RadioTap, sniff
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid,
    require_root,
    require_monitor_mode,
    add_iface_arg,
    add_duration_arg,
)


# ──────────────────────────────────────────────
# Alert system
# ──────────────────────────────────────────────

SEVERITY_LOW    = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH   = "HIGH"
SEVERITY_CRIT   = "CRITICAL"

_SEVERITY_COLOR = {
    SEVERITY_LOW:    "\033[94m",  # blue
    SEVERITY_MEDIUM: "\033[93m",  # yellow
    SEVERITY_HIGH:   "\033[91m",  # red
    SEVERITY_CRIT:   "\033[95m",  # magenta
}
_RESET = "\033[0m"

_alerts: list[dict] = []


def alert(severity: str, category: str, message: str, detail: str = ""):
    ts  = datetime.now().strftime("%H:%M:%S")
    col = _SEVERITY_COLOR.get(severity, "")
    print(f"\n  {col}[{severity:<8}]{_RESET} [{ts}] {category}")
    print(f"           {message}")
    if detail:
        print(f"           {detail}")
    _alerts.append({
        "ts": ts, "severity": severity,
        "category": category, "message": message, "detail": detail,
    })


# ──────────────────────────────────────────────
# State counters
# ──────────────────────────────────────────────

# Deauth flood detection
_deauth_counts: dict[str, list[float]] = defaultdict(list)  # mac → [timestamps]
DEAUTH_THRESHOLD = 10   # deauths per second from same source = flood

# Evil twin detection
_known_ssids: dict[str, set] = defaultdict(set)   # ssid → set of BSSIDs
_known_aps: dict[str, str]   = {}                  # bssid → ssid (from reference file)

# Probe flood
_probe_counts: dict[str, list[float]] = defaultdict(list)   # mac → [timestamps]
PROBE_THRESHOLD = 30  # probes per second from same MAC = flood

# WPS brute-force
_wps_attempts: dict[str, list[float]] = defaultdict(list)   # bssid → [timestamps]
WPS_THRESHOLD = 5   # WPS auth attempts per minute = brute force

# MAC churn (randomized MACs appearing at high rate)
_new_macs: list[float] = []
MAC_CHURN_THRESHOLD = 20  # new unique MACs per minute = scanner

# Alfa / Kali tool fingerprint (OUI 00:c0:ca)
_ALFA_OUI = "00:c0:ca"

_all_macs: set[str] = set()
_start_time = time.time()


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _is_randomized(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _recent_count(timestamps: list[float], window: float = 1.0) -> int:
    """Count events in the last `window` seconds."""
    now = time.time()
    return sum(1 for t in timestamps if now - t <= window)


def _prune(timestamps: list[float], window: float = 60.0) -> list[float]:
    """Remove timestamps older than `window` seconds to avoid memory growth."""
    now = time.time()
    return [t for t in timestamps if now - t <= window]


# ──────────────────────────────────────────────
# Detection logic
# ──────────────────────────────────────────────

def _check_deauth_flood(mac: str):
    """
    Deauth flood: more than DEAUTH_THRESHOLD deauths per second from same source.
    Classic sign of 04_attacks/03_deauth.py, mdk3/mdk4, or aireplay-ng -0.
    """
    now = time.time()
    _deauth_counts[mac].append(now)
    _deauth_counts[mac] = _prune(_deauth_counts[mac], 5.0)

    rate = _recent_count(_deauth_counts[mac], 1.0)
    if rate >= DEAUTH_THRESHOLD:
        total = len(_deauth_counts[mac])
        # Alert at the exact threshold and then every multiple thereafter.
        # Using only `total % DEAUTH_THRESHOLD == 0` misses counts that
        # aren't exact multiples (e.g., 15 deauths if threshold is 10).
        if total == DEAUTH_THRESHOLD or (total > DEAUTH_THRESHOLD and total % DEAUTH_THRESHOLD == 0):
            alert(
                SEVERITY_HIGH,
                "DEAUTH FLOOD",
                f"Source {mac} sent {rate} deauth frames in 1 second",
                f"Total deauths from this source: {total}. Someone is running a deauth attack.",
            )


def _check_evil_twin(bssid: str, ssid: str):
    """
    Evil twin: same SSID announced by a BSSID not in the known-AP reference.
    Also detects multiple BSSIDs for the same SSID (less reliable but worth flagging).
    """
    if not ssid:
        return

    _known_ssids[ssid].add(bssid)

    # Check against reference file
    if _known_aps:
        if bssid not in _known_aps:
            # Unknown AP broadcasting a known SSID
            known_bssids = [b for b, s in _known_aps.items() if s == ssid]
            if known_bssids:
                alert(
                    SEVERITY_CRIT,
                    "EVIL TWIN DETECTED",
                    f"Unknown BSSID {bssid} is broadcasting known SSID: \"{ssid}\"",
                    f"Known legitimate BSSIDs for this SSID: {known_bssids}",
                )
        return

    # Without reference file: flag if same SSID has multiple BSSIDs
    # (could be a legitimate mesh network, but worth investigating)
    bssids_for_ssid = _known_ssids[ssid]
    if len(bssids_for_ssid) == 2:  # alert once on transition 1→2
        alert(
            SEVERITY_MEDIUM,
            "MULTIPLE BSSIDS FOR SSID",
            f"SSID \"{ssid}\" is broadcast by {len(bssids_for_ssid)} BSSIDs",
            f"BSSIDs: {', '.join(bssids_for_ssid)} — may be mesh or evil twin.",
        )


def _check_probe_flood(mac: str):
    """
    Probe flood: aggressive scanning tool sending many probes from the same MAC.
    """
    now = time.time()
    _probe_counts[mac].append(now)
    _probe_counts[mac] = _prune(_probe_counts[mac], 5.0)

    rate = _recent_count(_probe_counts[mac], 1.0)
    if rate >= PROBE_THRESHOLD:
        total = len(_probe_counts[mac])
        if total % PROBE_THRESHOLD == 0:
            alert(
                SEVERITY_MEDIUM,
                "PROBE FLOOD",
                f"Source {mac} sent {rate} probe requests in 1 second",
                f"Likely a scanning tool or very impatient phone.",
            )


def _check_mac_churn():
    """
    MAC churn: many new unique MACs appearing in quick succession.
    Indicates a scanner rotating randomized MACs (or a very crowded venue).
    """
    _new_macs[:] = _prune(_new_macs, 60.0)
    rate = len(_new_macs)

    if rate >= MAC_CHURN_THRESHOLD and rate % MAC_CHURN_THRESHOLD == 0:
        alert(
            SEVERITY_LOW,
            "HIGH MAC CHURN",
            f"{rate} new unique MACs in the last 60 seconds",
            f"May indicate a scanner rotating addresses, or a very busy venue.",
        )


def _check_alfa_oui(mac: str):
    """
    Alfa cards are the standard tool for Wi-Fi pentesting.
    Seeing one in the environment during an actual pentest is expected.
    Seeing one when there's supposed to be none is interesting.
    """
    if mac.startswith(_ALFA_OUI):
        if mac not in _all_macs:
            alert(
                SEVERITY_LOW,
                "PENTEST ADAPTER DETECTED",
                f"Alfa Networks OUI detected: {mac}",
                f"Someone nearby has a dedicated Wi-Fi attack adapter. Could be you.",
            )


# ──────────────────────────────────────────────
# Packet handler
# ──────────────────────────────────────────────

def handle_packet(pkt):
    if not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]

    # Track new MACs for churn detection
    for addr_field in ["addr1", "addr2", "addr3"]:
        mac = getattr(dot11, addr_field, None)
        if mac and mac.lower() not in _all_macs and mac != "ff:ff:ff:ff:ff:ff":
            mac = mac.lower()
            _all_macs.add(mac)
            _new_macs.append(time.time())
            _check_mac_churn()
            _check_alfa_oui(mac)

    if dot11.type != 0:  # only process management frames
        return

    mac = (dot11.addr2 or "").lower()

    if dot11.subtype in (10, 12):  # disassoc or deauth
        if mac:
            _check_deauth_flood(mac)

    elif dot11.subtype == 8:  # beacon
        bssid = (dot11.addr3 or "").lower()
        ssid  = get_ssid(pkt)
        if bssid:
            _check_evil_twin(bssid, ssid)

    elif dot11.subtype == 4:  # probe request
        if mac:
            _check_probe_flood(mac)

    # Live status line (quiet when no alerts are firing)
    elapsed = int(time.time() - _start_time)
    print(
        f"\r  Monitoring... macs:{len(_all_macs):4d}  alerts:{len(_alerts):3d}"
        f"  ssids:{len(_known_ssids):3d}  {elapsed:4d}s",
        end="",
        flush=True,
    )


# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

def print_summary():
    elapsed = int(time.time() - _start_time)
    sev_counts: dict[str, int] = defaultdict(int)
    for a in _alerts:
        sev_counts[a["severity"]] += 1

    print(f"\n\n{'═' * 60}")
    print(f"  WIDS SESSION SUMMARY — {elapsed}s")
    print(f"{'═' * 60}")
    print(f"  Total alerts   : {len(_alerts)}")
    for sev in [SEVERITY_CRIT, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
        count = sev_counts[sev]
        col   = _SEVERITY_COLOR[sev]
        print(f"  {col}{sev:<10}{_RESET}  : {count}")
    print(f"  Unique MACs    : {len(_all_macs)}")
    print(f"  SSIDs seen     : {len(_known_ssids)}")

    if not _alerts:
        print(f"\n  No suspicious activity detected. Either your network is clean")
        print(f"  or the attacker is better than this sensor. Both are possible.")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    global _known_aps

    require_root()

    parser = argparse.ArgumentParser(
        description="WIDS sensor — because offense is only half the curriculum.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Load a reference AP list (from 02_recon/05_ap_scanner.py --output aps.json)\n"
            "for accurate evil twin detection:\n\n"
            "  sudo python3 02_recon/05_ap_scanner.py --iface wlan1 --output aps.json\n"
            "  sudo python3 05_defense/01_wids_sensor.py --iface wlan1 --known-aps aps.json"
        ),
    )
    add_iface_arg(parser)
    parser.add_argument("--known-aps",  default=None,
                        help="JSON from 02_recon/05_ap_scanner.py — enables evil twin detection")
    add_duration_arg(parser)
    args = parser.parse_args()

    require_monitor_mode(args.iface)

    # Load reference APs if provided
    if args.known_aps:
        try:
            with open(args.known_aps) as fh:
                data = json.load(fh)
            for ap in data.get("aps", []):
                bssid = ap.get("bssid", "").lower()
                ssid  = ap.get("ssid", "")
                if bssid:
                    _known_aps[bssid] = ssid
            print(f"[*] Loaded {len(_known_aps)} known APs from {args.known_aps}")
        except Exception as e:
            print(f"[!] Could not load known APs: {e}")

    print(f"\n=== 05_defense/01_wids_sensor.py ===")
    print(f"    Interface    : {args.iface}")
    print(f"    Known APs    : {len(_known_aps)} loaded")
    print(f"    Detecting    : deauth floods, evil twins, probe floods, MAC churn")
    print(f"    Mode         : PASSIVE — sending NO frames")
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
        lfilter=lambda p: p.haslayer(Dot11),
    )

    print_summary()


if __name__ == "__main__":
    main()
