#!/usr/bin/env python3
"""
02_recon/08_karma_detector.py — Detect KARMA-style rogue AP attacks.

A KARMA attack works like this:
  Client sends:   Probe Request for "MEO-AB12"
  Evil AP replies: "Yes, I am MEO-AB12, connect to me"
  Client connects: to the attacker instead of the real network

The attacker's AP has never announced "MEO-AB12" in a beacon.
It dynamically responds to whatever the client asks for.
This is the basis of tools like hostapd-wpe, Airbase-ng, and the
KARMA module in WiFi Pineapple.

Detection signature:
  A BSSID sends a Probe Response for an SSID that it has
  NEVER broadcast in a Beacon frame.

  Legitimate APs only respond to probes for their own SSIDs.
  A KARMA AP responds to probes for SSIDs it doesn't own.

Also detects:
  - AP impersonation: same SSID, slightly different BSSID (evil twin)
  - Unusually fast probe response time (scripted responder)
  - APs broadcasting many different SSIDs sequentially (KARMA in action)

Usage:
    sudo python3 02_recon/08_karma_detector.py --iface wlan1
    sudo python3 02_recon/08_karma_detector.py --iface wlan1 --known-aps aps.json

Pair with 05_defense/01_wids_sensor.py for a complete passive defense posture.
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
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap, sniff
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
# Alert severity
# ──────────────────────────────────────────────

_COLORS = {
    "CRITICAL": "\033[95m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "INFO":     "\033[94m",
}
_RESET = "\033[0m"

_alerts: list[dict] = []


def alert(severity: str, title: str, detail: str):
    ts  = datetime.now().strftime("%H:%M:%S")
    col = _COLORS.get(severity, "")
    print(f"\n\n  {col}╔═══ {severity}: {title} ═══{_RESET}")
    print(f"  {col}║{_RESET} {detail}")
    print(f"  {col}║{_RESET} @ {ts}")
    print(f"  {col}╚{'═'*50}{_RESET}\n")
    _alerts.append({
        "severity": severity,
        "title":    title,
        "detail":   detail,
        "ts":       ts,
    })


# ──────────────────────────────────────────────
# State
# ──────────────────────────────────────────────

# What each BSSID has announced in its own beacons
# bssid → set of SSIDs seen in beacons
_beacon_ssids: dict[str, set] = defaultdict(set)

# What each BSSID has responded to in probe responses
# bssid → set of SSIDs seen in probe responses
_probe_resp_ssids: dict[str, set] = defaultdict(set)

# SSIDs the BSSID has *already* been alerted for (avoid alert spam)
_alerted_karma: dict[str, set] = defaultdict(set)

# Known legitimate APs (from 02_recon/05_ap_scanner.py output or manual input)
# bssid → ssid
_known_aps: dict[str, str] = {}

# BSSID → list of distinct SSIDs it has responded to (KARMA = many SSIDs)
# A legitimate AP responds to one SSID. KARMA responds to whatever is asked.
_bssid_response_variety: dict[str, set] = defaultdict(set)

# Timing: track probe request + response pairs for fast-response detection
# (ssid, client_mac) → request_timestamp
_pending_probes: dict[tuple, float] = {}
_KARMA_RESPONSE_MS = 50   # responses faster than this are suspicious (scripted)

_start_time = time.time()


# ──────────────────────────────────────────────
# Detection logic
# ──────────────────────────────────────────────

def _check_karma(bssid: str, responded_ssid: str):
    """
    Core KARMA detection:
    If a BSSID responds to a probe for an SSID it has never
    announced in a beacon, it's behaving like a KARMA AP.
    """
    if not responded_ssid:
        return

    announced = _beacon_ssids.get(bssid, set())

    # If we have no beacon from this BSSID at all, it might just be that
    # we missed the beacon — track but don't alert yet.
    if not announced:
        _bssid_response_variety[bssid].add(responded_ssid)
        if len(_bssid_response_variety[bssid]) >= 3:
            # Three different SSIDs with no beacon is suspicious
            if responded_ssid not in _alerted_karma[bssid]:
                _alerted_karma[bssid].add(responded_ssid)
                alert(
                    "MEDIUM",
                    "POSSIBLE KARMA AP (no beacon observed)",
                    f"BSSID {bssid} responded to probe for \"{responded_ssid}\" "
                    f"but has never sent a beacon. "
                    f"Response variety: {sorted(_bssid_response_variety[bssid])}",
                )
        return

    # We have beacon data — a legitimate AP only responds to its own SSID
    if responded_ssid not in announced:
        if responded_ssid not in _alerted_karma[bssid]:
            _alerted_karma[bssid].add(responded_ssid)
            alert(
                "CRITICAL",
                "KARMA ATTACK DETECTED",
                f"BSSID {bssid} responded to probe for \"{responded_ssid}\" "
                f"but its beacon announces: {sorted(announced)}. "
                f"This is a KARMA/rogue AP impersonating client-requested SSIDs.",
            )


def _check_evil_twin(bssid: str, ssid: str):
    """
    If a known legitimate AP's SSID is being broadcast by an unknown BSSID,
    it's a potential evil twin.
    """
    if not _known_aps or not ssid:
        return

    for known_bssid, known_ssid in _known_aps.items():
        if known_ssid == ssid and known_bssid != bssid:
            alert(
                "HIGH",
                "EVIL TWIN IN PROBE RESPONSE",
                f"BSSID {bssid} is responding with SSID \"{ssid}\" "
                f"which belongs to known legitimate AP {known_bssid}.",
            )
            break


def _check_ssid_variety(bssid: str):
    """
    A KARMA AP in full operation responds to MANY different probe requests.
    Flag BSSIDs that respond to an unusual number of distinct SSIDs.
    """
    variety = len(_bssid_response_variety[bssid])
    # Legitimate APs with multiple SSIDs (dual-band) typically have 2-3.
    # KARMA APs respond to everything — variety of 10+ is telling.
    thresholds = {10: "MEDIUM", 20: "HIGH", 40: "CRITICAL"}
    for threshold, severity in thresholds.items():
        if variety == threshold:  # alert at each threshold crossing, not every packet
            alert(
                severity,
                "HIGH SSID RESPONSE VARIETY",
                f"BSSID {bssid} has responded to {variety} distinct SSIDs. "
                f"Legitimate APs respond to 1-3. KARMA APs respond to everything. "
                f"Sample: {sorted(list(_bssid_response_variety[bssid]))[:5]}",
            )


# ──────────────────────────────────────────────
# Packet handler
# ──────────────────────────────────────────────

def handle_packet(pkt):
    if not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]
    now   = time.time()

    if dot11.type != 0:
        return   # only management frames

    # Prune stale pending probes older than 10 seconds
    stale_cutoff = now - 10.0
    stale = [k for k, ts in _pending_probes.items() if ts < stale_cutoff]
    for k in stale:
        del _pending_probes[k]

    if dot11.subtype == 8:   # Beacon
        bssid = (dot11.addr3 or "").lower()
        ssid  = get_ssid(pkt)
        if bssid and ssid:
            _beacon_ssids[bssid].add(ssid)

    elif dot11.subtype == 4:  # Probe Request
        # Track probe requests for timing analysis
        ssid   = get_ssid(pkt)
        client = (dot11.addr2 or "").lower()
        if ssid and client:
            _pending_probes[(ssid, client)] = now

    elif dot11.subtype == 5:  # Probe Response
        bssid  = (dot11.addr3 or dot11.addr2 or "").lower()
        client = (dot11.addr1 or "").lower()
        ssid   = get_ssid(pkt)

        # Guard against None/empty bssid or ssid before touching dicts
        if not bssid or not ssid:
            return

        _probe_resp_ssids[bssid].add(ssid)
        _bssid_response_variety[bssid].add(ssid)

        # Core KARMA check
        _check_karma(bssid, ssid)
        _check_evil_twin(bssid, ssid)
        _check_ssid_variety(bssid)

        # Timing check — did a probe request for this SSID just go out?
        probe_key = (ssid, client)
        if probe_key in _pending_probes:
            delay_ms = (now - _pending_probes[probe_key]) * 1000
            del _pending_probes[probe_key]
            if 0 < delay_ms < _KARMA_RESPONSE_MS:
                alert(
                    "MEDIUM",
                    "SUSPICIOUSLY FAST PROBE RESPONSE",
                    f"BSSID {bssid} responded to probe for \"{ssid}\" "
                    f"in {delay_ms:.1f}ms — scripted responders are faster than real APs. "
                    f"(Normal AP response: 5-50ms, KARMA: <5ms)",
                )

    elapsed = int(time.time() - _start_time)
    print(
        f"\r  Monitoring...  beacons:{len(_beacon_ssids):3d}  "
        f"alerts:{len(_alerts):3d}  {elapsed:4d}s",
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
    print(f"  KARMA DETECTOR SUMMARY — {elapsed}s")
    print(f"{'═' * 60}")
    print(f"  APs with beacons    : {len(_beacon_ssids)}")
    print(f"  APs with responses  : {len(_probe_resp_ssids)}")
    print(f"  Total alerts        : {len(_alerts)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        count = sev_counts.get(sev, 0)
        if count:
            col = _COLORS.get(sev, "")
            print(f"  {col}{sev:<10}{_RESET} : {count}")

    if not _alerts:
        print(f"\n  No KARMA activity detected.")
        print(f"  Either the environment is clean, or the attacker already stopped.")

    # Report any APs with high response variety (even if no alert fired)
    suspicious = [
        (bssid, ssids)
        for bssid, ssids in _bssid_response_variety.items()
        if len(ssids) >= 5
    ]
    if suspicious:
        print(f"\n  APs with unusual SSID response variety:")
        for bssid, ssids in sorted(suspicious, key=lambda x: -len(x[1])):
            print(f"    {bssid}  →  {len(ssids)} distinct SSIDs responded")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    global _known_aps

    parser = argparse.ArgumentParser(
        description=(
            "KARMA attack detector — spots rogue APs that respond to "
            "any probe request regardless of their announced SSID."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "KARMA attacks are the backbone of WiFi Pineapple, hostapd-wpe,\n"
            "and Airbase-ng -P. They work because clients trust probe responses.\n\n"
            "For best detection: also run 05_defense/01_wids_sensor.py in another terminal.\n\n"
            "Load a known-AP reference to enable evil twin detection:\n"
            "  sudo python3 02_recon/05_ap_scanner.py --iface wlan1 --output aps.json\n"
            "  sudo python3 02_recon/08_karma_detector.py --iface wlan1 --known-aps aps.json"
        ),
    )
    add_iface_arg(parser)
    parser.add_argument("--known-aps",  default=None,
                        help="JSON from 02_recon/05_ap_scanner.py for evil twin detection")
    add_duration_arg(parser)
    args = parser.parse_args()

    if args.known_aps:
        try:
            with open(args.known_aps) as fh:
                data = json.load(fh)
            for ap in data.get("aps", []):
                bssid = ap.get("bssid", "").lower()
                ssid  = ap.get("ssid", "")
                if bssid:
                    _known_aps[bssid] = ssid
            print(f"[*] Loaded {len(_known_aps)} known APs for reference")
        except Exception as e:
            print(f"[!] Could not load known APs: {e}")

    require_root()
    require_monitor_mode(args.iface)

    print(f"\n=== 02_recon/08_karma_detector.py ===")
    print(f"    Interface  : {args.iface}")
    print(f"    Known APs  : {len(_known_aps)}")
    print(f"    Mode       : PASSIVE — sending NO frames")
    print()
    print("    Detection logic:")
    print("    • BSSID responds to SSID not in its own beacons → KARMA")
    print("    • BSSID responds to 10+ distinct SSIDs → KARMA in operation")
    print("    • Known SSID answered by unknown BSSID → Evil Twin")
    print("    • Response time < 50ms → scripted responder")
    print("    Ctrl-C to stop.\n")

    def on_sigint(sig, frame):
        print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    sniff(
        iface=args.iface,
        prn=handle_packet,
        store=False,
        timeout=args.duration if args.duration > 0 else None,
        lfilter=lambda p: (
            p.haslayer(Dot11) and p[Dot11].type == 0
            and p[Dot11].subtype in (4, 5, 8)
        ),
    )

    print_summary()


if __name__ == "__main__":
    main()
