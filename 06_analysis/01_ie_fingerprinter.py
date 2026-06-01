#!/usr/bin/env python3
"""
06_analysis/01_ie_fingerprinter.py — OS fingerprinting from probe request Information Elements.

MAC randomization hides the hardware identifier. It does not hide the OS.

Every operating system sends probe requests with Information Elements in a
specific order, with specific rates, and with specific vendor tags. This
sequence is consistent across devices running the same OS version and is
effectively a fingerprint that survives MAC rotation.

This is how commercial retail analytics systems (Cisco DNA Spaces, Aruba,
Euclid, etc.) track customers across visits even after iOS 14 "broke" it.
MAC randomization was never the whole story.

Reference: "Passive OS Fingerprinting via 802.11 Probe Requests"
           Cunche et al., 2012 + updated empirical observations.

Fingerprint components:
  - IE tag sequence (order matters)
  - Supported rates set
  - Vendor-specific OUIs present
  - HT capabilities flags
  - Extended capabilities bitmap

Usage:
    sudo python3 06_analysis/01_ie_fingerprinter.py --iface wlan1
    sudo python3 06_analysis/01_ie_fingerprinter.py --iface wlan1 --output fingerprints.json

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime
from hashlib import md5

try:
    from scapy.all import Dot11, Dot11Elt, sniff
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_rssi,
    is_randomized,
    mask_mac,
    require_root,
    require_monitor_mode,
    add_iface_arg,
    add_output_arg,
    add_duration_arg,
    safe_write_json,
)


# ──────────────────────────────────────────────
# OS Signature database
#
# Each signature is a dict of weighted features.
# Matching is scored — the highest-score wins.
# Source: empirical capture + published research.
# ──────────────────────────────────────────────

# Key vendor OUIs seen in probe request vendor tags
_OUI_APPLE    = "00:17:f2"   # Apple-specific IE
_OUI_MS       = "00:50:f2"   # Microsoft (WPS, WPA1, WMM)
_OUI_WFA      = "50:6f:9a"   # Wi-Fi Alliance (P2P, HS2.0)
_OUI_EPIGRAM  = "00:90:4c"   # Pre-N / Epigram (old Broadcom)

# Tag IDs we use as fingerprint features
_TAG_SSID          = 0
_TAG_RATES         = 1
_TAG_DS_PARAM      = 3
_TAG_HT_CAPS       = 45
_TAG_EXT_CAPS      = 127
_TAG_EXT_RATES     = 50
_TAG_INTERWORKING  = 107
_TAG_VENDOR        = 221
_TAG_PWR_CAPS      = 33
_TAG_SUPPORTED_CH  = 36
_TAG_RM_CAPS       = 70
_TAG_VHT_CAPS      = 191

# Known signatures — (label, features_dict)
# features: ie_sequence (partial, order matters), vendor_ouis, rates_set
_SIGNATURES = [
    {
        "os":       "iOS 14+",
        "notes":    "iPhone/iPad post-MAC randomization era",
        "ie_must":  [0, 1, 50, 3],          # must appear in this relative order
        "ie_any":   [45, 127, 107, 221],     # any of these present = points
        "ie_not":   [],
        "oui_must": [],
        "oui_any":  [_OUI_APPLE, _OUI_WFA],
        "oui_not":  [_OUI_MS],
        "rates":    {1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0},
        "rates_partial": True,   # rates are a superset check
    },
    {
        "os":       "iOS 13 / macOS",
        "notes":    "Pre-randomization Apple devices",
        "ie_must":  [0, 1, 50, 3],
        "ie_any":   [45, 127, 107, 221],
        "ie_not":   [],
        "oui_must": [_OUI_APPLE],
        "oui_any":  [_OUI_WFA],
        "oui_not":  [_OUI_MS],
        "rates":    {1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0},
        "rates_partial": True,
    },
    {
        "os":       "Windows 10/11",
        "notes":    "Microsoft stack — very consistent IE ordering",
        "ie_must":  [0, 1, 50, 3],
        "ie_any":   [45, 127, 221, 70],
        "ie_not":   [107],                   # Interworking rare on Windows probes
        "oui_must": [],
        "oui_any":  [_OUI_MS, _OUI_WFA],
        "oui_not":  [_OUI_APPLE],
        "rates":    {1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0},
        "rates_partial": True,
    },
    {
        "os":       "Android 10+",
        "notes":    "AOSP wpa_supplicant with randomization",
        "ie_must":  [0, 1, 50, 3],
        "ie_any":   [45, 127, 221],
        "ie_not":   [107],
        "oui_must": [],
        "oui_any":  [_OUI_WFA],
        "oui_not":  [_OUI_APPLE],
        "rates":    {1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0},
        "rates_partial": True,
    },
    {
        "os":       "Linux / wpa_supplicant",
        "notes":    "Desktop/laptop, Raspberry Pi, IoT with wpas",
        "ie_must":  [0, 1, 50, 3],
        "ie_any":   [45, 127],
        "ie_not":   [107],
        "oui_must": [],
        "oui_any":  [],
        "oui_not":  [_OUI_APPLE, _OUI_MS],
        "rates":    {1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0},
        "rates_partial": True,
    },
]


# ──────────────────────────────────────────────
# Probe request parser
# ──────────────────────────────────────────────

def _parse_probe(pkt) -> dict | None:
    """
    Extract everything fingerprint-relevant from a probe request.
    Returns None if the packet is unusable (no Dot11, wrong subtype, etc.)
    """
    dot11 = pkt[Dot11]
    if dot11.type != 0 or dot11.subtype != 4:
        return None

    mac = dot11.addr2
    if not mac:
        return None

    ie_sequence:  list[int]   = []   # all tag IDs in order
    rates:        set[float]  = set()
    vendor_ouis:  set[str]    = set()
    ssid:         str         = ""
    ht_present:   bool        = False
    vht_present:  bool        = False
    ext_caps:     bytes       = b""

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        tag_id = elt.ID
        info   = bytes(elt.info) if elt.info else b""
        ie_sequence.append(tag_id)

        if tag_id == 0:   # SSID
            try:
                ssid = info.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

        elif tag_id in (1, 50):   # Supported Rates / Extended Supported Rates
            for b in info:
                rates.add((b & 0x7F) / 2.0)

        elif tag_id == 45:
            ht_present = True

        elif tag_id == 191:
            vht_present = True

        elif tag_id == 127:
            ext_caps = info

        elif tag_id == 221 and len(info) >= 3:
            # Format as XX:XX:XX for OUI lookup
            oui = ":".join(f"{b:02x}" for b in info[:3])
            vendor_ouis.add(oui)

        if not isinstance(getattr(elt, "payload", None), Dot11Elt):
            break
        elt = elt.payload

    return {
        "mac":         mac.lower(),
        "ssid":        ssid,
        "ie_sequence": ie_sequence,
        "rates":       rates,
        "vendor_ouis": vendor_ouis,
        "ht":          ht_present,
        "vht":         vht_present,
        "ext_caps":    ext_caps.hex(),
        "rssi":        get_rssi(pkt),
        # Fingerprint hash: stable identifier for this probe style
        # (survives MAC rotation if OS hasn't updated)
        "fp_hash":     md5(
            str(ie_sequence).encode() + str(sorted(rates)).encode()
        ).hexdigest()[:8],
    }


# ──────────────────────────────────────────────
# Fingerprint matching
# ──────────────────────────────────────────────

def _score_signature(probe: dict, sig: dict) -> int:
    """
    Score how well a probe matches a signature.
    Higher = better match. Returns 0 if hard requirements fail.
    """
    score = 0
    seq   = probe["ie_sequence"]
    ouis  = probe["vendor_ouis"]
    rates = probe["rates"]

    # Hard requirement: ie_must must appear in order (not necessarily contiguous)
    must = sig["ie_must"]
    pos  = 0
    for tag in must:
        try:
            pos = seq.index(tag, pos) + 1
            score += 3
        except ValueError:
            return 0  # missing a required tag in order → no match

    # Bonus: optional tags present
    for tag in sig.get("ie_any", []):
        if tag in seq:
            score += 1

    # Penalty: tags that shouldn't be there
    for tag in sig.get("ie_not", []):
        if tag in seq:
            score -= 2

    # OUI requirements
    for oui in sig.get("oui_must", []):
        if oui in ouis:
            score += 4
        else:
            return 0  # required OUI missing

    for oui in sig.get("oui_any", []):
        if oui in ouis:
            score += 2

    for oui in sig.get("oui_not", []):
        if oui in ouis:
            score -= 3

    # Rate matching
    sig_rates = sig.get("rates", set())
    if sig_rates:
        overlap = len(rates & sig_rates)
        total   = len(sig_rates)
        score  += int(overlap / max(total, 1) * 4)

    return max(score, 0)


def fingerprint_os(probe: dict) -> tuple[str, int, str]:
    """
    Match probe against all signatures. Return (os_label, confidence, notes).
    Confidence: 0-100 (rough percentage based on max possible score).
    """
    best_os    = "Unknown"
    best_score = 0
    best_notes = ""

    for sig in _SIGNATURES:
        score = _score_signature(probe, sig)
        if score > best_score:
            best_score = score
            best_os    = sig["os"]
            best_notes = sig["notes"]

    # Rough confidence: normalize against a "perfect match" baseline of ~20 pts
    confidence = min(int(best_score / 20 * 100), 95)  # cap at 95 — we're never certain
    return best_os, confidence, best_notes


# ──────────────────────────────────────────────
# State and display
# ──────────────────────────────────────────────

# mac → {os_guess, confidence, fp_hash, probes_seen, ssids, rssi_list, first/last}
_devices: dict[str, dict] = {}
_start_time = time.time()


def handle_packet(pkt):
    if not pkt.haslayer(Dot11):
        return

    probe = _parse_probe(pkt)
    if not probe:
        return

    mac = probe["mac"]
    os_label, confidence, notes = fingerprint_os(probe)
    now = datetime.now().isoformat(timespec="seconds")

    if mac not in _devices:
        _devices[mac] = {
            "os_guess":   os_label,
            "confidence": confidence,
            "fp_hash":    probe["fp_hash"],
            "randomized": is_randomized(mac),
            "probes":     0,
            "ssids":      set(),
            "rssi_list":  [],
            "ie_seq":     probe["ie_sequence"],
            "vendor_ouis":probe["vendor_ouis"],
            "first_seen": now,
            "last_seen":  now,
        }
        # Print immediately on first probe from new device
        _print_device(mac, _devices[mac], probe)

    dev = _devices[mac]
    dev["probes"]   += 1
    dev["last_seen"] = now
    if probe["ssid"]:
        dev["ssids"].add(probe["ssid"])
    if probe["rssi"] is not None:
        dev["rssi_list"].append(probe["rssi"])

    elapsed = int(time.time() - _start_time)
    print(
        f"\r  devices:{len(_devices):3d}  elapsed:{elapsed:4d}s  "
        f"last: {mask_mac(mac)} → {os_label[:20]}  ",
        end="", flush=True,
    )


def _print_device(mac: str, dev: dict, probe: dict):
    rnd = "🎲 (randomized)" if dev["randomized"] else "real MAC"
    conf_bar = "█" * (dev["confidence"] // 10) + "░" * (10 - dev["confidence"] // 10)

    print(f"\n\n  ┌─ NEW DEVICE ─────────────────────────────────────────────┐")
    print(f"  │  MAC      : {mask_mac(mac):<20}  {rnd}")
    print(f"  │  OS guess : {dev['os_guess']:<35} [{conf_bar}] {dev['confidence']}%")
    print(f"  │  FP hash  : {dev['fp_hash']}  (stable across MAC rotations)")
    print(f"  │  IE seq   : {dev['ie_seq']}")
    print(f"  │  Vendor   : {', '.join(dev['vendor_ouis']) or 'none'}")
    if probe["ssid"]:
        print(f"  │  Probing  : \"{probe['ssid']}\"")
    print(f"  └─────────────────────────────────────────────────────────────┘")


def print_report():
    print(f"\n\n{'═' * 68}")
    print(f"  OS FINGERPRINT REPORT — {len(_devices)} unique devices")
    print(f"{'═' * 68}")
    print(f"  {'MAC':<20}  {'RND':<3}  {'OS GUESS':<22}  {'CONF':>5}  FP HASH  SSIDS")
    print(f"  {'─'*20}  {'─'*3}  {'─'*22}  {'─'*5}  {'─'*8}  {'─'*20}")

    os_counts: dict[str, int] = defaultdict(int)

    for mac, dev in sorted(_devices.items(), key=lambda x: x[1]["confidence"], reverse=True):
        rnd = "🎲" if dev["randomized"] else ""
        ssid_preview = ", ".join(sorted(dev["ssids"])[:2])
        if len(dev["ssids"]) > 2:
            ssid_preview += f" +{len(dev['ssids'])-2}"
        os_counts[dev["os_guess"]] += 1
        print(f"  {mask_mac(mac):<20}  {rnd:<3}  {dev['os_guess'][:22]:<22}"
              f"  {dev['confidence']:4d}%  {dev['fp_hash']}  {ssid_preview}")

    print(f"\n  OS distribution:")
    for os_label, count in sorted(os_counts.items(), key=lambda x: -x[1]):
        bar = "█" * count
        print(f"    {os_label:<25} {count:3d}  {bar}")

    rnd_count = sum(1 for d in _devices.values() if d["randomized"])
    elapsed   = int(time.time() - _start_time)
    print(f"\n  Randomized MACs : {rnd_count}/{len(_devices)}")
    print(f"  Capture time    : {elapsed}s")
    print(f"\n  Note: confidence > 70% is reasonably reliable.")
    print(f"        confidence < 40% means the IE set was ambiguous.")
    print(f"        The fp_hash persists even when the MAC changes.")


def main():
    require_root()

    parser = argparse.ArgumentParser(
        description=(
            "OS fingerprinting from probe request IEs — "
            "because MAC randomization was never the whole story."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The fingerprint hash (fp_hash) is derived from the IE sequence\n"
            "and supported rates — both are OS-determined, not hardware-determined.\n"
            "A device rotating its MAC every 24h still has the same fp_hash."
        ),
    )
    add_iface_arg(parser)
    add_output_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    require_monitor_mode(args.iface)

    print(f"\n=== 06_analysis/01_ie_fingerprinter.py ===")
    print(f"    Interface : {args.iface}")
    print(f"    Mode      : PASSIVE — sending NO frames")
    print(f"    Goal      : identify OS from probe request structure")
    print("    Ctrl-C to stop.\n")

    def on_sigint(sig, frame):
        print_report()
        if args.output:
            out = []
            for mac, dev in _devices.items():
                out.append({
                    "mac_masked":   mask_mac(mac),
                    "randomized":   dev["randomized"],
                    "os_guess":     dev["os_guess"],
                    "confidence":   dev["confidence"],
                    "fp_hash":      dev["fp_hash"],
                    "probe_count":  dev["probes"],
                    "ssids":        sorted(dev["ssids"]),
                    "ie_sequence":  dev["ie_seq"],
                    "vendor_ouis":  list(dev["vendor_ouis"]),
                    "first_seen":   dev["first_seen"],
                    "last_seen":    dev["last_seen"],
                })
            safe_write_json({
                "captured_at": datetime.now().isoformat(timespec="seconds"),
                "total":       len(_devices),
                "devices":     out,
            }, args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    sniff(
        iface=args.iface,
        prn=handle_packet,
        store=False,
        timeout=args.duration if args.duration > 0 else None,
        lfilter=lambda p: (
            p.haslayer(Dot11) and p[Dot11].type == 0 and p[Dot11].subtype == 4
        ),
    )

    print_report()
    if args.output:
        out = []
        for mac, dev in _devices.items():
            out.append({
                "mac_masked":   mask_mac(mac),
                "randomized":   dev["randomized"],
                "os_guess":     dev["os_guess"],
                "confidence":   dev["confidence"],
                "fp_hash":      dev["fp_hash"],
                "probe_count":  dev["probes"],
                "ssids":        sorted(dev["ssids"]),
                "ie_sequence":  dev["ie_seq"],
                "vendor_ouis":  list(dev["vendor_ouis"]),
                "first_seen":   dev["first_seen"],
                "last_seen":    dev["last_seen"],
            })
        safe_write_json({
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "total":       len(_devices),
            "devices":     out,
        }, args.output)


if __name__ == "__main__":
    main()
