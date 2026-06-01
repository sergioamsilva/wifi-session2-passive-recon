#!/usr/bin/env python3
"""
06_analysis/03_pnl_correlator.py — Cross-correlate Preferred Network Lists between devices.

Two devices that share several rare SSIDs in their PNL probably belong to
the same person, the same household, or the same workplace.

Think about it: "MEO-AB12", "Tesla_Service", and "eduroam" appearing in the
PNL of two different MACs is not a coincidence. That's a person who drives
a Tesla, works in academia, and has a MEO router at home. And they brought
both devices to class today.

This script loads one or more JSON files from 02_recon/04_probe_analyzer.py,
computes pairwise Jaccard similarity between all device PNLs, and
flags device pairs that are likely co-located or co-owned.

Jaccard similarity = |A ∩ B| / |A ∪ B|
  1.0 = identical PNL (same person, definitely)
  0.5 = half the networks in common (strong correlation)
  0.1 = a few common networks (weak, maybe just eduroam)
  0.0 = no common networks (strangers)

Usage:
    python3 06_analysis/03_pnl_correlator.py --input room.json
    python3 06_analysis/03_pnl_correlator.py --input session1.json session2.json session3.json
    python3 06_analysis/03_pnl_correlator.py --input room.json --threshold 0.3

No root required. No monitor mode. Just maths and JSON.

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import json
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path


# ──────────────────────────────────────────────
# SSIDs that are so common they add no signal
# Matching on "eduroam" means nothing — it's everywhere.
# ──────────────────────────────────────────────

_COMMON_SSIDS = {
    "eduroam", "AndroidAP", "iPhone", "AndroidShare",
    "Guest", "Free WiFi", "WiFi", "Teleworker",
    "ATTWifi", "xfinitywifi", "XFINITY", "CableWiFi",
    "_The Cloud", "BT Wi-fi", "BTWifi-with-FON",
    "NOS_WiFi_Passpoint", "MEO-WiFi", "NOS_WiFi",
    "Vodafone-Passpoint", "Hotspot",
}

# Minimum SSID length to consider — short SSIDs like "Home" are too generic
_MIN_SSID_LEN = 5


def _load_capture(path: str) -> list[dict]:
    """Load a 02_recon/04_probe_analyzer.py JSON output file."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("clients", [])
    except FileNotFoundError:
        print(f"[!] File not found: {path}")
        return []
    except json.JSONDecodeError as e:
        print(f"[!] JSON error in {path}: {e}")
        return []


def _meaningful_ssids(ssids: list[str]) -> set[str]:
    """
    Filter to SSIDs that are actually informative for correlation.
    Remove common networks, short names, and obvious defaults.
    """
    return {
        s for s in ssids
        if len(s) >= _MIN_SSID_LEN
        and s not in _COMMON_SSIDS
        and not s.startswith("DIRECT-")   # Wi-Fi Direct — everyone has these
        and not s.startswith("HP-Print")  # printer hotspots
        and not s.lower().startswith("androidap")
    }


def jaccard(a: set, b: set) -> float:
    """Classic Jaccard similarity. Returns 0 if both sets are empty."""
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _rarity_score(ssid: str, all_pnls: list[set]) -> float:
    """
    How rare is this SSID across all captured PNLs?
    A rare shared SSID is much stronger evidence than a common one.
    Returns a weight between 0.0 (seen everywhere) and 1.0 (unique to two devices).
    """
    count = sum(1 for pnl in all_pnls if ssid in pnl)
    if count <= 1:
        return 1.0
    # Inverse frequency — rarer = higher weight
    return 1.0 / count


def weighted_overlap(a: set, b: set, all_pnls: list[set]) -> tuple[float, list[tuple[str, float]]]:
    """
    Compute a rarity-weighted overlap score for two PNLs.
    Common SSIDs (eduroam) contribute little; unique SSIDs contribute a lot.
    Returns (total_score, [(ssid, weight), ...]) for the shared SSIDs.
    """
    shared  = a & b
    details = [(s, _rarity_score(s, all_pnls)) for s in shared]
    details.sort(key=lambda x: -x[1])
    total   = sum(w for _, w in details)
    return total, details


# ──────────────────────────────────────────────
# Main analysis
# ──────────────────────────────────────────────

def correlate(clients: list[dict], threshold: float, top_n: int) -> list[dict]:
    """
    Compute pairwise correlation for all devices.
    Returns pairs above threshold, sorted by score descending.

    Threshold logic: a pair is KEPT if either:
      - its Jaccard similarity >= threshold, OR
      - its weighted overlap score >= 1.0 (at least one strongly-rare shared SSID)
    A pair is skipped only when BOTH metrics are below their respective floors.
    This means a single extremely rare shared SSID (score >= 1.0) will always
    surface the pair regardless of the Jaccard threshold.
    """
    # Build per-device meaningful PNL
    device_pnls: list[tuple[str, bool, set]] = []   # (mac_masked, randomized, pnl)
    for c in clients:
        mac       = c.get("mac_masked", "?")
        rnd       = c.get("randomized", False)
        raw_ssids = c.get("ssids", [])
        pnl       = _meaningful_ssids(raw_ssids)
        if pnl:    # skip devices with no meaningful SSIDs
            device_pnls.append((mac, rnd, pnl))

    all_pnls = [p for _, _, p in device_pnls]

    pairs = []
    for (mac_a, rnd_a, pnl_a), (mac_b, rnd_b, pnl_b) in combinations(device_pnls, 2):
        j       = jaccard(pnl_a, pnl_b)
        score, details = weighted_overlap(pnl_a, pnl_b, all_pnls)

        # Skip this pair only if BOTH metrics are below their floors.
        # Pairs with score >= 1.0 (any rare shared SSID) are always kept.
        if j < threshold and score < 1.0:
            continue

        pairs.append({
            "mac_a":        mac_a,
            "mac_b":        mac_b,
            "rnd_a":        rnd_a,
            "rnd_b":        rnd_b,
            "jaccard":      round(j, 3),
            "weighted":     round(score, 2),
            "shared_ssids": [s for s, _ in details],
            "shared_count": len(details),
            "details":      details[:10],   # top 10 shared SSIDs with weights
        })

    pairs.sort(key=lambda x: (-x["weighted"], -x["jaccard"]))
    return pairs[:top_n]


def _correlation_label(jaccard: float, weighted: float) -> str:
    """
    Human-readable interpretation of the correlation scores.
    Diplomatically worded, because we're professionals.
    """
    if jaccard >= 0.7 or weighted >= 5.0:
        return "SAME PERSON (very likely)"
    if jaccard >= 0.4 or weighted >= 3.0:
        return "Same household / workplace (likely)"
    if jaccard >= 0.2 or weighted >= 1.5:
        return "Frequent co-location (possible)"
    return "Weak correlation"


# ──────────────────────────────────────────────
# Display
# ──────────────────────────────────────────────

def print_report(pairs: list[dict], clients: list[dict]):
    print(f"\n{'═' * 68}")
    print(f"  PNL CORRELATION REPORT — {len(pairs)} correlated pairs")
    print(f"  (from {len(clients)} total devices)")
    print(f"{'═' * 68}\n")

    if not pairs:
        print("  No correlated pairs found above the threshold.")
        print("  Try --threshold 0.1 for a more permissive search.")
        return

    for i, pair in enumerate(pairs, 1):
        label = _correlation_label(pair["jaccard"], pair["weighted"])
        rnd_a = " 🎲" if pair["rnd_a"] else ""
        rnd_b = " 🎲" if pair["rnd_b"] else ""

        print(f"  [{i:02d}] {label}")
        print(f"       Device A : {pair['mac_a']}{rnd_a}")
        print(f"       Device B : {pair['mac_b']}{rnd_b}")
        print(f"       Jaccard  : {pair['jaccard']:.3f}  |  "
              f"Weighted: {pair['weighted']:.2f}  |  "
              f"Shared SSIDs: {pair['shared_count']}")

        # Show the most distinctive shared SSIDs with rarity weights
        print(f"       Evidence:")
        for ssid, weight in pair["details"][:5]:
            bar = "█" * min(int(weight * 5), 10)
            print(f"         \"{ssid}\"  rarity:{weight:.2f}  {bar}")
        print()


def save_json(pairs: list[dict], path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({
            "generated_at":  __import__("datetime").datetime.now().isoformat(timespec="seconds"),
            "total_pairs":   len(pairs),
            "pairs":         pairs,
        }, fh, indent=2)
    print(f"[+] Saved → {path}")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Cross-correlate device PNLs to find devices that likely "
            "belong to the same person."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Input: JSON files from 02_recon/04_probe_analyzer.py\n\n"
            "Examples:\n"
            "  python3 06_analysis/03_pnl_correlator.py --input room.json\n"
            "  python3 06_analysis/03_pnl_correlator.py --input mon.json eve.json --threshold 0.2\n\n"
            "No root required. Pure offline analysis."
        ),
    )
    parser.add_argument("--input",     nargs="+", required=True,
                        help="JSON file(s) from 02_recon/04_probe_analyzer.py")
    parser.add_argument("--threshold", type=float, default=0.15,
                        help="Minimum Jaccard similarity to report (default: 0.15)")
    parser.add_argument("--top",       type=int,   default=20,
                        help="Maximum pairs to show (default: 20)")
    parser.add_argument("--output",    default=None,
                        help="Save correlation results to JSON")
    parser.add_argument("--no-filter", action="store_true",
                        help="Disable common SSID filtering (e.g. eduroam)")
    args = parser.parse_args()

    if args.no_filter:
        _COMMON_SSIDS.clear()

    # Load and merge all input files
    all_clients: list[dict] = []
    for path in args.input:
        loaded = _load_capture(path)
        print(f"[*] Loaded {len(loaded)} devices from {path}")
        all_clients.extend(loaded)

    # Deduplicate by mac_masked (same device across multiple captures)
    seen_macs: dict[str, dict] = {}
    for c in all_clients:
        mac = c.get("mac_masked", "")
        if mac not in seen_macs:
            seen_macs[mac] = c
        else:
            # Merge SSIDs from multiple captures
            existing = set(seen_macs[mac].get("ssids", []))
            new      = set(c.get("ssids", []))
            seen_macs[mac]["ssids"] = sorted(existing | new)
    merged = list(seen_macs.values())

    print(f"[*] Total unique devices: {len(merged)}")
    print(f"[*] Threshold: Jaccard ≥ {args.threshold}")
    print(f"[*] Computing pairwise correlations ...\n")

    pairs = correlate(merged, args.threshold, args.top)
    print_report(pairs, merged)

    if args.output:
        save_json(pairs, args.output)


if __name__ == "__main__":
    main()
