#!/usr/bin/env python3
"""
06_analysis/04_wigle_enricher.py — Geolocate SSIDs from a captured PNL using WiGLE.

WiGLE (wigle.net) is a crowdsourced database of over 1 billion geolocated
Wi-Fi networks. If an AP was ever seen by a wardriver with the WiGLE app,
its BSSID and approximate GPS coordinates are in there.

Given the PNL output from 02_recon/04_probe_analyzer.py, this script queries WiGLE
for each SSID and returns approximate locations where that network was seen.

Combined with the probe capture, this means:
  Device probes for "MEO-AB12"
    → WiGLE knows "MEO-AB12" is at lat 38.73, lon -9.14
    → Target lives approximately in Almada, Portugal.

This is the "WiGLE OSINT" demo from slide 21 — done programmatically.

Requirements:
  - Free WiGLE account at wigle.net
  - API credentials (Settings → API Token)
  - pip install requests

Usage:
    python3 06_analysis/04_wigle_enricher.py \\
        --input room.json \\
        --api-name "AID..." --api-token "TOKEN..." \\
        --output enriched.json

    # Or set env vars to avoid exposing credentials in shell history:
    export WIGLE_API_NAME="AID..."
    export WIGLE_API_TOKEN="TOKEN..."
    python3 06_analysis/04_wigle_enricher.py --input room.json --output enriched.json

Rate limits: WiGLE free tier allows ~10 API calls/minute. This script
respects that. Don't remove the rate limiting or your key gets banned.

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] requests not installed. pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# WiGLE API
# ──────────────────────────────────────────────

_WIGLE_BASE = "https://api.wigle.net/api/v2"
_RATE_DELAY  = 6.5   # seconds between requests (10/min free tier limit)


def _wigle_headers(api_name: str, api_token: str) -> dict:
    """
    WiGLE uses HTTP Basic Auth with API Name + API Token (not username/password).
    The API name starts with 'AID' and is different from your login name.
    """
    import base64
    credentials = base64.b64encode(f"{api_name}:{api_token}".encode()).decode()
    return {
        "Authorization": f"Basic {credentials}",
        "Accept":        "application/json",
    }


def _search_by_ssid(ssid: str, headers: dict) -> tuple[list[dict], str]:
    """
    Search WiGLE for all observed BSSIDs matching this SSID.
    Returns (results, status) where status is one of:
      "ok"        — results found (status 200, non-empty)
      "not_found" — status 200 but empty results (SSID not in WiGLE)
      "error_NNN" — non-200 HTTP status (API error)
      "exception" — network/timeout error
    """
    try:
        resp = requests.get(
            f"{_WIGLE_BASE}/network/search",
            params={
                "ssid":       ssid,
                "onlymine":   "false",
                "freenet":    "false",
                "paynet":     "false",
                "lastupdt":   "",
                "variance":   "0.010",
                "resultsPerPage": 10,
            },
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 401:
            print(f"\n[!] WiGLE authentication failed. Check your API credentials.")
            sys.exit(1)
        if resp.status_code == 429:
            print(f"\n[!] Rate limit hit. Sleeping 60 seconds ...")
            time.sleep(60)
            return [], "error_429"
        if resp.status_code != 200:
            return [], f"error_{resp.status_code}"

        results = resp.json().get("results", [])
        if not results:
            return [], "not_found"
        return results, "ok"

    except requests.RequestException as e:
        print(f"\n[!] WiGLE request failed for SSID '{ssid}': {e}")
        return [], "exception"


def _search_by_bssid(bssid: str, headers: dict) -> dict | None:
    """
    Search WiGLE for a specific BSSID. More precise than SSID search —
    a BSSID is globally unique (mostly), so this gives one specific location.
    """
    try:
        resp = requests.get(
            f"{_WIGLE_BASE}/network/search",
            params={"netid": bssid.upper().replace(":", "%3A")},
            headers=headers,
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        results = resp.json().get("results", [])
        return results[0] if results else None
    except Exception:
        return None


def _format_location(record: dict) -> dict:
    """
    Extract the useful location fields from a WiGLE search result.
    Validates lat/lon as actual floats before constructing the maps URL —
    WiGLE occasionally returns None or non-numeric strings for coordinates.
    """
    lat = record.get("trilat")
    lon = record.get("trilong")

    maps_url = None
    if lat is not None and lon is not None:
        try:
            float(lat)
            float(lon)
            maps_url = f"https://www.google.com/maps?q={lat},{lon}"
        except (TypeError, ValueError):
            pass  # coordinates present but unparseable — skip the URL

    return {
        "bssid":     record.get("netid", "?"),
        "ssid":      record.get("ssid", "?"),
        "lat":       lat,
        "lon":       lon,
        "accuracy":  record.get("accuracy"),
        "country":   record.get("country"),
        "region":    record.get("region"),
        "city":      record.get("city"),
        "last_seen": record.get("lastupdt"),
        "encryption":record.get("encryption"),
        "maps_url":  maps_url,
    }


# ──────────────────────────────────────────────
# Main enrichment pipeline
# ──────────────────────────────────────────────

def enrich_clients(
    clients:   list[dict],
    headers:   dict,
    max_ssids: int,
    min_probes: int,
) -> list[dict]:
    """
    For each client in the capture, look up their most interesting SSIDs
    on WiGLE and attach geolocation data.
    """
    enriched = []
    total_queries = 0

    for i, client in enumerate(clients):
        mac    = client.get("mac_masked", "?")
        ssids  = client.get("ssids", [])
        probes = client.get("probe_count", 0)

        if probes < min_probes:
            continue  # skip devices that barely appeared

        if not ssids:
            continue

        print(f"\n  [{i+1:3d}/{len(clients)}] {mac}  ({len(ssids)} SSIDs, {probes} probes)")

        client_locations = []

        # Process SSIDs most likely to be home/office (longer, specific names)
        sorted_ssids = sorted(ssids, key=lambda s: -len(s))[:max_ssids]

        for ssid in sorted_ssids:
            if len(ssid) < 6:
                print(f"       skip \"{ssid}\" (too short, too generic)")
                continue

            print(f"       querying \"{ssid}\" ...", end="", flush=True)
            results, status = _search_by_ssid(ssid, headers)
            total_queries += 1

            if status == "ok":
                locations = [_format_location(r) for r in results[:3]]
                client_locations.append({
                    "ssid":      ssid,
                    "found":     len(results),
                    "locations": locations,
                })
                # Show the first result inline
                loc = locations[0]
                city    = loc.get("city") or ""
                region  = loc.get("region") or ""
                country = loc.get("country") or ""
                place   = ", ".join(filter(None, [city, region, country])) or "unknown location"
                print(f" → {len(results)} results — {place}")
                if loc.get("maps_url"):
                    print(f"         {loc['maps_url']}")
            elif status == "not_found":
                print(f" → not in WiGLE database")
            else:
                # status is "error_NNN" or "exception"
                code = status.replace("error_", "") if status.startswith("error_") else "?"
                print(f" → API error (code {code})")

            # Respect rate limit — free tier is 10 req/min
            time.sleep(_RATE_DELAY)

        enriched.append({
            **client,
            "wigle_results": client_locations,
            "wigle_queried": len(sorted_ssids),
        })

    print(f"\n[*] Total WiGLE queries: {total_queries}")
    return enriched


# ──────────────────────────────────────────────
# Report
# ──────────────────────────────────────────────

def print_report(enriched: list[dict]):
    print(f"\n\n{'═' * 68}")
    print(f"  WIGLE GEOLOCATION REPORT — {len(enriched)} devices")
    print(f"{'═' * 68}\n")

    for client in enriched:
        mac     = client.get("mac_masked", "?")
        rnd     = " 🎲" if client.get("randomized") else ""
        results = client.get("wigle_results", [])

        if not results:
            continue

        print(f"  {mac}{rnd}")
        for r in results:
            ssid = r["ssid"]
            for loc in r["locations"][:1]:  # show best result per SSID
                city    = loc.get("city") or ""
                region  = loc.get("region") or ""
                country = loc.get("country") or ""
                place   = ", ".join(filter(None, [city, region, country])) or "?"
                lat, lon = loc.get("lat"), loc.get("lon")
                coords  = f"{lat:.4f}, {lon:.4f}" if lat and lon else "?"

                print(f"    \"{ssid}\"  →  {place}  [{coords}]")
                if loc.get("maps_url"):
                    print(f"           {loc['maps_url']}")
        print()


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Enrich captured PNL data with WiGLE geolocation — "
            "turn SSIDs into map coordinates."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Get free API credentials at: https://wigle.net → Settings → API Token\n\n"
            "The API name starts with 'AID' — it's not your WiGLE username.\n\n"
            "Rate limit: 10 requests/minute on free tier.\n"
            "This script sleeps 6.5s between queries automatically.\n\n"
            "Privacy note: we send SSIDs to WiGLE's servers.\n"
            "Do not run this on personally identifying SSIDs without consent."
        ),
    )
    parser.add_argument("--input",       required=True,
                        help="JSON output from 02_recon/04_probe_analyzer.py")
    parser.add_argument("--output",      default=None,
                        help="Save enriched results to JSON")
    parser.add_argument("--api-name",    default=os.environ.get("WIGLE_API_NAME"),
                        help="WiGLE API name (env: WIGLE_API_NAME)")
    parser.add_argument("--api-token",   default=os.environ.get("WIGLE_API_TOKEN"),
                        help="WiGLE API token (env: WIGLE_API_TOKEN)")
    parser.add_argument("--max-ssids",   type=int, default=5,
                        help="Max SSIDs to query per device (default: 5)")
    parser.add_argument("--min-probes",  type=int, default=3,
                        help="Min probe count to include a device (default: 3)")
    args = parser.parse_args()

    # Credential check FIRST — fail fast before any file I/O.
    # Nothing more frustrating than waiting for a large JSON to load
    # only to discover your API token is missing.
    if not args.api_name or not args.api_token:
        print("[!] WiGLE API credentials required.")
        print("    --api-name and --api-token, or set WIGLE_API_NAME / WIGLE_API_TOKEN")
        print("    Get them free at: https://wigle.net → Settings → API Token")
        sys.exit(1)

    # Load capture (after credentials are confirmed)
    try:
        with open(args.input, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    clients = data.get("clients", [])
    print(f"\n=== 06_analysis/04_wigle_enricher.py ===")
    print(f"    Input     : {args.input} ({len(clients)} devices)")
    print(f"    Max SSIDs : {args.max_ssids} per device")
    print(f"    Min probes: {args.min_probes}")
    print(f"    Rate limit: {_RATE_DELAY}s between queries")
    print(f"\n[*] Starting enrichment — this will take a while. Get a coffee.\n")

    headers  = _wigle_headers(args.api_name, args.api_token)
    enriched = enrich_clients(clients, headers, args.max_ssids, args.min_probes)

    print_report(enriched)

    if args.output:
        out = {
            "generated_at":  datetime.now().isoformat(timespec="seconds"),
            "source_file":   args.input,
            "total_clients": len(enriched),
            "clients":       enriched,
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"[+] Saved → {args.output}")


if __name__ == "__main__":
    main()
