#!/usr/bin/env python3
"""
02_recon/04_probe_analyzer.py — Harvest 802.11 Probe Request frames and expose
                        the travel diaries people carry in their pockets.

Every phone in this room is screaming the names of every Wi-Fi network
it has ever loved. We are just politely listening.

This is entirely passive. We send zero frames. We are ghosts.
Incredibly well-informed ghosts who know where you had your last vacation.

Usage:
    sudo python3 02_recon/04_probe_analyzer.py --iface wlan1 --output room.json
    sudo python3 02_recon/04_probe_analyzer.py --iface wlan1 --output room.json --duration 600

Run 01_setup/03_channel_hopper.py in a separate terminal for full coverage.
Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import signal
import sys
import time
from datetime import datetime

try:
    from scapy.all import Dot11, Dot11Elt, RadioTap, sniff
except ImportError:
    print("[!] Scapy not found. The entire script is useless without it.")
    print("    Fix:  pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid, get_rssi,
    is_randomized, mask_mac,
    load_oui_db, lookup_vendor,
    require_root, require_monitor_mode,
    add_iface_arg, add_output_arg, add_duration_arg,
    safe_write_json,
)


# ──────────────────────────────────────────────
# OUI / Vendor lookup
# Knowing the vendor turns a MAC into a story.
# ──────────────────────────────────────────────

_OUI_DB: dict[str, str] = {}


# ──────────────────────────────────────────────
# Capture state
# ──────────────────────────────────────────────

# mac → {vendor, randomized, ssids: set(), count, rssi_list, first_seen, last_seen}
_clients: dict[str, dict] = {}
_start_time = time.time()


# ──────────────────────────────────────────────
# Packet processing
# ──────────────────────────────────────────────

def handle_packet(pkt):
    """
    Process a single Probe Request frame.
    Called by Scapy's sniff() for every matching packet — fast path, no drama.
    """
    if not pkt.haslayer(Dot11):
        return
    dot11 = pkt[Dot11]

    # Probe Request = management frame (type 0), subtype 4
    if dot11.type != 0 or dot11.subtype != 4:
        return

    mac = dot11.addr2
    if not mac:
        return
    mac = mac.lower()

    ssid = get_ssid(pkt)
    rssi = get_rssi(pkt)
    now  = datetime.now().isoformat(timespec="seconds")

    if mac not in _clients:
        _clients[mac] = {
            "vendor":     lookup_vendor(mac, _OUI_DB),
            "randomized": is_randomized(mac),
            "ssids":      set(),
            "count":      0,
            "rssi_list":  [],
            "first_seen": now,
            "last_seen":  now,
        }

    entry = _clients[mac]
    entry["count"]     += 1
    entry["last_seen"]  = now
    if ssid:
        entry["ssids"].add(ssid)
    if rssi is not None:
        entry["rssi_list"].append(rssi)

    # Live display — one line, updated in-place so the terminal doesn't become a wall of text
    elapsed    = int(time.time() - _start_time)
    rnd_flag   = "🎲" if entry["randomized"] else "  "
    vendor_str = entry["vendor"][:18]
    print(
        f"\r  {rnd_flag} {mask_mac(mac):<20}  {vendor_str:<18}"
        f"  #{entry['count']:4d}  SSIDs:{len(entry['ssids']):3d}"
        f"  clients:{len(_clients):3d}  {elapsed:4d}s",
        end="",
        flush=True,
    )


# ──────────────────────────────────────────────
# Reporting
# ──────────────────────────────────────────────

def print_report():
    """
    Print the full summary table. This is the part the class gathers around.
    Please anonymise before projecting on the big screen. Or don't. Your call.
    (Please do.)
    """
    print("\n\n" + "═" * 72)
    print(f"  CLIENTS AND PNL — {len(_clients)} unique clients")
    print("═" * 72)
    print(f"  {'CLIENT MAC':<20}  {'RND':<3}  {'#':>5}  {'VENDOR':<18}  SSIDS PROBED")
    print("─" * 72)

    sorted_clients = sorted(_clients.items(), key=lambda x: x[1]["count"], reverse=True)

    for mac, info in sorted_clients:
        rnd       = "🎲" if info["randomized"] else ""
        ssid_list = sorted(info["ssids"])

        # Show first 3 SSIDs — the rest are implied to be equally embarrassing
        preview = ", ".join(ssid_list[:3])
        if len(ssid_list) > 3:
            preview += f" (+{len(ssid_list) - 3} more)"

        print(f"  {mask_mac(mac):<20}  {rnd:<3}  {info['count']:>5}"
              f"  {info['vendor'][:18]:<18}  {preview}")

    print("─" * 72)

    rnd_count = sum(1 for c in _clients.values() if c["randomized"])
    total     = len(_clients)
    pct       = (rnd_count / total * 100) if total else 0.0
    elapsed   = int(time.time() - _start_time)

    print(f"  [stat] Randomized MACs : {rnd_count}/{total} ({pct:.0f}%)")
    print(f"  [stat] Capture time    : {elapsed}s")
    print(f"  [stat] Total probes    : {sum(c['count'] for c in _clients.values())}")


def save_json(path: str):
    """
    Serialize findings to JSON.
    MACs are masked. We collect for education, not for surveillance capitalism.
    """
    data = []
    for mac, info in sorted(_clients.items(), key=lambda x: x[1]["count"], reverse=True):
        rssi_list = info["rssi_list"]
        data.append({
            "mac_masked":   mask_mac(mac),
            "vendor":       info["vendor"],
            "randomized":   info["randomized"],
            "probe_count":  info["count"],
            "ssids":        sorted(info["ssids"]),
            "rssi_avg_dbm": (
                round(sum(rssi_list) / len(rssi_list), 1) if rssi_list else None
            ),
            "first_seen":   info["first_seen"],
            "last_seen":    info["last_seen"],
        })

    output_dict = {
        "captured_at":    datetime.now().isoformat(timespec="seconds"),
        "total_clients":  len(_clients),
        "randomized_pct": round(
            sum(1 for c in _clients.values() if c["randomized"])
            / max(len(_clients), 1) * 100,
            1,
        ),
        "clients": data,
    }

    safe_write_json(output_dict, path)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    global _OUI_DB

    require_root()

    parser = argparse.ArgumentParser(
        description=(
            "Passive 802.11 probe request analyser — "
            "builds the Preferred Network List of every client in range."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 02_recon/04_probe_analyzer.py --iface wlan1 --output room.json\n"
            "  sudo python3 02_recon/04_probe_analyzer.py --iface wlan1 --duration 600\n\n"
            "🎲 = randomized MAC.  ** = masked octets.  We are the good guys."
        ),
    )
    add_iface_arg(parser)
    add_output_arg(parser, default="probes.json")
    add_duration_arg(parser)
    args = parser.parse_args()

    require_monitor_mode(args.iface)

    _OUI_DB     = load_oui_db()
    oui_source  = f"wireshark manuf ({len(_OUI_DB)} OUIs)" if _OUI_DB else "built-in fallback table"

    print(f"\n=== 02_recon/04_probe_analyzer.py ===")
    print(f"    Interface  : {args.iface}")
    print(f"    Output     : {args.output}")
    print(f"    Duration   : {'infinite (Ctrl-C to stop)' if args.duration == 0 else f'{args.duration}s'}")
    print(f"    OUI source : {oui_source}")
    print(f"    Mode       : PASSIVE — we send ZERO frames")
    print()
    print("    Listening for probe requests ...")
    print("    Tip: run 01_setup/03_channel_hopper.py in another terminal for full coverage.\n")

    def on_sigint(sig, frame):
        """Handle Ctrl-C gracefully — print report, save file, exit cleanly."""
        print_report()
        save_json(args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    # lfilter: management frame (type 0) + subtype 4 (probe request)
    # Scapy applies this before calling handle_packet — cheap CPU filter.
    timeout = args.duration if args.duration > 0 else None
    sniff(
        iface=args.iface,
        prn=handle_packet,
        store=False,
        timeout=timeout,
        lfilter=lambda p: (
            p.haslayer(Dot11)
            and p[Dot11].type    == 0
            and p[Dot11].subtype == 4
        ),
    )

    # Reached only when --duration expires naturally (not via Ctrl-C)
    print_report()
    save_json(args.output)


if __name__ == "__main__":
    main()
