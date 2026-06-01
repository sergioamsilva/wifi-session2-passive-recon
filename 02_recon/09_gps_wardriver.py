#!/usr/bin/env python3
"""
02_recon/09_gps_wardriver.py — Log APs with GPS coordinates to a WiGLE-compatible CSV.

The grand finale of passive recon: drive (or walk) around, sniff beacons, and
stamp each AP with where you were standing when you heard it. The output CSV is
in WiGLE-1.4 format, so you can upload it to wigle.net or feed it straight into
06_analysis/04_wigle_enricher.py for offline geolocation.

GPS comes from gpsd (the standard Linux GPS daemon) over its TCP JSON protocol
— no extra Python dependency. No GPS? It still logs, with blank coordinates,
which is fine for an indoor walkthrough of the format.

  sudo apt install gpsd gpsd-clients
  gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock     # your GPS receiver

Passive. Sends nothing.

Usage:
    sudo python3 02_recon/09_gps_wardriver.py --iface wlan1mon --output drive.csv
    sudo python3 02_recon/09_gps_wardriver.py --iface wlan1mon --output drive.csv --no-gps

Requires: pip install scapy   (gpsd optional)

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import json
import socket
import sys
import threading
import time
from datetime import datetime

try:
    from scapy.all import sniff, Dot11, Dot11Beacon
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    require_root, require_monitor_mode, add_iface_arg,
    get_ssid, get_channel, get_rssi, classify_security,
)

# Shared GPS fix, updated by the gpsd reader thread.
_gps = {"lat": "", "lon": "", "alt": "", "acc": "", "ok": False}
_gps_stop = threading.Event()
_seen: set = set()
_csv = None
_count = 0


def gpsd_reader(host: str, port: int):
    """Connect to gpsd and keep _gps updated with the latest TPV fix."""
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print(f"[!] Could not connect to gpsd at {host}:{port} ({e}).")
        print("    Logging with blank coordinates. Use --no-gps to silence this.")
        return
    sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
    buf = b""
    sock.settimeout(1.0)
    print("[*] gpsd connected — waiting for a fix ...")
    while not _gps_stop.is_set():
        try:
            data = sock.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if not data:
            break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("class") == "TPV" and obj.get("lat") is not None:
                first = not _gps["ok"]
                _gps.update(lat=obj.get("lat", ""), lon=obj.get("lon", ""),
                            alt=obj.get("alt", ""), acc=obj.get("eph", ""), ok=True)
                if first:
                    print(f"[+] GPS fix acquired: {_gps['lat']}, {_gps['lon']}")
    sock.close()


def handle(pkt):
    global _count
    if not pkt.haslayer(Dot11Beacon):
        return
    bssid = pkt[Dot11].addr3
    if not bssid:
        return
    bssid = bssid.lower()
    if bssid in _seen:
        return
    _seen.add(bssid)

    sec = classify_security(pkt)
    auth = f"[{sec['label']}]"
    if sec["pmf"] == "required":
        auth += "[PMF]"
    row = [
        bssid.upper(),
        get_ssid(pkt) or "",
        auth,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        str(get_channel(pkt) or ""),
        str(get_rssi(pkt) if get_rssi(pkt) is not None else ""),
        str(_gps["lat"]), str(_gps["lon"]), str(_gps["alt"]), str(_gps["acc"]),
        "WIFI",
    ]
    _csv.write(",".join(_quote(c) for c in row) + "\n")
    _csv.flush()
    _count += 1
    fix = "📍" if _gps["ok"] else "  "
    print(f"  {fix} {bssid}  {row[1]:<22} {auth:<24} ch{row[4]:>3}  {row[5]} dBm")


def _quote(value: str) -> str:
    """Minimal CSV quoting — SSIDs can contain commas."""
    if any(c in value for c in (",", '"', "\n")):
        return '"' + value.replace('"', '""') + '"'
    return value


def main():
    global _csv
    parser = argparse.ArgumentParser(
        description="Wardrive: log beacons to a WiGLE-1.4 CSV, stamped with GPS.",
    )
    add_iface_arg(parser)
    parser.add_argument("--output", required=True, help="Output CSV path.")
    parser.add_argument("--no-gps", action="store_true",
                        help="Skip gpsd; log with blank coordinates.")
    parser.add_argument("--gpsd-host", default="127.0.0.1")
    parser.add_argument("--gpsd-port", type=int, default=2947)
    args = parser.parse_args()

    require_root("02_recon/09_gps_wardriver.py")
    require_monitor_mode(args.iface)

    try:
        _csv = open(args.output, "w")
    except OSError as e:
        print(f"[!] Cannot open {args.output}: {e}")
        sys.exit(1)

    # WiGLE-1.4 pre-header + column header.
    _csv.write("WigleWifi-1.4,appRelease=cybers3c,model=scapy,release=1,"
               "device=wardriver,display=,board=,brand=CYBERS3C\n")
    _csv.write("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,"
               "CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n")
    _csv.flush()

    reader = None
    if not args.no_gps:
        reader = threading.Thread(target=gpsd_reader,
                                  args=(args.gpsd_host, args.gpsd_port), daemon=True)
        reader.start()

    print(f"\n=== 02_recon/09_gps_wardriver.py | iface={args.iface} ===")
    print(f"[*] Logging to {args.output} (WiGLE-1.4). Passive. Ctrl-C to stop.\n")

    try:
        sniff(iface=args.iface, prn=handle, store=0,
              lfilter=lambda p: p.haslayer(Dot11Beacon))
    except KeyboardInterrupt:
        pass
    finally:
        _gps_stop.set()
        _csv.close()

    print(f"\n[+] Done. {_count} unique APs → {args.output}")
    print(f"    Upload to wigle.net, or enrich offline:")
    print(f"    python3 06_analysis/04_wigle_enricher.py  (see its --help for CSV input)")


if __name__ == "__main__":
    main()
