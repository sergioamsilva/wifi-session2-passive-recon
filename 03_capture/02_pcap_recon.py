#!/usr/bin/env python3
"""
03_capture/02_pcap_recon.py — Full passive recon over a saved .pcap. No adapter required.

Every capture script in this suite needs a card in monitor mode. This one
doesn't: point it at a .pcap / .pcapng you captured earlier — or one handed out
in class — and it reconstructs the whole picture offline:

  • Access points : SSID, channel, security (WPA2/WPA3/PMF), vendor, signal
  • Clients       : vendor, MAC randomization, the SSIDs they probed (their PNL)
  • Associations  : which client is talking to which AP
  • Handshakes    : which (AP, client) pairs have a crackable EAPOL / PMKID

It's the offline twin of 03/05/07/09 rolled into one — ideal for teaching when
not everyone has an Alfa card. Feed the JSON to 07_reporting/01_report_generator.py, and any
crackable capture to 04_attacks/06_handshake_to_hashcat.py.

Usage:
    python3 03_capture/02_pcap_recon.py --pcap lab.pcap
    python3 03_capture/02_pcap_recon.py --pcap lab.pcap --output recon.json

Requires: pip install scapy   (no root, no monitor mode)

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import os
import sys
from datetime import datetime

try:
    from scapy.all import (Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq,
                           Dot11AssoReq, Dot11ReassoReq, EAPOL, PcapReader)
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid, get_channel, get_rssi, classify_security,
    is_randomized, mask_mac, lookup_vendor, load_oui_db,
    eapol_message_type, eapol_pmkid, safe_write_json,
)

BROADCAST = "ff:ff:ff:ff:ff:ff"


def crackable(hs: dict) -> bool:
    """A pair is crackable with a PMKID, or with M1+M2 / M2+M3 captured."""
    m = hs["msgs"]
    return hs["pmkid"] or {1, 2} <= m or {2, 3} <= m


def analyze(pcap: str, oui: dict):
    aps: dict[str, dict] = {}
    clients: dict[str, dict] = {}
    handshakes: dict[tuple, dict] = {}
    frames = 0

    def ap(bssid):
        return aps.setdefault(bssid, {
            "bssid": bssid, "ssid": "", "channel": None, "security": None,
            "pmf": None, "vendor": lookup_vendor(bssid, oui), "rssi": None,
            "beacons": 0, "clients": set()})

    def cli(mac):
        return clients.setdefault(mac, {
            "mac": mac, "vendor": lookup_vendor(mac, oui),
            "randomized": is_randomized(mac), "probes": set(),
            "ap": None, "data_frames": 0})

    def bind(bssid, sta):
        if bssid and sta and bssid != BROADCAST and sta != BROADCAST:
            c = cli(sta)
            c["ap"] = c["ap"] or bssid
            ap(bssid)["clients"].add(sta)

    with PcapReader(pcap) as pr:
        for pkt in pr:
            if not pkt.haslayer(Dot11):
                continue
            frames += 1
            d = pkt[Dot11]

            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                b = d.addr3
                if not b:
                    continue
                rec = ap(b.lower())
                rec["beacons"] += 1
                if (ss := get_ssid(pkt)):
                    rec["ssid"] = ss
                if (ch := get_channel(pkt)):
                    rec["channel"] = ch
                sec = classify_security(pkt)
                rec["security"], rec["pmf"] = sec["label"], sec["pmf"]
                r = get_rssi(pkt)
                if r is not None and (rec["rssi"] is None or r > rec["rssi"]):
                    rec["rssi"] = r

            elif pkt.haslayer(Dot11ProbeReq):
                c = d.addr2
                if c and (ss := get_ssid(pkt)):
                    cli(c.lower())["probes"].add(ss)

            elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
                if d.addr2 and d.addr3:
                    bind(d.addr3.lower(), d.addr2.lower())

            elif pkt.haslayer(EAPOL):
                ds = d.FCfield & 0x03
                if ds == 0x02:
                    b, c = d.addr2, d.addr1
                elif ds == 0x01:
                    b, c = d.addr1, d.addr2
                else:
                    b, c = d.addr3, (d.addr1 or d.addr2)
                if not b or not c:
                    continue
                b, c = b.lower(), c.lower()
                raw = bytes(pkt[EAPOL])
                mt = eapol_message_type(raw)
                hs = handshakes.setdefault((b, c), {"msgs": set(), "pmkid": False})
                if mt:
                    hs["msgs"].add(mt)
                if mt == 1 and eapol_pmkid(raw):
                    hs["pmkid"] = True
                bind(b, c)

            elif d.type == 2:  # data frame → association + activity
                ds = d.FCfield & 0x03
                if ds == 0x01:
                    b, c = d.addr1, d.addr2
                elif ds == 0x02:
                    b, c = d.addr2, d.addr1
                else:
                    continue
                if b and c:
                    b, c = b.lower(), c.lower()
                    bind(b, c)
                    if c in clients and c != BROADCAST:
                        clients[c]["data_frames"] += 1

    return aps, clients, handshakes, frames


def report(aps, clients, handshakes, frames):
    print(f"\n{'═' * 72}")
    print(f"  PCAP RECON — {frames} 802.11 frames | {len(aps)} APs | "
          f"{len(clients)} clients")
    print(f"{'═' * 72}")

    print(f"\n  ACCESS POINTS")
    print(f"  {'SSID':<22} {'BSSID':<17} {'CH':>3} {'SECURITY':<22} {'VENDOR'}")
    print("  " + "─" * 86)
    for a in sorted(aps.values(), key=lambda x: -(x["rssi"] or -999)):
        pmf = "+PMF" if a["pmf"] == "required" else ""
        print(f"  {(a['ssid'] or '<hidden>'):<22} {a['bssid']:<17} "
              f"{str(a['channel'] or '?'):>3} {(a['security'] or '?')+pmf:<22} "
              f"{a['vendor']}  ({len(a['clients'])} clients)")

    rnd = sum(1 for c in clients.values() if c["randomized"])
    print(f"\n  CLIENTS  ({rnd}/{len(clients)} randomized)")
    print(f"  {'CLIENT':<19} {'RND':<4} {'VENDOR':<18} {'ASSOC AP':<17} PROBES")
    print("  " + "─" * 86)
    for c in sorted(clients.values(), key=lambda x: -x["data_frames"]):
        flag = "🎲" if c["randomized"] else ""
        probes = ", ".join(sorted(c["probes"])[:3])
        if len(c["probes"]) > 3:
            probes += f" (+{len(c['probes']) - 3})"
        print(f"  {mask_mac(c['mac']):<19} {flag:<4} {c['vendor']:<18} "
              f"{(c['ap'] or '—'):<17} {probes}")

    cr = [(k, v) for k, v in handshakes.items() if crackable(v)]
    print(f"\n  HANDSHAKES / PMKIDs  ({len(cr)} crackable of {len(handshakes)} seen)")
    print("  " + "─" * 86)
    for (b, c), hs in handshakes.items():
        msgs = "".join(f"M{i}" for i in sorted(hs["msgs"]))
        tag = "PMKID" if hs["pmkid"] else ""
        mark = "✓" if crackable(hs) else " "
        print(f"  [{mark}] {b}  ↔  {mask_mac(c)}  {msgs} {tag}")
    if cr:
        print(f"\n  → Crackable. Convert with:")
        print(f"    python3 04_attacks/06_handshake_to_hashcat.py --pcap <this.pcap> --output out.22000")


def main():
    parser = argparse.ArgumentParser(
        description="Offline passive recon over a saved .pcap — no adapter needed.",
    )
    parser.add_argument("--pcap", required=True, help="Capture file (.pcap/.pcapng)")
    parser.add_argument("--output", default=None, help="Write findings as JSON here.")
    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"[!] No such file: {args.pcap}")
        sys.exit(1)

    print(f"\n=== 03_capture/02_pcap_recon.py | {args.pcap} ===")
    oui = load_oui_db()
    aps, clients, handshakes, frames = analyze(args.pcap, oui)

    if frames == 0:
        print("[!] No 802.11 frames found. Was this captured in monitor mode?")
        sys.exit(1)

    report(aps, clients, handshakes, frames)

    if args.output:
        payload = {
            "analyzed_at": datetime.now().isoformat(timespec="seconds"),
            "pcap": os.path.basename(args.pcap),
            "frames": frames,
            "access_points": [
                {**a, "clients": len(a["clients"])} for a in aps.values()],
            "clients": [
                {**c, "probes": sorted(c["probes"])} for c in clients.values()],
            "handshakes": [
                {"bssid": b, "client": c, "msgs": sorted(hs["msgs"]),
                 "pmkid": hs["pmkid"], "crackable": crackable(hs)}
                for (b, c), hs in handshakes.items()],
        }
        safe_write_json(payload, args.output)


if __name__ == "__main__":
    main()
