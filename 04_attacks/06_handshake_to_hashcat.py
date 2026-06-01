#!/usr/bin/env python3
"""
04_attacks/06_handshake_to_hashcat.py — Turn a captured .pcap into a hashcat 22000 file.

This is the bridge the README keeps promising. 03_capture/01_handshake_catcher.py and
04_attacks/04_pmkid_extractor.py give you a .pcap full of EAPOL frames; hashcat wants the
hc22000 (-m 22000) text format. This script does the conversion and, crucially,
validates that what you captured is actually crackable — so you don't burn an
hour of GPU time on half a handshake.

Two paths, automatically chosen:
  1. If hcxpcapngtool is installed (recommended, authoritative), we call it.
  2. Otherwise we fall back to a pure-scapy extractor that handles PMKIDs
     reliably and M1+M2 EAPOL pairs on a best-effort basis. For anything
     picky, install hcxtools — this fallback is for learning the format.

Output line formats (hashcat -m 22000):
  PMKID : WPA*01*PMKID*AP*STA*ESSID***
  EAPOL : WPA*02*MIC*AP*STA*ESSID*ANONCE*EAPOL_M2*MESSAGEPAIR

Usage:
    python3 04_attacks/06_handshake_to_hashcat.py --pcap lab.pcap
    python3 04_attacks/06_handshake_to_hashcat.py --pcap lab.pcap --output lab.22000
    python3 04_attacks/06_handshake_to_hashcat.py --pcap lab.pcap --no-hcxtools

Then crack:
    hashcat -m 22000 lab.22000 rockyou.txt

Requires: pip install scapy   (hcxpcapngtool optional but recommended)

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 3
"""

import argparse
import os
import shutil
import subprocess
import sys

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, EAPOL, PcapReader
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid, format_mac_plain,
    eapol_message_type, eapol_anonce, eapol_mic, eapol_zero_mic, eapol_pmkid,
)


# ──────────────────────────────────────────────
# Path 1 — hcxpcapngtool (the authoritative converter)
# ──────────────────────────────────────────────

def via_hcxtools(pcap: str, output: str) -> bool:
    tool = shutil.which("hcxpcapngtool")
    if not tool:
        return False
    print(f"[*] hcxpcapngtool found → using it ({tool})")
    r = subprocess.run([tool, "-o", output, pcap], capture_output=True, text=True)
    if r.stdout.strip():
        print(r.stdout.strip())
    if r.returncode == 0 and os.path.exists(output) and os.path.getsize(output) > 0:
        return True
    print("[!] hcxpcapngtool produced no output — falling back to scapy.")
    return False


# ──────────────────────────────────────────────
# Path 2 — pure-scapy extractor (educational fallback)
# ──────────────────────────────────────────────

def extract(pcap: str):
    essids: dict[str, str] = {}
    pmkids: dict[tuple, bytes] = {}   # (bssid, sta) -> pmkid
    m1: dict[tuple, bytes] = {}       # (bssid, sta) -> anonce
    pairs: list[dict] = []
    seen: set = set()

    with PcapReader(pcap) as pr:
        for pkt in pr:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                b = pkt[Dot11].addr3
                ss = get_ssid(pkt)
                if b and ss:
                    essids[b.lower()] = ss
                continue

            if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
                continue

            d = pkt[Dot11]
            ds = d.FCfield & 0x03
            if ds == 0x02:      # FromDS — frame from AP
                bssid, sta = d.addr2, d.addr1
            elif ds == 0x01:    # ToDS — frame to AP
                bssid, sta = d.addr1, d.addr2
            else:
                bssid, sta = d.addr3, (d.addr1 or d.addr2)
            if not bssid or not sta:
                continue
            bssid, sta = bssid.lower(), sta.lower()
            key = (bssid, sta)

            raw = bytes(pkt[EAPOL])
            mt = eapol_message_type(raw)
            if mt == 1:
                m1[key] = eapol_anonce(raw)
                pk = eapol_pmkid(raw)
                if pk:
                    pmkids[key] = pk
            elif mt == 2 and key in m1:
                mic = eapol_mic(raw)
                sig = (bssid, sta, mic.hex())
                if sig not in seen:
                    seen.add(sig)
                    pairs.append({"bssid": bssid, "sta": sta,
                                  "anonce": m1[key], "mic": mic,
                                  "eapol": eapol_zero_mic(raw)})
    return essids, pmkids, pairs


def build_lines(essids, pmkids, pairs):
    lines: list[str] = []
    stats = {"pmkid": 0, "eapol": 0, "no_essid": 0}

    for (bssid, sta), pk in pmkids.items():
        ess = essids.get(bssid)
        if not ess:
            stats["no_essid"] += 1
            continue
        lines.append(
            f"WPA*01*{pk.hex()}*{format_mac_plain(bssid)}*"
            f"{format_mac_plain(sta)}*{ess.encode().hex()}***")
        stats["pmkid"] += 1

    for p in pairs:
        ess = essids.get(p["bssid"])
        if not ess:
            stats["no_essid"] += 1
            continue
        # MESSAGEPAIR 00 = M1+M2, EAPOL sourced from M2.
        lines.append(
            f"WPA*02*{p['mic'].hex()}*{format_mac_plain(p['bssid'])}*"
            f"{format_mac_plain(p['sta'])}*{ess.encode().hex()}*"
            f"{p['anonce'].hex()}*{p['eapol'].hex()}*00")
        stats["eapol"] += 1

    return lines, stats


def via_scapy(pcap: str, output: str) -> bool:
    print("[*] Using pure-scapy extractor (install hcxtools for production use).")
    essids, pmkids, pairs = extract(pcap)
    lines, stats = build_lines(essids, pmkids, pairs)

    print(f"    ESSIDs seen      : {len(essids)}")
    print(f"    PMKID lines      : {stats['pmkid']}")
    print(f"    EAPOL M1+M2 lines: {stats['eapol']}")
    if stats["no_essid"]:
        print(f"    [!] Skipped {stats['no_essid']} candidate(s): no beacon/ESSID "
              f"in this pcap for that BSSID — capture a beacon too.")

    if not lines:
        print("\n[!] Nothing crackable found. Likely reasons:")
        print("    • Only M3/M4 captured (need M1+M2, or a PMKID in M1)")
        print("    • No beacon in the pcap, so the ESSID is unknown")
        print("    • Not actually a WPA2 handshake")
        return False

    with open(output, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Convert a .pcap handshake/PMKID capture to hashcat -m 22000.",
    )
    parser.add_argument("--pcap", required=True, help="Input capture (.pcap/.pcapng)")
    parser.add_argument("--output", default=None,
                        help="Output .22000 file (default: <pcap>.22000)")
    parser.add_argument("--no-hcxtools", action="store_true",
                        help="Force the pure-scapy fallback even if hcxtools exists.")
    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"[!] No such file: {args.pcap}")
        sys.exit(1)

    output = args.output or (os.path.splitext(args.pcap)[0] + ".22000")

    print(f"\n=== 04_attacks/06_handshake_to_hashcat.py ===")
    print(f"    Input  : {args.pcap}")
    print(f"    Output : {output}\n")

    ok = False
    if not args.no_hcxtools:
        ok = via_hcxtools(args.pcap, output)
    if not ok:
        ok = via_scapy(args.pcap, output)

    if ok:
        n = sum(1 for _ in open(output))
        print(f"\n[+] Saved {n} hash line(s) → {output}")
        print(f"    hashcat -m 22000 {output} rockyou.txt")
    else:
        # remove a possibly-empty file we never wrote to
        sys.exit(2)


if __name__ == "__main__":
    main()
