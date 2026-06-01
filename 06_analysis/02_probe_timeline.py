#!/usr/bin/env python3
"""
06_analysis/02_probe_timeline.py — Visualise probe burst patterns and device wake/sleep cycles.

When a phone wakes from standby, it fires a burst of 3-10 probe requests
in rapid succession, then goes quiet. This is completely predictable behaviour
and reveals — without decrypting anything — when a person picked up their phone.

What this shows in 30 minutes of capture:
  • When each device woke up (picked up phone / walked into range)
  • When it went to sleep
  • How aggressive the scanner is (burst size and rate)
  • Channel-scan patterns (sequence of channel changes in burst)
  • Approximate arrival and departure times of people in the room

This is the technique retail analytics companies used before Apple
tried to stop them with MAC randomization. It still works because
the timing behaviour is OS-determined, not MAC-determined.

Usage:
    sudo python3 06_analysis/02_probe_timeline.py --iface wlan1
    sudo python3 06_analysis/02_probe_timeline.py --iface wlan1 --duration 1800 --output timeline.json
    # Replay from existing capture:
    python3 06_analysis/02_probe_timeline.py --pcap probes.pcap

Requires: pip install scapy

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import Dot11, rdpcap, sniff
except ImportError:
    print("[!] Scapy missing. pip install scapy")
    sys.exit(1)

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import (
    get_ssid,
    get_rssi,
    is_randomized,
    mask_mac,
    require_root,
    require_monitor_mode,
    add_output_arg,
    add_duration_arg,
    safe_write_json,
)


# ──────────────────────────────────────────────
# Burst detection parameters
# A "burst" is a cluster of probes separated by less than BURST_GAP seconds.
# A "sleep" is any gap longer than SLEEP_GAP seconds.
# ──────────────────────────────────────────────

BURST_GAP  = 2.0    # seconds — probes within this gap = same burst
SLEEP_GAP  = 30.0   # seconds — gap longer than this = device went to sleep


# ──────────────────────────────────────────────
# State
# mac → list of (timestamp_float, ssid, rssi)
# ──────────────────────────────────────────────

_events: dict[str, list[tuple[float, str, int | None]]] = defaultdict(list)
_capture_start: float = time.time()
_first_packet:  float | None = None


def handle_packet(pkt, ts: float | None = None):
    global _first_packet

    if not pkt.haslayer(Dot11):
        return
    dot11 = pkt[Dot11]
    if dot11.type != 0 or dot11.subtype != 4:
        return

    mac = dot11.addr2
    if not mac:
        return
    mac = mac.lower()

    # Use packet timestamp if available (pcap replay), otherwise wall clock
    pkt_ts = ts or (float(pkt.time) if hasattr(pkt, "time") else time.time())
    if _first_packet is None:
        _first_packet = pkt_ts

    ssid = get_ssid(pkt)
    rssi = get_rssi(pkt)

    _events[mac].append((pkt_ts, ssid, rssi))

    elapsed = int(time.time() - _capture_start)
    print(
        f"\r  devices:{len(_events):3d}  probes:{sum(len(v) for v in _events.values()):6d}"
        f"  {elapsed:4d}s",
        end="", flush=True,
    )


# ──────────────────────────────────────────────
# Burst analysis
# ──────────────────────────────────────────────

def _compute_bursts(timestamps: list[float]) -> list[dict]:
    """
    Group timestamps into bursts separated by BURST_GAP.
    Returns list of {start, end, count, gap_before} dicts.
    """
    if not timestamps:
        return []

    ts = sorted(timestamps)
    bursts: list[dict] = []
    burst_start = ts[0]
    burst_count = 1
    prev_ts     = ts[0]

    for t in ts[1:]:
        gap = t - prev_ts
        if gap <= BURST_GAP:
            burst_count += 1
        else:
            bursts.append({
                "start":      burst_start,
                "end":        prev_ts,
                "count":      burst_count,
                "duration_s": round(prev_ts - burst_start, 2),
                "gap_after":  round(gap, 1),
            })
            burst_start = t
            burst_count = 1
        prev_ts = t

    bursts.append({
        "start":      burst_start,
        "end":        prev_ts,
        "count":      burst_count,
        "duration_s": round(prev_ts - burst_start, 2),
        "gap_after":  None,
    })
    return bursts


def _wake_events(bursts: list[dict]) -> list[dict]:
    """
    Identify 'wake' events — bursts preceded by a sleep gap (> SLEEP_GAP seconds).
    The first burst is always a wake event (device appeared).
    """
    events = []
    for i, burst in enumerate(bursts):
        if i == 0:
            events.append({"type": "APPEARED", "ts": burst["start"], "burst_size": burst["count"]})
        elif i > 0:
            prev_gap = burst["start"] - bursts[i-1]["end"]
            if prev_gap >= SLEEP_GAP:
                events.append({
                    "type":       "WAKE",
                    "ts":         burst["start"],
                    "burst_size": burst["count"],
                    "slept_for":  round(prev_gap, 0),
                })
    return events


# ──────────────────────────────────────────────
# ASCII timeline renderer
# ──────────────────────────────────────────────

def _render_ascii_timeline(
    mac:        str,
    events_list: list[tuple[float, str, int | None]],
    width:      int = 60,
):
    """
    Render a single device's probe activity as an ASCII timeline bar.
    Each character represents one time bucket. '█' = active, '·' = silent.
    """
    if not events_list or _first_packet is None:
        return ""

    # Determine total capture duration
    all_ts     = [e[0] for e in events_list]
    t_min      = _first_packet
    t_max      = max(all_ts) + 1

    # If capture is very short, use 30s window minimum
    duration   = max(t_max - t_min, 30.0)
    bucket_s   = duration / width

    buckets    = [0] * width
    for ts, _, _ in events_list:
        idx = min(int((ts - t_min) / bucket_s), width - 1)
        buckets[idx] += 1

    bar = ""
    for count in buckets:
        if count == 0:
            bar += "·"
        elif count <= 2:
            bar += "▒"
        elif count <= 5:
            bar += "▓"
        else:
            bar += "█"

    return bar


# ──────────────────────────────────────────────
# Report
# ──────────────────────────────────────────────

def print_report():
    # Guard against empty capture — avoids division by zero in max() below
    if not _events:
        print("  No probe events captured.")
        return

    elapsed = int(time.time() - _capture_start)

    print(f"\n\n{'═' * 70}")
    print(f"  PROBE TIMELINE REPORT — {len(_events)} devices | {elapsed}s capture")
    print(f"{'═' * 70}\n")

    # Sort by total probes descending
    sorted_devs = sorted(_events.items(), key=lambda x: len(x[1]), reverse=True)

    for mac, ev_list in sorted_devs:
        rnd    = "🎲" if is_randomized(mac) else "  "
        count  = len(ev_list)
        ssids  = sorted(set(s for _, s, _ in ev_list if s))
        ts_list = [e[0] for e in ev_list]
        bursts  = _compute_bursts(ts_list)
        wakes   = _wake_events(bursts)
        bar     = _render_ascii_timeline(mac, ev_list)

        rssi_vals = [r for _, _, r in ev_list if r is not None]
        rssi_str  = f"{sum(rssi_vals)//len(rssi_vals):4d} dBm" if rssi_vals else "   ?"

        first_ts = datetime.fromtimestamp(min(ts_list)).strftime("%H:%M:%S")
        last_ts  = datetime.fromtimestamp(max(ts_list)).strftime("%H:%M:%S")

        print(f"  {rnd} {mask_mac(mac)}  #{count:4d} probes  {rssi_str}  {first_ts}→{last_ts}")
        print(f"     [{bar}]")
        print(f"     Bursts: {len(bursts)}  |  Wake events: {len(wakes)}  |"
              f"  SSIDs: {len(ssids)}")

        for wake in wakes[:4]:   # show first 4 wake events
            ts_fmt = datetime.fromtimestamp(wake["ts"]).strftime("%H:%M:%S")
            slept  = f" (slept {int(wake['slept_for'])}s)" if wake["type"] == "WAKE" else ""
            print(f"       {wake['type']:<10} @ {ts_fmt}  burst={wake['burst_size']}{slept}")

        if ssids:
            print(f"     SSIDs: {', '.join(ssids[:4])}"
                  + (f" +{len(ssids)-4} more" if len(ssids) > 4 else ""))
        print()

    # Timeline legend
    t_min_fmt = datetime.fromtimestamp(_first_packet).strftime("%H:%M:%S") if _first_packet else "?"
    t_max_fmt = datetime.fromtimestamp(
        max(e[0] for evs in _events.values() for e in evs)
    ).strftime("%H:%M:%S") if _events else "?"
    print(f"  Timeline: {t_min_fmt} ──────────────────────────────────── {t_max_fmt}")
    print(f"            · = silent  ▒ = 1-2 probes  ▓ = 3-5  █ = 6+")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Probe timeline visualizer — when did each device wake up, "
            "and what does their scanning pattern look like?"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Works live (--iface) or from a saved capture (--pcap).\n\n"
            "Tip: run for at least 15 minutes for meaningful wake/sleep data.\n"
            "     30 minutes reveals arrival/departure patterns in a room."
        ),
    )
    # --iface is optional here (can use --pcap instead), so add manually
    parser.add_argument("--iface", default=None,
                        help="Monitor-mode interface (live capture). "
                             "Run 01_setup/02_setup_monitor.py start <iface> first.")
    parser.add_argument("--pcap",     default=None, help="Replay from existing pcap file")
    add_output_arg(parser)
    add_duration_arg(parser)
    args = parser.parse_args()

    if not args.iface and not args.pcap:
        print("[!] Provide --iface for live capture or --pcap for replay.")
        sys.exit(1)

    print(f"\n=== 06_analysis/02_probe_timeline.py ===")
    print(f"    Mode      : PASSIVE — sending NO frames")
    print(f"    BURST_GAP : {BURST_GAP}s (probes within this = one burst)")
    print(f"    SLEEP_GAP : {SLEEP_GAP}s (gap longer than this = device slept)")
    print("    Ctrl-C to stop.\n")

    def on_sigint(sig, frame):
        print_report()
        if args.output and _events:
            out = []
            for mac, ev_list in _events.items():
                ts_list = [e[0] for e in ev_list]
                bursts  = _compute_bursts(ts_list)
                wakes   = _wake_events(bursts)
                ssids   = sorted(set(s for _, s, _ in ev_list if s))
                rssi_vals = [r for _, _, r in ev_list if r is not None]
                out.append({
                    "mac_masked":  mask_mac(mac),
                    "randomized":  is_randomized(mac),
                    "probe_count": len(ev_list),
                    "burst_count": len(bursts),
                    "wake_events": len(wakes),
                    "ssids":       ssids,
                    "rssi_avg":    round(sum(rssi_vals)/len(rssi_vals), 1) if rssi_vals else None,
                    "first_seen":  datetime.fromtimestamp(min(ts_list)).isoformat(timespec="seconds"),
                    "last_seen":   datetime.fromtimestamp(max(ts_list)).isoformat(timespec="seconds"),
                    "bursts":      bursts[:20],  # cap to avoid huge files
                })
            safe_write_json({
                "captured_at": datetime.now().isoformat(timespec="seconds"),
                "total":       len(_events),
                "devices":     out,
            }, args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    if args.pcap:
        # Replay mode — read the pcap and process at full speed
        print(f"[*] Reading {args.pcap} ...")
        try:
            packets = rdpcap(args.pcap)
        except Exception as e:
            print(f"[!] Could not read pcap file '{args.pcap}': {e}")
            sys.exit(1)
        for pkt in packets:
            handle_packet(pkt)
        print_report()
        if args.output and _events:
            out = []
            for mac, ev_list in _events.items():
                ts_list = [e[0] for e in ev_list]
                bursts  = _compute_bursts(ts_list)
                wakes   = _wake_events(bursts)
                ssids   = sorted(set(s for _, s, _ in ev_list if s))
                rssi_vals = [r for _, _, r in ev_list if r is not None]
                out.append({
                    "mac_masked":  mask_mac(mac),
                    "randomized":  is_randomized(mac),
                    "probe_count": len(ev_list),
                    "burst_count": len(bursts),
                    "wake_events": len(wakes),
                    "ssids":       ssids,
                    "rssi_avg":    round(sum(rssi_vals)/len(rssi_vals), 1) if rssi_vals else None,
                    "first_seen":  datetime.fromtimestamp(min(ts_list)).isoformat(timespec="seconds"),
                    "last_seen":   datetime.fromtimestamp(max(ts_list)).isoformat(timespec="seconds"),
                    "bursts":      bursts[:20],  # cap to avoid huge files
                })
            safe_write_json({
                "captured_at": datetime.now().isoformat(timespec="seconds"),
                "total":       len(_events),
                "devices":     out,
            }, args.output)

    else:
        require_root()
        require_monitor_mode(args.iface)

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
        if args.output and _events:
            out = []
            for mac, ev_list in _events.items():
                ts_list = [e[0] for e in ev_list]
                bursts  = _compute_bursts(ts_list)
                wakes   = _wake_events(bursts)
                ssids   = sorted(set(s for _, s, _ in ev_list if s))
                rssi_vals = [r for _, _, r in ev_list if r is not None]
                out.append({
                    "mac_masked":  mask_mac(mac),
                    "randomized":  is_randomized(mac),
                    "probe_count": len(ev_list),
                    "burst_count": len(bursts),
                    "wake_events": len(wakes),
                    "ssids":       ssids,
                    "rssi_avg":    round(sum(rssi_vals)/len(rssi_vals), 1) if rssi_vals else None,
                    "first_seen":  datetime.fromtimestamp(min(ts_list)).isoformat(timespec="seconds"),
                    "last_seen":   datetime.fromtimestamp(max(ts_list)).isoformat(timespec="seconds"),
                    "bursts":      bursts[:20],  # cap to avoid huge files
                })
            safe_write_json({
                "captured_at": datetime.now().isoformat(timespec="seconds"),
                "total":       len(_events),
                "devices":     out,
            }, args.output)


if __name__ == "__main__":
    main()
