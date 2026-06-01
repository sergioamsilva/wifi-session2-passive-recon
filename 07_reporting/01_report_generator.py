#!/usr/bin/env python3
"""
07_reporting/01_report_generator.py — Merge the suite's JSON outputs into one Markdown report.

Every capture script in this suite can write JSON (--output something.json).
After a session you end up with a pile of them: beacons, probes, fingerprints,
PMKIDs. This script reads that pile and produces a single readable Markdown
report — the kind of thing a student hands in or a pentester pastes into a
findings doc.

It understands the suite's known shapes (e.g. 07's fingerprint files) and falls
back to a generic tabulation for anything else, so it won't choke on a file it
hasn't seen before.

No root, no scapy, no network — it just reads files.

Usage:
    python3 07_reporting/01_report_generator.py room.json fingerprints.json --output report.md
    python3 07_reporting/01_report_generator.py ./captures/                  # scan a directory
    python3 07_reporting/01_report_generator.py *.json                       # stdout if no --output

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module
"""

import argparse
import glob
import json
import os
import sys


def _load(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        print(f"[!] Skipping {path}: {e}", file=sys.stderr)
        return None


def _first_list(data: dict):
    """Return (key, list) for the first top-level list-of-dicts, else (None, None)."""
    if not isinstance(data, dict):
        return None, None
    for k, v in data.items():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return k, v
    return None, None


def _table(rows: list[dict], columns: list[str], limit: int = 50) -> list[str]:
    """Render a Markdown table from a list of dicts, given preferred columns."""
    present = [c for c in columns if any(c in r for r in rows)]
    if not present:
        present = list(rows[0].keys())[:6]
    out = ["| " + " | ".join(present) + " |",
           "|" + "|".join("---" for _ in present) + "|"]
    for r in rows[:limit]:
        cells = []
        for c in present:
            val = r.get(c, "")
            if isinstance(val, (list, dict)):
                val = ", ".join(map(str, val)) if isinstance(val, list) else "…"
            cells.append(str(val).replace("|", "\\|"))
        out.append("| " + " | ".join(cells) + " |")
    if len(rows) > limit:
        out.append(f"\n_…and {len(rows) - limit} more (showing first {limit})._")
    return out


def render_file(path: str, data) -> list[str]:
    name = os.path.basename(path)
    md = [f"## `{name}`", ""]

    if not isinstance(data, dict):
        md.append("```json")
        md.append(json.dumps(data, indent=2, ensure_ascii=False)[:2000])
        md.append("```")
        return md + [""]

    # Top-level scalar metadata first.
    meta = {k: v for k, v in data.items() if not isinstance(v, (list, dict))}
    if meta:
        for k, v in meta.items():
            md.append(f"- **{k}**: {v}")
        md.append("")

    key, rows = _first_list(data)
    if not rows:
        md.append("_No tabular records found._\n")
        return md

    md.append(f"**{len(rows)} {key}**")
    md.append("")

    # Known shape: 07 fingerprints → curated columns.
    if key == "fingerprints":
        md += _table(rows, ["ssid", "bssid", "channel", "wifi_gen", "rssi_dbm"])
        wps = [r for r in rows if r.get("wps")]
        openish = [r for r in rows if not r.get("rsn") and not r.get("has_wpa1")]
        md.append("")
        md.append(f"- WPS-enabled APs: **{len(wps)}**")
        md.append(f"- Open / WEP APs: **{len(openish)}**")
    else:
        # Generic: prefer common keys if present, else whatever's there.
        md += _table(rows, ["ssid", "bssid", "mac", "client", "channel",
                             "vendor", "label", "pmf", "count", "rssi_dbm"])
    return md + [""]


def main():
    parser = argparse.ArgumentParser(
        description="Merge capture JSON files into one Markdown report.",
    )
    parser.add_argument("paths", nargs="+",
                        help="JSON files, globs, or directories to include.")
    parser.add_argument("--output", default=None,
                        help="Write Markdown here (default: stdout).")
    parser.add_argument("--title", default="Wi-Fi Reconnaissance Report")
    args = parser.parse_args()

    # Expand directories and globs into a flat file list.
    files: list[str] = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "*.json")))
        else:
            files += sorted(glob.glob(p)) or ([p] if os.path.isfile(p) else [])
    files = [f for f in dict.fromkeys(files) if f.endswith(".json")]

    if not files:
        print("[!] No JSON files found in the given paths.")
        sys.exit(1)

    md = [f"# {args.title}", "",
          f"_Generated from {len(files)} capture file(s)._", "",
          "## Files included", ""]
    md += [f"- `{os.path.basename(f)}`" for f in files]
    md.append("")

    for f in files:
        data = _load(f)
        if data is not None:
            md += render_file(f, data)

    report = "\n".join(md) + "\n"

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as e:
            print(f"[!] Could not write {args.output}: {e}")
            sys.exit(1)
        print(f"[+] Report written → {args.output}  ({len(files)} files)")
    else:
        print(report)


if __name__ == "__main__":
    main()
