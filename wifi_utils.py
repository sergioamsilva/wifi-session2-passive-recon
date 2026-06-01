"""
wifi_utils.py — Shared utilities for the CYBERS3C Wi-Fi script suite.

Every function here was duplicated across 7-10 scripts. Now it lives in
one place, which means bugs get fixed once and everyone benefits.

Import what you need:
    from wifi_utils import get_ssid, require_monitor_mode, safe_write_json, ...

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Iterator

# ── Scapy import (optional for non-capture scripts) ──────────────────────────
try:
    from scapy.all import Dot11Elt, RadioTap
    _SCAPY = True
except ImportError:
    _SCAPY = False


# ─────────────────────────────────────────────────────────────────────────────
# MAC address utilities
# ─────────────────────────────────────────────────────────────────────────────

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


def validate_mac(mac: str) -> str:
    """
    Validate and normalise a MAC address string.
    Returns the lowercase colon-separated form.
    Raises ValueError with a clear message on invalid input.
    """
    if not mac:
        raise ValueError("MAC address is empty.")
    normalised = mac.strip().lower().replace("-", ":").replace(".", ":")
    if not _MAC_RE.match(normalised):
        raise ValueError(
            f"Invalid MAC address: '{mac}'. Expected format: AA:BB:CC:DD:EE:FF"
        )
    return normalised


def is_randomized(mac: str) -> bool:
    """
    Return True if the MAC uses a locally administered (randomised) address.
    The locally administered bit is bit 1 of the first octet.
    """
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def mask_mac(mac: str) -> str:
    """
    Mask the last 3 octets for privacy in output and logs.
    AA:BB:CC:DD:EE:FF → AA:BB:CC:**:**:**
    """
    parts = mac.split(":")
    if len(parts) != 6:
        return mac
    return ":".join(parts[:3] + ["**", "**", "**"])


def format_mac_plain(mac: str) -> str:
    """Remove colons — used for hashcat input format."""
    return mac.replace(":", "")


# ─────────────────────────────────────────────────────────────────────────────
# 802.11 packet parsing
# ─────────────────────────────────────────────────────────────────────────────

def walk_ies(pkt) -> Iterator[tuple[int, bytes]]:
    """
    Safely iterate over all Information Elements in a Dot11 frame.
    Yields (tag_id, tag_data) pairs.
    Stops at the first non-Dot11Elt payload to avoid infinite loops on
    malformed frames. Safe even if pkt has no IEs at all.
    """
    if not _SCAPY:
        return
    elt = pkt.getlayer(Dot11Elt) if hasattr(pkt, "getlayer") else None
    while elt is not None:
        info = bytes(elt.info) if elt.info is not None else b""
        yield elt.ID, info
        payload = getattr(elt, "payload", None)
        elt = payload if isinstance(payload, Dot11Elt) else None


def get_ssid(pkt) -> str:
    """
    Extract the SSID from a Dot11 frame (IE tag 0).
    Returns an empty string for wildcard probes or hidden APs.
    Never raises — malformed frames return "".
    """
    for tag_id, data in walk_ies(pkt):
        if tag_id == 0:
            try:
                return data.decode("utf-8", errors="replace").strip()
            except Exception:
                return ""
    return ""


def get_rssi(pkt) -> int | None:
    """
    Extract RSSI in dBm from the RadioTap header.
    Returns None if the header is absent or the field is not present.
    """
    if not _SCAPY:
        return None
    if hasattr(pkt, "haslayer") and pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        if hasattr(rt, "dBm_AntSignal"):
            try:
                return int(rt.dBm_AntSignal)
            except (TypeError, ValueError):
                pass
    return None


def get_channel(pkt) -> int | None:
    """
    Extract the current channel from the DS Parameter Set IE (tag 3).
    Returns None if the tag is absent.
    """
    for tag_id, data in walk_ies(pkt):
        if tag_id == 3 and data:
            return data[0]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# OUI / Vendor lookup
# ─────────────────────────────────────────────────────────────────────────────

# Built-in fallback for offline / minimal installs.
# Covers the most common adapters seen in Wi-Fi security training.
_FALLBACK_OUI: dict[str, str] = {
    "3c:22:fb": "Apple",
    "3c:06:30": "Apple",
    "a4:5e:60": "Samsung",
    "dc:a6:32": "Raspberry Pi",
    "f0:18:98": "Apple",
    "b4:5d:50": "Apple",
    "18:65:90": "Apple",
    "00:c0:ca": "Alfa Networks",
    "ec:d0:9f": "Google",
    "04:d6:aa": "Google",
    "40:4e:36": "Intel",
    "a0:c9:a0": "Intel Corp.",
    "5c:ba:37": "Xiaomi",
    "28:6c:07": "Xiaomi",
    "e4:02:9b": "Huawei",
    "94:77:2b": "OnePlus",
    "84:ef:18": "Huawei",
    "00:26:bb": "Apple",
    "d8:bb:c1": "Apple",
    "8c:85:90": "Apple",
    "1c:36:bb": "Apple",
    "68:a8:6d": "Apple",
    "b8:8d:12": "Apple",
    "60:f8:1d": "Apple",
    "e8:d8:d1": "Apple",
}


def load_oui_db(path: str = "/usr/share/wireshark/manuf") -> dict[str, str]:
    """
    Load Wireshark's OUI database (~50k entries).
    Returns an empty dict (and falls back to _FALLBACK_OUI in lookup_vendor)
    if the file is not present — not a crash, just a smaller lookup table.
    """
    db: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                raw_oui = parts[0].replace("-", ":").lower()
                if len(raw_oui) != 8:   # skip 28-bit / 36-bit OUIs
                    continue
                vendor = (parts[2] if len(parts) > 2 else parts[1]).strip()
                db[raw_oui] = vendor
    except FileNotFoundError:
        pass
    return db


def lookup_vendor(mac: str, db: dict[str, str] | None = None) -> str:
    """
    Look up the vendor name for a MAC address.
    Tries `db` first, then the built-in fallback table.
    Returns "Unknown" if not found anywhere.
    """
    oui = mac[:8].lower()
    if db:
        vendor = db.get(oui)
        if vendor:
            return vendor
    return _FALLBACK_OUI.get(oui, "Unknown")


# ─────────────────────────────────────────────────────────────────────────────
# System checks
# ─────────────────────────────────────────────────────────────────────────────

def require_root(script_name: str = "") -> None:
    """
    Exit with a clear error if the process is not running as root.
    Raw socket capture requires kernel privileges — there's no way around this.
    """
    if os.geteuid() != 0:
        name = script_name or os.path.basename(sys.argv[0])
        print("[!] Root required — raw socket capture needs kernel privileges.")
        print(f"    sudo python3 {name} ...")
        sys.exit(1)


def check_monitor_mode(iface: str) -> bool:
    """
    Return True if `iface` is currently in monitor mode.
    Uses `iw dev <iface> info` — accurate and fast.
    """
    result = subprocess.run(
        ["iw", "dev", iface, "info"],
        capture_output=True, text=True,
    )
    return "type monitor" in result.stdout


def require_monitor_mode(iface: str) -> None:
    """
    Exit with a clear error if the interface is not in monitor mode.
    Always call this at the start of any capture script.
    """
    if not check_monitor_mode(iface):
        print(f"[!] '{iface}' is not in monitor mode.")
        print(f"    Fix it first:  sudo python3 01_setup/02_setup_monitor.py start {iface}")
        sys.exit(1)


def list_interfaces() -> list[dict]:
    """
    Return a list of available wireless interfaces with their current mode.
    Each entry: {"name": str, "mode": str, "addr": str}
    """
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    interfaces: list[dict] = []
    current: dict = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            if current:
                interfaces.append(current)
            current = {"name": line.split()[1], "mode": "unknown", "addr": ""}
        elif line.startswith("type") and current:
            current["mode"] = line.split()[1]
        elif line.startswith("addr") and current:
            current["addr"] = line.split()[1]
    if current:
        interfaces.append(current)
    return interfaces


# ─────────────────────────────────────────────────────────────────────────────
# Argparse helpers
# ─────────────────────────────────────────────────────────────────────────────

def add_iface_arg(parser) -> None:
    parser.add_argument(
        "--iface", required=True,
        help="Monitor-mode interface (e.g. wlan1mon). "
             "Run 01_setup/02_setup_monitor.py start <iface> first.",
    )


def add_output_arg(parser, default: str | None = None) -> None:
    help_text = "Save results to this file."
    if default:
        help_text += f" (default: {default})"
    parser.add_argument("--output", default=default, help=help_text)


def add_duration_arg(parser) -> None:
    parser.add_argument(
        "--duration", type=int, default=0,
        help="Capture duration in seconds. 0 = run until Ctrl-C. (default: 0)",
    )


def add_bssid_arg(parser, required: bool = False) -> None:
    parser.add_argument(
        "--bssid", default=None, required=required,
        metavar="AA:BB:CC:DD:EE:FF",
        help="Target AP BSSID. Must be in AA:BB:CC:DD:EE:FF format.",
    )


def parse_bssid_arg(value: str | None) -> str | None:
    """
    Parse and validate a BSSID argument.
    Returns the normalised lowercase BSSID or None.
    Calls sys.exit(1) with a clear message if the format is wrong.
    """
    if value is None:
        return None
    try:
        return validate_mac(value)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# 802.11 security / RSN parsing
# ─────────────────────────────────────────────────────────────────────────────

# AKM suite selectors (the type byte of a 00-0F-AC suite).
# IEEE 802.11-2020 Table 9-151 + WPA3 additions.
AKM_NAMES: dict[int, str] = {
    1:  "802.1X (Enterprise)",
    2:  "PSK",
    3:  "FT-802.1X",
    4:  "FT-PSK",
    5:  "802.1X-SHA256",
    6:  "PSK-SHA256",
    7:  "TDLS",
    8:  "SAE",
    9:  "FT-SAE",
    11: "802.1X-SuiteB-SHA256",
    12: "802.1X-SuiteB-SHA384",
    13: "FT-802.1X-SHA384",
    18: "OWE",
    24: "SAE-EXT-KEY",
    25: "FT-SAE-EXT-KEY",
}

# Pairwise / group cipher selectors.
CIPHER_NAMES: dict[int, str] = {
    0: "Use-Group", 1: "WEP-40", 2: "TKIP", 4: "CCMP-128",
    5: "WEP-104", 6: "BIP-CMAC-128", 8: "GCMP-128", 9: "GCMP-256",
    10: "CCMP-256", 11: "BIP-GMAC-128", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256",
}

# AKM suite-type numbers grouped by family — used for classification.
_ENTERPRISE_AKMS = {1, 3, 5, 11, 12, 13}
_SAE_AKMS        = {8, 9, 24, 25}
_PSK_AKMS        = {2, 4, 6}
_OWE_AKMS        = {18}


def parse_rsn_ie(data: bytes) -> dict:
    """
    Parse a raw RSN Information Element body (the bytes *after* the tag+len
    of IE 48). Returns version, ciphers, AKM suite numbers + names, PMF flags
    and any PMKIDs. Never raises — a malformed IE returns whatever parsed.
    """
    result = {
        "version": None,
        "group_cipher": None,
        "pairwise_ciphers": [],
        "akms": [],            # raw suite-type numbers
        "akm_names": [],
        "pmf_capable": False,
        "pmf_required": False,
        "pmkids": [],          # list of hex strings
    }
    try:
        pos = 0
        if pos + 2 > len(data):
            return result
        result["version"] = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2

        if pos + 4 > len(data):
            return result
        result["group_cipher"] = CIPHER_NAMES.get(data[pos + 3], f"?({data[pos + 3]})")
        pos += 4

        if pos + 2 > len(data):
            return result
        n = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        for _ in range(n):
            if pos + 4 > len(data):
                break
            result["pairwise_ciphers"].append(
                CIPHER_NAMES.get(data[pos + 3], f"?({data[pos + 3]})"))
            pos += 4

        if pos + 2 > len(data):
            return result
        n = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        for _ in range(n):
            if pos + 4 > len(data):
                break
            suite = data[pos + 3]
            result["akms"].append(suite)
            result["akm_names"].append(AKM_NAMES.get(suite, f"?({suite})"))
            pos += 4

        if pos + 2 > len(data):
            return result
        caps = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        result["pmf_capable"]  = bool(caps & 0x0080)
        result["pmf_required"] = bool(caps & 0x0040)

        if pos + 2 > len(data):
            return result
        pmkid_count = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        for _ in range(pmkid_count):
            if pos + 16 > len(data):
                break
            result["pmkids"].append(data[pos:pos + 16].hex())
            pos += 16
    except Exception:
        pass
    return result


def get_rsn(pkt) -> dict | None:
    """
    Find and parse the RSN IE (tag 48) in a Dot11 frame.
    Returns the parsed dict, or None if the frame carries no RSN IE.
    """
    for tag_id, data in walk_ies(pkt):
        if tag_id == 48:
            return parse_rsn_ie(data)
    return None


def has_wpa1(pkt) -> bool:
    """True if the frame carries a Microsoft WPA1 vendor IE (OUI 00:50:f2, type 1)."""
    for tag_id, data in walk_ies(pkt):
        if (tag_id == 221 and len(data) >= 4
                and data[:3] == b"\x00\x50\xf2" and data[3] == 1):
            return True
    return False


def _has_privacy_bit(pkt) -> bool:
    """Read the Privacy bit (0x0010) from a beacon/probe-response capability field."""
    if not _SCAPY:
        return False
    try:
        from scapy.all import Dot11Beacon, Dot11ProbeResp
        layer = None
        if pkt.haslayer(Dot11Beacon):
            layer = pkt[Dot11Beacon]
        elif pkt.haslayer(Dot11ProbeResp):
            layer = pkt[Dot11ProbeResp]
        if layer is None:
            return False
        return bool(int(layer.cap) & 0x0010)
    except Exception:
        return False


def classify_security(pkt) -> dict:
    """
    Classify an AP's security from its beacon / probe-response frame.

    Returns:
        {
          "label": "WPA3-SAE" | "WPA2/WPA3-Transition" | "WPA2-Enterprise" | ...,
          "akms": [str], "ciphers": [str],
          "pmf": "required" | "capable" | "disabled",
          "transition": bool,   # WPA3 transition mode (SAE + PSK in one RSN IE)
          "enterprise": bool,
          "wpa3": bool,
        }
    """
    base = {"akms": [], "ciphers": [], "pmf": "disabled",
            "transition": False, "enterprise": False, "wpa3": False}

    rsn = get_rsn(pkt)
    if rsn is None:
        if has_wpa1(pkt):
            return {**base, "label": "WPA1"}
        if _has_privacy_bit(pkt):
            return {**base, "label": "WEP"}
        return {**base, "label": "Open"}

    akms = set(rsn["akms"])
    has_sae = bool(akms & _SAE_AKMS)
    has_psk = bool(akms & _PSK_AKMS)
    has_ent = bool(akms & _ENTERPRISE_AKMS)
    has_owe = bool(akms & _OWE_AKMS)

    if rsn["pmf_required"]:
        pmf = "required"
    elif rsn["pmf_capable"]:
        pmf = "capable"
    else:
        pmf = "disabled"

    transition = has_sae and has_psk

    if has_sae and has_psk:
        label = "WPA2/WPA3-Transition"
    elif has_sae:
        label = "WPA3-SAE"
    elif has_owe:
        label = "OWE (Enhanced Open)"
    elif has_ent:
        label = "WPA3-Enterprise" if rsn["pmf_required"] else "WPA2-Enterprise"
    elif has_psk:
        label = "WPA2-PSK"
    else:
        label = "RSN (" + ", ".join(rsn["akm_names"]) + ")"

    wpa3 = has_sae or has_owe or (has_ent and rsn["pmf_required"])

    return {
        "label": label,
        "akms": rsn["akm_names"],
        "ciphers": rsn["pairwise_ciphers"],
        "pmf": pmf,
        "transition": transition,
        "enterprise": has_ent,
        "wpa3": wpa3,
    }


# ─────────────────────────────────────────────────────────────────────────────
# EAPOL / 4-way handshake parsing
# ─────────────────────────────────────────────────────────────────────────────
#
# EAPOL key-frame field offsets (bytes of pkt[EAPOL]):
#   5-6    Key Information (big-endian)
#   17-48  Nonce (ANonce in M1, SNonce in M2)
#   81-96  Key MIC
#   97-98  Key Data Length (big-endian)
#   99..   Key Data (an RSN IE carrying a PMKID may live here, in M1)

def eapol_message_type(raw: bytes) -> int | None:
    """
    Classify an EAPOL key frame as message 1/2/3/4 of the WPA 4-way handshake,
    from its Key Information bits. Returns None if it isn't a recognisable msg.
    """
    if len(raw) < 7:
        return None
    ki = (raw[5] << 8) | raw[6]
    ack     = bool(ki & 0x0080)
    mic     = bool(ki & 0x0100)
    install = bool(ki & 0x0040)
    secure  = bool(ki & 0x0200)
    if ack and not mic and not install and not secure:
        return 1   # M1 (AP → STA, carries ANonce + maybe PMKID)
    if not ack and mic and not install and not secure:
        return 2   # M2 (STA → AP, carries SNonce + MIC)
    if ack and mic and install and secure:
        return 3   # M3
    if not ack and mic and secure:
        return 4   # M4
    return None


def eapol_anonce(raw: bytes) -> bytes:
    """The 32-byte nonce field (ANonce in M1)."""
    return raw[17:49] if len(raw) >= 49 else b""


def eapol_mic(raw: bytes) -> bytes:
    """The 16-byte Key MIC field."""
    return raw[81:97] if len(raw) >= 97 else b""


def eapol_zero_mic(raw: bytes) -> bytes:
    """Return the EAPOL frame with its 16-byte MIC field zeroed — hashcat needs this."""
    if len(raw) < 97:
        return raw
    return raw[:81] + b"\x00" * 16 + raw[97:]


def eapol_pmkid(raw: bytes) -> bytes | None:
    """
    Extract a PMKID (16 bytes) from an M1 frame's Key Data (an RSN IE).
    Returns None if there's no Key Data or no PMKID present.
    """
    if len(raw) < 99:
        return None
    kdl = (raw[97] << 8) | raw[98]
    if kdl == 0 or len(raw) < 99 + kdl:
        return None
    kd = raw[99:99 + kdl]
    pos = 0
    while pos + 2 <= len(kd):
        tag, ln = kd[pos], kd[pos + 1]
        pos += 2
        if pos + ln > len(kd):
            break
        if tag == 0x30:  # RSN IE
            rsn = parse_rsn_ie(kd[pos:pos + ln])
            if rsn["pmkids"]:
                return bytes.fromhex(rsn["pmkids"][0])
        pos += ln
    return None


# ─────────────────────────────────────────────────────────────────────────────
# File I/O
# ─────────────────────────────────────────────────────────────────────────────

def safe_write_json(data: dict, path: str) -> None:
    """
    Write `data` as JSON to `path` — atomically and with permission checks.

    Uses a temporary file in the same directory so the write is atomic
    (rename is atomic on Linux). Fails with a clear message instead of
    a traceback if the directory doesn't exist or isn't writable.
    """
    directory = os.path.dirname(os.path.abspath(path))

    if not os.path.isdir(directory):
        print(f"[!] Output directory does not exist: {directory}")
        sys.exit(1)

    if not os.access(directory, os.W_OK):
        print(f"[!] No write permission for: {directory}")
        print(f"    Try a different --output path, or run with sudo.")
        sys.exit(1)

    try:
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
            os.replace(tmp_path, path)   # atomic on POSIX
        except Exception:
            os.unlink(tmp_path)
            raise
    except OSError as e:
        print(f"[!] Could not write to '{path}': {e}")
        sys.exit(1)

    print(f"[+] Saved → {path}")
