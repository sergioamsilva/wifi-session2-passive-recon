#!/usr/bin/env python3
"""
01_setup/01_preflight_check.py — Verify that your machine is ready for class
                         before the professor starts and you look silly.

Checks: root access, wireless interfaces, Python dependencies,
        system tools, and kernel modules. Prints a clear PASS/FAIL
        for each item so you know exactly what to fix.

Run this at the start of every session. It takes 3 seconds.
Troubleshooting without it takes 20 minutes. Your choice.

Usage:
    sudo python3 01_setup/01_preflight_check.py
    sudo python3 01_setup/01_preflight_check.py --fix   # attempt auto-fix where possible

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — All Sessions
"""

import argparse
import importlib
import os
import shutil
import subprocess
import sys

# --- make wifi_utils (repo root) importable from any topic subfolder ---
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_utils import list_interfaces, check_monitor_mode

# ──────────────────────────────────────────────
# Result tracking
# ──────────────────────────────────────────────

_results: list[tuple[str, bool, str]] = []  # (label, passed, note)


def check(label: str, passed: bool, note: str = ""):
    """Record a check result and print it immediately."""
    icon  = "✓" if passed else "✗"
    color = "\033[92m" if passed else "\033[91m"  # green / red
    reset = "\033[0m"
    note_str = f"  ← {note}" if note else ""
    print(f"  [{color}{icon}{reset}] {label}{note_str}")
    _results.append((label, passed, note))


# ──────────────────────────────────────────────
# Individual checks
# ──────────────────────────────────────────────

def check_root():
    check("Running as root", os.geteuid() == 0,
          "run with: sudo python3 01_setup/01_preflight_check.py" if os.geteuid() != 0 else "")


def check_python_version():
    major, minor = sys.version_info[:2]
    ok = (major, minor) >= (3, 10)
    check(f"Python ≥ 3.10", ok,
          f"you have {major}.{minor} — upgrade or the type hints will scream at you" if not ok else f"{major}.{minor}")


def check_python_package(pkg: str, import_name: str | None = None):
    name = import_name or pkg
    try:
        importlib.import_module(name)
        check(f"Python: {pkg}", True)
    except ImportError:
        check(f"Python: {pkg}", False, f"pip install {pkg}")


def check_binary(binary: str, package: str | None = None, note: str = ""):
    found = shutil.which(binary) is not None
    install_hint = f"apt install {package or binary}" if not found else ""
    check(f"Tool: {binary}", found, note or install_hint)


def check_wireless_interfaces():
    """List wireless interfaces using wifi_utils.list_interfaces() and check at least one exists."""
    interfaces_info = list_interfaces()
    interface_names = [iface["name"] for iface in interfaces_info]
    if interface_names:
        check(f"Wireless interfaces", True, ", ".join(interface_names))
    else:
        check("Wireless interfaces", False, "plug in your Wi-Fi adapter")
    return interface_names


def check_monitor_mode_support(interfaces: list[str]):
    """
    Check if any interface supports monitor mode using wifi_utils.check_monitor_mode().
    Tests each interface directly — no iw phy gymnastics required.
    """
    if not interfaces:
        check("Monitor mode support", False, "no interfaces to check")
        return

    # Also check iw list for hardware capability (even if not currently in monitor mode)
    iw_list = subprocess.run(["iw", "list"], capture_output=True, text=True)
    hw_supports_monitor = "monitor" in iw_list.stdout.lower()

    # Check whether any interface is currently in monitor mode
    currently_monitor = [iface for iface in interfaces if check_monitor_mode(iface)]

    if currently_monitor:
        check("Monitor mode support", True,
              f"active monitor interface(s): {', '.join(currently_monitor)}")
    elif hw_supports_monitor:
        check("Monitor mode support", True,
              "hardware supports it — run 01_setup/02_setup_monitor.py start <iface> to enable")
    else:
        check("Monitor mode support", False,
              "check: iw list | grep -A8 'Supported interface modes'")


def check_kernel_module(module: str):
    result = subprocess.run(["lsmod"], capture_output=True, text=True)
    loaded = module.lower() in result.stdout.lower()
    check(f"Kernel module: {module}", loaded,
          f"try: sudo modprobe {module}" if not loaded else "loaded")


def check_usb_adapters():
    """Sniff for known Wi-Fi adapter USB IDs."""
    known = {
        "0bda:8812": "Realtek RTL8812AU (Alfa AWUS036ACH)",
        "0bda:8814": "Realtek RTL8814AU (Alfa AWUS1900)",
        "148f:7612": "MediaTek MT7612U (Alfa AWUS036ACM)",
        "0cf3:9271": "Atheros AR9271 (Alfa AWUS036NHA)",
        "0bda:b812": "Realtek RTL8812BU",
    }
    result = subprocess.run(["lsusb"], capture_output=True, text=True)
    found_any = False
    for vid_pid, name in known.items():
        if vid_pid in result.stdout:
            check(f"USB adapter: {name}", True, vid_pid)
            found_any = True
    if not found_any:
        check("USB Wi-Fi adapter", False,
              "none of the known adapters detected — check lsusb output manually")


def check_file_exists(path: str, label: str):
    check(label, os.path.exists(path), f"not found at {path}" if not os.path.exists(path) else path)


# ──────────────────────────────────────────────
# Auto-fix (best-effort)
# ──────────────────────────────────────────────

def try_fix(fix_scapy: bool = False):
    print("\n[*] Attempting auto-fix for common issues ...\n")

    if fix_scapy:
        print("  $ pip install scapy")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "scapy"], check=False)
        except Exception as e:
            print(f"  [!] pip install scapy failed: {e}")

    # Best-effort system package installs — may require sudo, may not have apt
    for pkg in ["aircrack-ng", "hcxtools", "hashcat"]:
        print(f"  $ apt install -y {pkg}")
        try:
            subprocess.run(
                ["apt", "install", "-y", pkg],
                check=False,
                capture_output=True,  # suppress apt noise; failures are non-fatal
            )
        except Exception as e:
            print(f"  [!] apt install {pkg} failed: {e}")


# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

def print_summary():
    passed = sum(1 for _, ok, _ in _results if ok)
    total  = len(_results)
    failed = [label for label, ok, _ in _results if not ok]

    print(f"\n{'═' * 55}")
    print(f"  RESULT: {passed}/{total} checks passed")
    print(f"{'═' * 55}")

    if not failed:
        print("  ✓ All good. You're ready. Go break things (ethically).")
    else:
        print(f"  ✗ Failed checks:")
        for label in failed:
            print(f"      • {label}")
        print()
        print("  Fix the above and re-run this script.")
        print("  If something still fails, it's probably the USB cable.")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Pre-flight check — know before class what's broken.",
    )
    parser.add_argument("--fix", action="store_true",
                        help="Attempt to auto-fix missing Python packages and system tools")
    args = parser.parse_args()

    print(f"\n=== 01_setup/01_preflight_check.py — CYBERS3C Wi-Fi Module ===\n")

    # ── System ──
    print("[*] System")
    check_root()
    check_python_version()

    # ── Python packages ──
    print("\n[*] Python packages")
    check_python_package("scapy")
    check_python_package("json")    # stdlib, always passes
    check_python_package("struct")  # stdlib

    # ── System tools ──
    print("\n[*] System tools")
    check_binary("iw",          note="core wireless tool")
    check_binary("ip",          note="interface management")
    check_binary("aircrack-ng", "aircrack-ng")
    check_binary("airodump-ng", "aircrack-ng")
    check_binary("airmon-ng",   "aircrack-ng")
    check_binary("hcxpcapngtool", "hcxtools",
                 note="needed for hashcat .22000 conversion")
    check_binary("hashcat",     note="needed for Session 3")
    check_binary("wireshark",   note="optional but highly recommended")
    check_binary("tshark",      "wireshark", note="CLI wireshark")
    check_binary("hostapd",     note="needed for Session 3 evil twin")
    check_binary("dnsmasq",     note="needed for Session 3 DHCP")

    # ── Hardware ──
    print("\n[*] Hardware")
    check_usb_adapters()
    ifaces = check_wireless_interfaces()
    check_monitor_mode_support(ifaces)

    # ── Useful files ──
    print("\n[*] Reference files")
    check_file_exists("/usr/share/wireshark/manuf",
                      "Wireshark OUI database")
    check_file_exists("/usr/share/wordlists/rockyou.txt",
                      "rockyou.txt wordlist (Session 3)")

    # ── Our own scripts ──
    print("\n[*] Session scripts")
    for script in [
        "wifi_utils.py",
        "01_setup/01_preflight_check.py",
        "01_setup/02_setup_monitor.py",
        "01_setup/03_channel_hopper.py",
        "02_recon/04_probe_analyzer.py",
        "03_capture/01_handshake_catcher.py",
        "02_recon/05_ap_scanner.py",
        "02_recon/06_hidden_ssid_hunter.py",
        "02_recon/07_beacon_fingerprint.py",
        "04_attacks/03_deauth.py",
        "04_attacks/04_pmkid_extractor.py",
        "04_attacks/05_evil_twin.py",
        "05_defense/01_wids_sensor.py",
        "05_defense/02_wps_scanner.py",
        "13_client_tracker.py",
        "14_rogue_ap_detector.py",
        "06_analysis/03_pnl_correlator.py",
        "06_analysis/04_wigle_enricher.py",
        "17_report_generator.py",
    ]:
        check_file_exists(script, script)

    if args.fix:
        scapy_ok = any(label == "Python: scapy" and ok for label, ok, _ in _results)
        try_fix(fix_scapy=not scapy_ok)

    print_summary()


if __name__ == "__main__":
    main()
