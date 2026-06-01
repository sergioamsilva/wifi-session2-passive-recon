#!/usr/bin/env python3
"""
01_setup/02_setup_monitor.py — Put your Wi-Fi card in monitor mode (or take it back out).

Your adapter was born to passively judge everyone's traffic.
This script gives it that superpower.

Usage:
    sudo python3 01_setup/02_setup_monitor.py start wlan1
    sudo python3 01_setup/02_setup_monitor.py start wlan1 --channel 6
    sudo python3 01_setup/02_setup_monitor.py stop  wlan1

Note: if you run this without sudo and it fails, that's on you.
      The script warned you. Right here. In the docstring.

CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module — Session 2
"""

import argparse
import os
import subprocess
import sys


def run(cmd, check=True, quiet=False):
    """Run a shell command and complain loudly if it breaks."""
    if not quiet:
        print(f"  $ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"  [!] Command failed: {result.stderr.strip() or result.stdout.strip()}")
        sys.exit(1)
    return result


def kill_interfering():
    """
    Murder every process that thinks it owns your wireless card.
    NetworkManager, wpa_supplicant — this is not personal. It's business.
    """
    print("[*] Evicting tenant processes from your wireless interface ...")
    for proc in ["wpa_supplicant", "NetworkManager", "dhclient", "dhcpcd"]:
        subprocess.run(["pkill", "-f", proc], capture_output=True)
    print("    Done. Silence.\n")


def enable_monitor(iface: str, channel: int | None):
    """
    The main event. Transform a boring managed interface into an
    all-seeing, all-hearing, packet-sniffing oracle.
    """
    kill_interfering()

    print(f"[*] Taking {iface} offline for its transformation ...")
    run(["ip", "link", "set", iface, "down"])

    print(f"[*] Whispering 'monitor mode' to the kernel ...")
    run(["iw", "dev", iface, "set", "type", "monitor"])

    print(f"[*] Bringing {iface} back up, reborn ...")
    run(["ip", "link", "set", iface, "up"])

    if channel is not None:
        print(f"[*] Tuning to channel {channel} like it's 1998 and this is a radio ...")
        result = run(["iw", "dev", iface, "set", "channel", str(channel)], check=False)
        if result.returncode != 0:
            print(f"  [!] Channel {channel} refused to cooperate: {result.stderr.strip()}")
            print("      (Some chipsets are shy about channels. The hopper handles it.)")

    print()
    validate(iface)

    print(f"\n[+] Your toolbelt for today:")
    print(f"    sudo python3 01_setup/03_channel_hopper.py --iface {iface} --band 2.4")
    print(f"    sudo python3 02_recon/04_probe_analyzer.py --iface {iface} --output room.json")
    print(f"    sudo python3 03_capture/01_handshake_catcher.py --iface {iface} --output lab.pcap")


def disable_monitor(iface: str):
    """
    Return the card to civilian life.
    It had a good run. Time to reconnect to the coffee shop Wi-Fi.
    """
    print(f"[*] Bringing {iface} down for its walk of shame ...")
    run(["ip", "link", "set", iface, "down"])

    print(f"[*] Restoring {iface} to managed mode (boring again) ...")
    run(["iw", "dev", iface, "set", "type", "managed"])

    print(f"[*] Bringing {iface} back up ...")
    run(["ip", "link", "set", iface, "up"])

    print("[*] Waking up NetworkManager (it missed you) ...")
    subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True)

    print(f"\n[+] {iface} is back in managed mode. Dignity restored.")
    validate(iface)


def validate(iface: str):
    """
    Check our work. Trust, but verify.
    Actually, just verify — trust is for therapists.
    """
    result = run(["iw", "dev", iface, "info"], check=False, quiet=True)
    print("─" * 52)
    print(result.stdout.strip())
    print("─" * 52)

    if "type monitor" in result.stdout:
        print(f"[✓] Monitor mode confirmed. {iface} sees everything now.")
    elif "type managed" in result.stdout:
        print(f"[✓] Managed mode confirmed. Back to normal human behaviour.")
    else:
        print(f"[!] Mode unclear. Run:  iw dev {iface} info  and read carefully.")


def check_root():
    """Diplomatically enforce the 'run as root' contract."""
    if os.geteuid() != 0:
        print("[!] Root required. You wouldn't install a car engine without a lift.")
        print(f"    sudo python3 {sys.argv[0]} ...")
        sys.exit(1)


def check_interface(iface: str) -> str:
    """
    Make sure the interface actually exists before we try to boss it around.
    Also handles the airmon-ng renaming trap: if 'wlan0' doesn't exist but
    'wlan0mon' does, we suggest (and use) the renamed interface automatically.
    Returns the actual interface name to use (may differ from the one requested).
    """
    result = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True)
    if result.returncode == 0:
        return iface  # found exactly what was asked for

    # airmon-ng appends 'mon' — check for that variant
    mon_iface = iface + "mon"
    mon_result = subprocess.run(["iw", "dev", mon_iface, "info"], capture_output=True, text=True)
    if mon_result.returncode == 0:
        print(f"[!] '{iface}' not found, but '{mon_iface}' exists.")
        print(f"    Looks like airmon-ng already renamed it.")

        if "type monitor" in mon_result.stdout:
            print(f"    It's already in monitor mode. Using '{mon_iface}'.\n")
            return mon_iface
        else:
            print(f"    Using '{mon_iface}' instead.\n")
            return mon_iface

    # Nothing found — list what's actually available
    print(f"[!] Interface '{iface}' not found. Did you plug the adapter in?")
    print("    Available interfaces:")
    out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    # Extract just the interface names for a cleaner message
    ifaces_found = [
        line.strip().split()[1]
        for line in out.splitlines()
        if line.strip().startswith("Interface")
    ]
    if ifaces_found:
        for name in ifaces_found:
            info = subprocess.run(["iw", "dev", name, "info"], capture_output=True, text=True).stdout
            mode = "monitor" if "type monitor" in info else "managed"
            print(f"      {name}  ({mode})")
        print(f"\n    Try:  sudo python3 01_setup/02_setup_monitor.py start {ifaces_found[0]}")
    else:
        for line in out.splitlines():
            print(f"    {line}")
    sys.exit(1)


def main():
    check_root()

    parser = argparse.ArgumentParser(
        description="Enable / disable Wi-Fi monitor mode — no drama, just packets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 01_setup/02_setup_monitor.py start wlan1 --channel 6\n"
            "  sudo python3 01_setup/02_setup_monitor.py stop  wlan1\n\n"
            "If it still doesn't work after this, check dmesg. Or the USB cable.\n"
            "It's almost always the USB cable."
        ),
    )
    parser.add_argument("action", choices=["start", "stop"],
                        help="'start' = go full spy mode; 'stop' = go home")
    parser.add_argument("iface", help="Wireless interface (e.g. wlan1, wlan0)")
    parser.add_argument("--channel", type=int, default=None, metavar="N",
                        help="Channel to park on after enabling monitor mode")
    args = parser.parse_args()

    iface = check_interface(args.iface)

    print(f"\n=== 01_setup/02_setup_monitor.py | action={args.action} | iface={iface} ===\n")

    if args.action == "start":
        enable_monitor(iface, args.channel)
    else:
        disable_monitor(iface)


if __name__ == "__main__":
    main()
