#!/usr/bin/env python3
"""
tools/check_capture.py — List available network interfaces via Scapy.

Purpose:  Confirm that Npcap is installed and Scapy can see interfaces.
Behaviour: READ-ONLY — lists interfaces, does NOT open or capture on any.

╔══════════════════════════════════════════════════════════════════╗
║  ⚠️  This script must NEVER send any data out.                  ║
║  It only reads the local interface list. No sniff, no send.     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys


def list_interfaces() -> list[dict]:
    """Return a list of dicts describing each Windows network interface.

    Each dict contains keys like 'name', 'description', 'ips', etc.,
    as provided by Scapy's get_windows_if_list().

    Returns an empty list if Scapy cannot enumerate interfaces.
    """
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore
    except ImportError:
        print(
            "ERROR: Could not import scapy.arch.windows.\n"
            "       Make sure Scapy is installed (`pip install scapy`)\n"
            "       and you are running on Windows with Npcap installed.",
            file=sys.stderr,
        )
        return []

    interfaces = get_windows_if_list()
    return interfaces


def print_interfaces(interfaces: list[dict]) -> None:
    """Pretty-print the interface list to stdout."""
    if not interfaces:
        print("No interfaces found. Is Npcap installed?")
        return

    print(f"\n{'='*70}")
    print(f" Found {len(interfaces)} network interface(s)")
    print(f"{'='*70}\n")

    for idx, iface in enumerate(interfaces, start=1):
        name = iface.get("name", "N/A")
        description = iface.get("description", "N/A")
        ips = iface.get("ips", [])
        mac = iface.get("mac", "N/A")

        print(f"  [{idx}] {description}")
        print(f"      Name : {name}")
        print(f"      MAC  : {mac}")
        print(f"      IPs  : {', '.join(str(ip) for ip in ips) if ips else 'None'}")
        print()

    print(f"{'='*70}")
    print(" ✅ Npcap + Scapy are working correctly.")
    print(f"{'='*70}\n")


def main() -> None:
    """Entry point: list interfaces and print them."""
    interfaces = list_interfaces()
    print_interfaces(interfaces)


if __name__ == "__main__":
    main()
