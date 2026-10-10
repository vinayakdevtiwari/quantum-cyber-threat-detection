"""
network.py

Work out which address phones should actually use to reach this machine.

WHY THIS NEEDS CARE
-------------------
A demo laptop is often connected several ways at once: Ethernet to the venue
router, Wi-Fi to the venue router, and a Mobile Hotspot that the phones join.
Those are different interfaces with different addresses, and they are NOT
interchangeable.

The trap: a phone attached to the Windows hotspot has an address in the
192.168.137.x range and can only reach the hotspot adapter (192.168.137.1).
If the server advertises the Ethernet address instead, the phone times out --
with no error message pointing at the real cause.

So this module enumerates every usable IPv4 address, marks which one belongs
to a hotspot, and returns the one that phones will actually reach. When more
than one candidate exists it returns all of them rather than guessing, because
a wrong guess costs demo time and a list costs nothing to try.
"""

import socket
import subprocess
import sys

# Windows Mobile Hotspot always uses this range for its adapter, which makes
# it reliably identifiable without querying the hotspot API.
HOTSPOT_PREFIX = "192.168.137."

# Interfaces that are never useful to a phone on another device.
_SKIP_PREFIXES = ("127.", "169.254.", "0.")


def _addresses_via_system():
    """Enumerate IPv4 addresses using the OS, with interface names."""
    entries = []

    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetIPAddress -AddressFamily IPv4 | "
                 "Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=20)
            import json
            data = json.loads(out.stdout or "[]")
            if isinstance(data, dict):
                data = [data]
            for item in data:
                alias = str(item.get("InterfaceAlias", ""))
                ip = str(item.get("IPAddress", ""))
                if ip:
                    entries.append((ip, alias))
        except Exception:
            pass

    if not entries:
        # Fallback: hostname resolution, which at least gets one address.
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if ip:
                entries.append((ip, "host"))
        except Exception:
            pass

    return entries


def candidate_addresses():
    """
    Return [(ip, interface_alias), ...] for every address phones could use.

    Ordered so the hotspot address comes first when present, because a phone
    attached to THIS machine's hotspot can only reach this machine's hotspot
    interface.
    """
    entries = [e for e in _addresses_via_system() if not e[0].startswith(_SKIP_PREFIXES)]

    # De-duplicate by IP while preserving order.
    seen, unique = set(), []
    for ip, alias in entries:
        if ip not in seen:
            seen.add(ip)
            unique.append((ip, alias))

    hotspot = [e for e in unique if e[0].startswith(HOTSPOT_PREFIX)]
    other = [e for e in unique if not e[0].startswith(HOTSPOT_PREFIX)]

    # Hotspot first, then everything else. An address like 192.168.1.x on a
    # venue router is still usable IF the phone is on that router, so it stays
    # in the list rather than being discarded.
    return hotspot + other


def primary_address():
    """Best single guess, for compatibility with the existing signature."""
    candidates = candidate_addresses()
    return candidates[0][0] if candidates else "127.0.0.1"


def describe(port=5000):
    """Human-readable summary of what to open on which device."""
    candidates = candidate_addresses()
    lines = []

    for ip, alias in candidates:
        tag = ""
        if ip.startswith(HOTSPOT_PREFIX):
            tag = "  <- use this if phones joined THIS laptop's hotspot"
        elif "Loopback" in alias or "loopback" in alias.lower():
            continue
        lines.append(f"  http://{ip}:{port}{tag}")

    return "\n".join(lines) if lines else "  (no usable IPv4 address found)"


if __name__ == "__main__":
    print("=" * 66)
    print(" ADDRESSES PHONES CAN REACH")
    print("=" * 66)
    for ip, alias in candidate_addresses():
        marker = " [HOTSPOT]" if ip.startswith(HOTSPOT_PREFIX) else ""
        print("  %-16s %s%s" % (ip, alias, marker))
    print()
    print(describe())