from __future__ import annotations
from typing import Optional


def lookup_mac(ip: str) -> Optional[str]:
    """
    Devuelve la MAC asociada a una IP leyendo /proc/net/arp.
    Si no existe entrada para esa IP, devuelve None.
    """
    try:
        with open("/proc/net/arp", "r", encoding="ascii") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue

                ip_addr = parts[0]
                flags = parts[2]
                mac = parts[3]

                # flags == 0x2 -> entrada completa/resuelta
                if ip_addr == ip and flags == "0x2" and mac != "00:00:00:00:00:00":
                    return mac.lower()

    except OSError:
        # /proc/net/arp no disponible, container raro, etc.
        return None

    return None
