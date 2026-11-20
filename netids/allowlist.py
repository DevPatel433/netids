"""IP allowlist that accepts single addresses and CIDR ranges (IPv4 and IPv6).

Entries are validated when the allowlist is built, so a typo in the config
fails at startup instead of silently allowing or blocking the wrong traffic.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class Allowlist:
    def __init__(self, entries: Iterable[str] = ()) -> None:
        self._networks: List[IPNetwork] = [
            ipaddress.ip_network(entry, strict=False) for entry in entries
        ]

    def __contains__(self, ip: object) -> bool:
        try:
            address = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        return any(address in network for network in self._networks)

    def __len__(self) -> int:
        return len(self._networks)
