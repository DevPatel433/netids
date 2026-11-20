"""Live packet capture with scapy.

Emits two kinds of events:
  * pure SYN  (SYN set, ACK clear): start of a connection attempt
  * pure ACK  (ACK set, SYN clear): completes handshakes and carries data

Requires root or CAP_NET_RAW.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from scapy.all import IP, TCP, sniff  # type: ignore[import-not-found]

from .detector import AckEvent, SynEvent

log = logging.getLogger(__name__)

TCP_SYN = 0x02
TCP_ACK = 0x10


def run_capture(
    iface: str,
    bpf_filter: str,
    on_syn: Callable[[SynEvent], None],
    on_ack: Callable[[AckEvent], None],
) -> None:
    def handle(pkt) -> None:
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return
            ip, tcp = pkt[IP], pkt[TCP]
            flags = int(tcp.flags)
            now = time.time()
            if (flags & TCP_SYN) and not (flags & TCP_ACK):
                on_syn(SynEvent(src=ip.src, dst=ip.dst, dst_port=int(tcp.dport), timestamp=now))
            elif (flags & TCP_ACK) and not (flags & TCP_SYN):
                on_ack(AckEvent(src=ip.src, dst=ip.dst, dst_port=int(tcp.dport), timestamp=now))
        except Exception:  # one malformed packet must not stop the sensor
            log.exception("failed to process packet")

    sniff(iface=iface, filter=bpf_filter, prn=handle, store=False)
