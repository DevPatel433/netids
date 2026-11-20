"""Detection logic for TCP SYN-based attacks.

Three detectors share one sliding-window model:

* port_scan:   one source touches many distinct destination ports.
* brute_force: one source repeatedly hits the same watched service port.
* syn_flood:   one destination:port receives many SYNs while very few
               handshakes complete (low ACK ratio). Flood sources are usually
               spoofed, so these alerts are logged but never blocked.

The module has no scapy dependency, so it can be tested without root or
live traffic.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, List, Tuple

from .allowlist import Allowlist


@dataclass(frozen=True)
class SynEvent:
    """A pure TCP SYN (connection attempt) seen on the wire."""

    src: str
    dst: str
    dst_port: int
    timestamp: float


@dataclass(frozen=True)
class AckEvent:
    """A pure TCP ACK, which usually completes a handshake or carries data."""

    src: str
    dst: str
    dst_port: int
    timestamp: float


@dataclass(frozen=True)
class Alert:
    kind: str  # "port_scan", "brute_force", or "syn_flood"
    src: str  # offending source, or the target address for floods
    detail: str
    timestamp: float
    blockable: bool = True


Target = Tuple[str, int]


def _trim_times(times: Deque[float], now: float, window: float) -> None:
    cutoff = now - window
    while times and times[0] < cutoff:
        times.popleft()


class Detector:
    """Raises alerts on suspicious connection-attempt patterns.

    Each alert is rate-limited by `cooldown_seconds`, keyed on the alert kind
    plus its subject, so one long scan produces one alert rather than
    thousands.
    """

    def __init__(
        self,
        *,
        window_seconds: float = 60.0,
        port_scan_unique_ports: int = 20,
        brute_force_attempts: int = 10,
        watched_ports: Iterable[int] = (21, 22, 23, 3306, 3389),
        cooldown_seconds: float = 300.0,
        whitelist: Iterable[str] = (),
        flood_min_syns: int = 200,
        flood_max_ack_ratio: float = 0.1,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if port_scan_unique_ports < 2 or brute_force_attempts < 2:
            raise ValueError("thresholds must be at least 2")
        if not 0 < flood_max_ack_ratio < 1:
            raise ValueError("flood_max_ack_ratio must be between 0 and 1")

        self.window = float(window_seconds)
        self.port_scan_threshold = port_scan_unique_ports
        self.brute_force_threshold = brute_force_attempts
        self.watched_ports = frozenset(watched_ports)
        self.cooldown = float(cooldown_seconds)
        self.allowlist = Allowlist(whitelist)
        self.flood_min_syns = flood_min_syns
        self.flood_max_ack_ratio = flood_max_ack_ratio

        self._history: Dict[str, Deque[SynEvent]] = defaultdict(deque)
        self._syn_targets: Dict[Target, Deque[float]] = defaultdict(deque)
        self._ack_targets: Dict[Target, Deque[float]] = defaultdict(deque)
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._observations = 0

    # ----- public API -------------------------------------------------------

    def observe(self, event: SynEvent) -> List[Alert]:
        """Record one SYN and return any alerts it triggers."""
        self._observations += 1
        if self._observations % 5000 == 0:
            self.prune(event.timestamp)

        alerts = self._check_flood(event)

        if event.src in self.allowlist:
            return alerts

        history = self._history[event.src]
        history.append(event)
        self._trim_events(history, event.timestamp)

        distinct_ports = len({e.dst_port for e in history})
        if distinct_ports >= self.port_scan_threshold:
            alerts += self._alert(
                kind="port_scan",
                src=event.src,
                detail=f"{distinct_ports} distinct ports in {self.window:.0f}s",
                ts=event.timestamp,
            )

        hits = Counter(e.dst_port for e in history if e.dst_port in self.watched_ports)
        for port, count in sorted(hits.items()):
            if count >= self.brute_force_threshold:
                alerts += self._alert(
                    kind="brute_force",
                    src=event.src,
                    detail=f"{count} SYNs to port {port} in {self.window:.0f}s",
                    ts=event.timestamp,
                    key=f"brute_force:{port}",
                )
        return alerts

    def observe_ack(self, event: AckEvent) -> None:
        """Record a pure ACK. Used only to compute the flood ACK ratio."""
        acks = self._ack_targets[(event.dst, event.dst_port)]
        acks.append(event.timestamp)
        _trim_times(acks, event.timestamp, self.window)

    def prune(self, now: float) -> None:
        """Drop idle sources and expired state to bound memory use."""
        for src in list(self._history):
            history = self._history[src]
            self._trim_events(history, now)
            if not history:
                del self._history[src]

        for table in (self._syn_targets, self._ack_targets):
            for target in list(table):
                _trim_times(table[target], now, self.window)
                if not table[target]:
                    del table[target]

        for key in list(self._last_alert):
            if now - self._last_alert[key] >= self.cooldown:
                del self._last_alert[key]

    # ----- internals --------------------------------------------------------

    def _check_flood(self, event: SynEvent) -> List[Alert]:
        target: Target = (event.dst, event.dst_port)
        syns = self._syn_targets[target]
        syns.append(event.timestamp)
        _trim_times(syns, event.timestamp, self.window)

        acks = self._ack_targets[target]
        _trim_times(acks, event.timestamp, self.window)

        syn_count = len(syns)
        if syn_count < self.flood_min_syns:
            return []
        ratio = len(acks) / syn_count
        if ratio > self.flood_max_ack_ratio:
            return []

        return self._alert(
            kind="syn_flood",
            src=event.dst,
            detail=(
                f"{syn_count} SYNs to {event.dst}:{event.dst_port} in {self.window:.0f}s, "
                f"ACK ratio {ratio:.2f}"
            ),
            ts=event.timestamp,
            key=f"syn_flood:{event.dst_port}",
            blockable=False,
        )

    def _trim_events(self, history: Deque[SynEvent], now: float) -> None:
        cutoff = now - self.window
        while history and history[0].timestamp < cutoff:
            history.popleft()

    def _alert(
        self,
        *,
        kind: str,
        src: str,
        detail: str,
        ts: float,
        key: str | None = None,
        blockable: bool = True,
    ) -> List[Alert]:
        rate_key = (key or kind, src)
        last = self._last_alert.get(rate_key)
        if last is not None and ts - last < self.cooldown:
            return []
        self._last_alert[rate_key] = ts
        return [Alert(kind=kind, src=src, detail=detail, timestamp=ts, blockable=blockable)]
