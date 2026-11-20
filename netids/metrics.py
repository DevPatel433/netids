"""Prometheus-format metrics served over HTTP at /metrics.

Uses only the standard library. Bind it to 127.0.0.1 unless you have a reason
to expose it.
"""

from __future__ import annotations

import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Type


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._syn = 0
        self._ack = 0
        self._blocks = 0
        self._alerts: Counter[str] = Counter()

    def record_syn(self) -> None:
        with self._lock:
            self._syn += 1

    def record_ack(self) -> None:
        with self._lock:
            self._ack += 1

    def record_alert(self, kind: str) -> None:
        with self._lock:
            self._alerts[kind] += 1

    def record_block(self) -> None:
        with self._lock:
            self._blocks += 1

    def render(self) -> str:
        with self._lock:
            lines = [
                "# HELP netids_syn_packets_total Pure TCP SYN packets seen.",
                "# TYPE netids_syn_packets_total counter",
                f"netids_syn_packets_total {self._syn}",
                "# HELP netids_ack_packets_total Pure TCP ACK packets seen.",
                "# TYPE netids_ack_packets_total counter",
                f"netids_ack_packets_total {self._ack}",
                "# HELP netids_alerts_total Alerts raised, by kind.",
                "# TYPE netids_alerts_total counter",
            ]
            for kind in sorted(self._alerts):
                lines.append(f'netids_alerts_total{{kind="{kind}"}} {self._alerts[kind]}')
            lines += [
                "# HELP netids_blocks_total IP addresses blocked.",
                "# TYPE netids_blocks_total counter",
                f"netids_blocks_total {self._blocks}",
            ]
        return "\n".join(lines) + "\n"


def _make_handler(metrics: Metrics) -> Type[BaseHTTPRequestHandler]:
    class MetricsHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            if self.path.split("?", 1)[0] != "/metrics":
                self.send_error(404)
                return
            body = metrics.render().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:  # keep stdout clean
            return

    return MetricsHandler


def start_server(metrics: Metrics, listen: str) -> ThreadingHTTPServer:
    """Serve metrics on `host:port` in a background thread. Use port 0 for tests."""
    host, _, port = listen.rpartition(":")
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), _make_handler(metrics))
    threading.Thread(target=server.serve_forever, name="netids-metrics", daemon=True).start()
    return server
