"""Structured alert output as JSON Lines, ready for SIEM ingestion.

One JSON object per line, so Filebeat, Wazuh, or Splunk can tail the file
without custom parsing.
"""

from __future__ import annotations

import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .detector import Alert


class JsonAlertWriter:
    def __init__(self, path: Optional[str], sensor: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self.sensor = sensor or socket.gethostname()
        self._lock = threading.Lock()

    def build_record(self, alert: Alert, action: str) -> dict:
        return {
            "timestamp": datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat(),
            "sensor": self.sensor,
            "event": "alert",
            "kind": alert.kind,
            "src": alert.src,
            "detail": alert.detail,
            "action": action,
        }

    def write(self, alert: Alert, action: str) -> dict:
        record = self.build_record(alert, action)
        if self.path is None:
            return record
        line = json.dumps(record, sort_keys=True)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return record
