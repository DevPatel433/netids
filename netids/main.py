"""Command-line entry point.

    netids run                 start the sensor (used by systemd)
    netids blocks              show active blocks
    netids unblock <ip>        remove a block immediately
"""

from __future__ import annotations

import argparse
import logging
import sys
import tomllib
from pathlib import Path
from typing import Optional

from .alerts import JsonAlertWriter
from .allowlist import Allowlist
from .blocker import BlockerError, NftBlocker
from .detector import Alert, Detector
from .metrics import Metrics, start_server

DEFAULT_CONFIG = "/etc/netids/config.toml"
log = logging.getLogger("netids")


def load_config(path: str) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def setup_logging(log_cfg: dict) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    log_path = Path(log_cfg["file"])
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path))
    except OSError as exc:
        print(f"warning: cannot open log file {log_path}: {exc}", file=sys.stderr)

    logging.basicConfig(
        level=log_cfg.get("level", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=handlers,
        force=True,
    )


def build_blocker(cfg: dict, *, enabled: Optional[bool] = None) -> NftBlocker:
    resp = cfg["response"]
    return NftBlocker(
        table=resp["nft_table"],
        block_seconds=resp["block_seconds"],
        enabled=resp["enabled"] if enabled is None else enabled,
        allowlist=Allowlist(cfg["detection"]["whitelist"]),
    )


def cmd_run(cfg: dict, iface_override: Optional[str]) -> int:
    setup_logging(cfg["logging"])
    det = cfg["detection"]

    detector = Detector(
        window_seconds=det["window_seconds"],
        port_scan_unique_ports=det["port_scan_unique_ports"],
        brute_force_attempts=det["brute_force_attempts"],
        watched_ports=det["watched_ports"],
        cooldown_seconds=det["alert_cooldown_seconds"],
        whitelist=det["whitelist"],
        flood_min_syns=det["flood_min_syns"],
        flood_max_ack_ratio=det["flood_max_ack_ratio"],
    )
    blocker = build_blocker(cfg)
    try:
        blocker.setup()
    except BlockerError as exc:
        log.error("nftables setup failed: %s", exc)
        return 1

    metrics = Metrics()
    listen = cfg.get("metrics", {}).get("listen", "")
    if listen:
        start_server(metrics, listen)
        log.info("Metrics available at http://%s/metrics", listen)

    writer = JsonAlertWriter(cfg.get("output", {}).get("json_alerts", ""))

    def handle_alert(alert: Alert) -> None:
        metrics.record_alert(alert.kind)
        log.warning("ALERT %s from %s: %s", alert.kind, alert.src, alert.detail)

        action = "not_blockable"
        if alert.blockable:
            try:
                action = blocker.block(alert.src)
            except (BlockerError, ValueError) as exc:
                log.error("could not block %s: %s", alert.src, exc)
                action = "error"
        if action == "blocked":
            metrics.record_block()
        writer.write(alert, action)

    def on_syn(event) -> None:
        metrics.record_syn()
        for alert in detector.observe(event):
            handle_alert(alert)

    def on_ack(event) -> None:
        metrics.record_ack()
        detector.observe_ack(event)

    iface = iface_override or cfg["capture"]["interface"]
    bpf = cfg["capture"]["bpf_filter"]
    log.info(
        "Listening on %s (filter=%r, enforcement=%s)",
        iface, bpf, "ON" if blocker.enabled else "OFF (dry run)",
    )

    # Imported here so the detector and CLI can be tested without scapy.
    from .capture import run_capture

    try:
        run_capture(iface, bpf, on_syn, on_ack)
    except PermissionError:
        log.error("Packet capture needs root or CAP_NET_RAW")
        return 1
    except KeyboardInterrupt:
        log.info("Stopping")
    return 0


def cmd_blocks(cfg: dict) -> int:
    setup_logging(cfg["logging"])
    try:
        print(build_blocker(cfg, enabled=True).list_blocks())
    except BlockerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_unblock(cfg: dict, ip: str) -> int:
    setup_logging(cfg["logging"])
    try:
        removed = build_blocker(cfg, enabled=True).unblock(ip)
    except (BlockerError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if removed:
        print(f"unblocked {ip}")
        return 0
    print(f"{ip} is not blocked")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netids",
        description="Detect port scans, brute-force attempts and SYN floods; optionally block offenders.",
    )
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="path to config.toml")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="start the sensor")
    run.add_argument("-i", "--iface", help="override the capture interface")

    sub.add_parser("blocks", help="list active blocks")

    unblock = sub.add_parser("unblock", help="remove an IP from the blocklist")
    unblock.add_argument("ip", help="IPv4 address to unblock")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
    except OSError as exc:
        print(f"error: cannot read config: {exc}", file=sys.stderr)
        return 2

    if args.command == "run":
        return cmd_run(cfg, args.iface)
    if args.command == "blocks":
        return cmd_blocks(cfg)
    return cmd_unblock(cfg, args.ip)


if __name__ == "__main__":
    raise SystemExit(main())
