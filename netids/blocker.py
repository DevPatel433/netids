"""Blocks offending IPv4 addresses with nftables.

Blocks live in an nftables set with per-element timeouts, so they expire on
their own. The table is kept across service restarts, so active blocks
survive a restart. Commands are passed as argument lists (never through a
shell), and every address is validated before it reaches nft.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
from typing import Callable, List, Optional

from .allowlist import Allowlist

log = logging.getLogger(__name__)

Runner = Callable[[List[str]], Optional[str]]

# Return values from block(). Logged and exported as the alert "action".
BLOCKED = "blocked"
ALREADY_BLOCKED = "already_blocked"
DRY_RUN = "dry_run"
ALLOWLISTED = "allowlisted"


class BlockerError(RuntimeError):
    """Raised when an nft command fails."""


def _run_nft(args: List[str]) -> str:
    try:
        proc = subprocess.run(["nft", *args], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise BlockerError("nft binary not found; install nftables") from exc
    if proc.returncode != 0:
        raise BlockerError(proc.stderr.strip() or f"nft exited with {proc.returncode}")
    return proc.stdout


class NftBlocker:
    def __init__(
        self,
        *,
        table: str = "netids",
        block_seconds: int = 3600,
        enabled: bool = False,
        allowlist: Optional[Allowlist] = None,
        runner: Optional[Runner] = None,
    ) -> None:
        self.table = table
        self.block_seconds = int(block_seconds)
        self.enabled = enabled
        self.allowlist = allowlist or Allowlist()
        self._run: Runner = runner or _run_nft

    # ----- lifecycle --------------------------------------------------------

    def setup(self) -> None:
        """Create the table, blocklist set, input chain and drop rule if needed.

        An existing, complete table is reused so active blocks persist across
        restarts. A missing or partial table is rebuilt from scratch.
        """
        if not self.enabled:
            log.info("Response disabled: nftables will not be modified (dry run)")
            return

        if self._table_is_ready():
            log.info("Reusing nftables table 'inet %s'; active blocks are preserved", self.table)
            return

        try:
            self._run(["delete", "table", "inet", self.table])
        except BlockerError:
            pass  # table did not exist

        self._run(["add", "table", "inet", self.table])
        self._run(
            ["add", "set", "inet", self.table, "blocklist",
             "{ type ipv4_addr; flags timeout; }"]
        )
        self._run(
            ["add", "chain", "inet", self.table, "input",
             "{ type filter hook input priority -10; policy accept; }"]
        )
        self._run(
            ["add", "rule", "inet", self.table, "input",
             "ip", "saddr", "@blocklist", "drop"]
        )
        log.info("Created nftables table 'inet %s'", self.table)

    def _table_is_ready(self) -> bool:
        try:
            output = self._run(["list", "table", "inet", self.table]) or ""
        except BlockerError:
            return False
        return "@blocklist" in output and "drop" in output

    # ----- operations -------------------------------------------------------

    def block(self, ip: str) -> str:
        """Block `ip` for `block_seconds`. Returns one of the status constants."""
        address = str(ipaddress.IPv4Address(ip))  # raises ValueError if invalid

        if address in self.allowlist:
            log.warning("Refusing to block allowlisted address %s", address)
            return ALLOWLISTED

        if not self.enabled:
            log.warning("DRY RUN: would block %s for %ds", address, self.block_seconds)
            return DRY_RUN

        element = f"{{ {address} timeout {self.block_seconds}s }}"
        try:
            self._run(["add", "element", "inet", self.table, "blocklist", element])
        except BlockerError as exc:
            if "File exists" in str(exc):
                log.info("%s is already blocked", address)
                return ALREADY_BLOCKED
            raise

        log.warning("BLOCKED %s for %ds", address, self.block_seconds)
        return BLOCKED

    def unblock(self, ip: str) -> bool:
        """Remove `ip` from the blocklist. Returns False if it wasn't blocked."""
        address = str(ipaddress.IPv4Address(ip))
        try:
            self._run(["delete", "element", "inet", self.table, "blocklist",
                       f"{{ {address} }}"])
        except BlockerError as exc:
            if "No such file" in str(exc):
                return False
            raise
        log.warning("UNBLOCKED %s", address)
        return True

    def list_blocks(self) -> str:
        """Return the raw nftables view of the current blocklist."""
        return self._run(["list", "set", "inet", self.table, "blocklist"]) or ""
