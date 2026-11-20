import unittest

from netids.allowlist import Allowlist
from netids.blocker import (
    ALLOWLISTED,
    ALREADY_BLOCKED,
    BLOCKED,
    DRY_RUN,
    BlockerError,
    NftBlocker,
)

READY_TABLE = """table inet netids {
    set blocklist {
        type ipv4_addr
        flags timeout
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @blocklist drop
    }
}
"""


class FakeNft:
    """Records every nft call. `list` calls return `list_output` or raise `list_error`."""

    def __init__(self, list_output="", list_error=None, fail_with=None, output=""):
        self.calls = []
        self.list_output = list_output
        self.list_error = list_error
        self.fail_with = fail_with
        self.output = output

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "list":
            if self.list_error:
                raise BlockerError(self.list_error)
            return self.list_output
        if self.fail_with:
            raise BlockerError(self.fail_with)
        return self.output


def joined(calls):
    return [" ".join(c) for c in calls]


class SetupTests(unittest.TestCase):
    def test_dry_run_never_touches_nft(self):
        nft = FakeNft()
        b = NftBlocker(enabled=False, runner=nft)
        b.setup()
        self.assertEqual(nft.calls, [])

    def test_setup_creates_resources_when_table_missing(self):
        nft = FakeNft(list_error="Error: No such file or directory")
        NftBlocker(enabled=True, runner=nft).setup()
        lines = joined(nft.calls)
        self.assertTrue(any(c.startswith("delete table inet netids") for c in lines))
        self.assertTrue(any(c.startswith("add table inet netids") for c in lines))
        self.assertTrue(any("flags timeout" in c for c in lines))
        self.assertTrue(any("hook input" in c for c in lines))
        self.assertTrue(any("ip saddr @blocklist drop" in c for c in lines))

    def test_existing_complete_table_is_reused(self):
        nft = FakeNft(list_output=READY_TABLE)
        NftBlocker(enabled=True, runner=nft).setup()
        mutating = [c for c in nft.calls if c[0] != "list"]
        self.assertEqual(mutating, [], "persisted blocks must not be wiped on restart")

    def test_partial_table_is_rebuilt(self):
        nft = FakeNft(list_output="table inet netids { }")
        NftBlocker(enabled=True, runner=nft).setup()
        self.assertTrue(any(c[0] == "delete" for c in nft.calls))
        self.assertTrue(any(c[:2] == ["add", "table"] for c in nft.calls))


class BlockTests(unittest.TestCase):
    def test_dry_run_returns_dry_run_without_calls(self):
        nft = FakeNft()
        b = NftBlocker(enabled=False, runner=nft)
        self.assertEqual(b.block("203.0.113.7"), DRY_RUN)
        self.assertEqual(nft.calls, [])

    def test_block_adds_element_with_timeout(self):
        nft = FakeNft()
        b = NftBlocker(block_seconds=600, enabled=True, runner=nft)
        self.assertEqual(b.block("203.0.113.7"), BLOCKED)
        self.assertEqual(
            nft.calls[-1],
            ["add", "element", "inet", "netids", "blocklist",
             "{ 203.0.113.7 timeout 600s }"],
        )

    def test_already_blocked_is_reported_not_raised(self):
        nft = FakeNft(fail_with="Error: Could not process rule: File exists")
        self.assertEqual(NftBlocker(enabled=True, runner=nft).block("203.0.113.7"), ALREADY_BLOCKED)

    def test_other_nft_errors_propagate(self):
        nft = FakeNft(fail_with="permission denied")
        with self.assertRaises(BlockerError):
            NftBlocker(enabled=True, runner=nft).block("203.0.113.7")

    def test_invalid_ip_is_rejected_before_nft(self):
        nft = FakeNft()
        b = NftBlocker(enabled=True, runner=nft)
        for bad in ["not-an-ip", "1.2.3.4; flush ruleset", "::1", "999.1.1.1"]:
            with self.assertRaises(ValueError):
                b.block(bad)
        self.assertEqual(nft.calls, [])

    def test_allowlisted_address_is_never_blocked(self):
        nft = FakeNft()
        b = NftBlocker(enabled=True, allowlist=Allowlist(["10.0.0.0/8"]), runner=nft)
        self.assertEqual(b.block("10.1.2.3"), ALLOWLISTED)
        self.assertEqual(nft.calls, [])


class UnblockAndListTests(unittest.TestCase):
    def test_unblock_deletes_element(self):
        nft = FakeNft()
        self.assertTrue(NftBlocker(enabled=True, runner=nft).unblock("203.0.113.7"))
        self.assertEqual(
            nft.calls[-1],
            ["delete", "element", "inet", "netids", "blocklist", "{ 203.0.113.7 }"],
        )

    def test_unblock_missing_element_returns_false(self):
        nft = FakeNft(fail_with="Error: Could not process rule: No such file or directory")
        self.assertFalse(NftBlocker(enabled=True, runner=nft).unblock("203.0.113.7"))

    def test_list_blocks_returns_nft_output(self):
        nft = FakeNft(list_output="set blocklist { elements = { 203.0.113.7 } }")
        out = NftBlocker(enabled=True, runner=nft).list_blocks()
        self.assertEqual(nft.calls[-1], ["list", "set", "inet", "netids", "blocklist"])
        self.assertIn("203.0.113.7", out)


if __name__ == "__main__":
    unittest.main()
