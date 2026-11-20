import unittest

from netids.allowlist import Allowlist


class AllowlistTests(unittest.TestCase):
    def test_single_address(self):
        a = Allowlist(["127.0.0.1"])
        self.assertIn("127.0.0.1", a)
        self.assertNotIn("127.0.0.2", a)

    def test_cidr_range(self):
        a = Allowlist(["192.168.56.0/24"])
        self.assertIn("192.168.56.1", a)
        self.assertIn("192.168.56.254", a)
        self.assertNotIn("192.168.57.1", a)

    def test_ipv6_range(self):
        a = Allowlist(["2001:db8::/32"])
        self.assertIn("2001:db8::1", a)
        self.assertNotIn("2001:db9::1", a)

    def test_non_ip_lookups_return_false(self):
        a = Allowlist(["10.0.0.0/8"])
        self.assertNotIn("not-an-ip", a)
        self.assertNotIn("", a)

    def test_invalid_entry_fails_at_construction(self):
        with self.assertRaises(ValueError):
            Allowlist(["10.0.0.0/33"])
        with self.assertRaises(ValueError):
            Allowlist(["admin-laptop"])

    def test_empty_allowlist_contains_nothing(self):
        a = Allowlist()
        self.assertEqual(len(a), 0)
        self.assertNotIn("10.0.0.1", a)


if __name__ == "__main__":
    unittest.main()
