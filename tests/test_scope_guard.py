#!/usr/bin/env python3
"""Tests for scope-guard. Run: python3 -m unittest discover -s tests -v"""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scope_guard import Scope

S = Scope(
    allow=["example.com", "*.wild.test", "203.0.113.0/24", "2001:db8::/32"],
    deny=["staging.example.com", "203.0.113.9"],
)


class TestDomains(unittest.TestCase):
    def test_apex_and_subdomains(self):
        self.assertTrue(S.allows("example.com")[0])
        self.assertTrue(S.allows("api.example.com")[0])
        self.assertTrue(S.allows("deep.api.example.com")[0])

    def test_lookalike_rejected(self):
        self.assertFalse(S.allows("notexample.com")[0])
        self.assertFalse(S.allows("example.com.evil.test")[0])

    def test_wildcard_excludes_apex(self):
        self.assertTrue(S.allows("a.wild.test")[0])
        self.assertFalse(S.allows("wild.test")[0])

    def test_deny_wins_over_allow(self):
        ok, why = S.allows("staging.example.com")
        self.assertFalse(ok)
        self.assertIn("denied", why)

    def test_case_and_trailing_dot(self):
        self.assertTrue(S.allows("API.Example.COM.")[0])

    def test_unrelated_host(self):
        self.assertFalse(S.allows("evil.test")[0])


class TestIPs(unittest.TestCase):
    def test_cidr_allow(self):
        self.assertTrue(S.allows("203.0.113.5")[0])

    def test_cidr_deny_single_ip(self):
        self.assertFalse(S.allows("203.0.113.9")[0])

    def test_outside_cidr(self):
        self.assertFalse(S.allows("198.51.100.1")[0])

    def test_ipv6_cidr(self):
        self.assertTrue(S.allows("2001:db8::5")[0])
        self.assertFalse(S.allows("2001:db9::5")[0])

    def test_ip_does_not_match_domain_entry(self):
        self.assertFalse(S.allows("1.2.3.4")[0])


class TestEdge(unittest.TestCase):
    def test_empty(self):
        self.assertFalse(S.allows("")[0])

    def test_deny_list_can_carve_cidr(self):
        s = Scope(allow=["10.0.0.0/8"], deny=["10.9.0.0/16"])
        self.assertTrue(s.allows("10.1.2.3")[0])
        self.assertFalse(s.allows("10.9.1.1")[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
