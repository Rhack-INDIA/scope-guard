#!/usr/bin/env python3
"""scope-guard — refuse to touch anything that is not in written scope.

Every bug-bounty and pentest incident I have seen starts the same way: a scanner run
against a host that looked in-scope. This is a tiny, boring gate that makes
out-of-scope a hard error instead of a judgement call.

scope.yaml:
    allow:
      - example.com              # apex + any subdomain
      - "*.example.com"          # subdomains only
      - 203.0.113.0/24           # CIDR
      - 2001:db8::/32
    deny:                        # checked first, always wins
      - staging.example.com
      - 203.0.113.9

Usage:
    scope-guard check api.example.com 203.0.113.5
    scope-guard check evil.test            # exit 1
    cat hosts.txt | scope-guard filter     # prints only in-scope entries
"""
from __future__ import annotations
import argparse, ipaddress, sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("need PyYAML: pip install pyyaml", file=sys.stderr); raise


class Scope:
    def __init__(self, allow: list[str], deny: list[str] | None = None):
        self.allow = [a.strip().lower() for a in allow]
        self.deny = [d.strip().lower() for d in (deny or [])]

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(data.get("allow") or [], data.get("deny") or [])

    # ---------- matching ----------
    @staticmethod
    def _as_net(entry: str):
        try:
            return ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return None

    def _matches_entry(self, target: str, entry: str) -> bool:
        net = self._as_net(entry)
        if net is not None:
            try:
                return ipaddress.ip_address(target) in net
            except ValueError:
                return False
        if entry.startswith("*."):
            base = entry[2:]
            return target.endswith("." + base) and target != base
        return target == entry or target.endswith("." + entry)

    def allows(self, target: str) -> tuple[bool, str]:
        t = (target or "").strip().lower().rstrip(".")
        if not t:
            return False, "empty target"
        for d in self.deny:
            if self._matches_entry(t, d):
                return False, f"explicitly denied by {d}"
        for a in self.allow:
            if self._matches_entry(t, a):
                return True, f"matches {a}"
        return False, "not in allow list"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scope-guard")
    ap.add_argument("-s", "--scope", default="scope.yaml")
    ap.add_argument("cmd", choices=["check", "filter", "list"])
    ap.add_argument("targets", nargs="*")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print failures")
    a = ap.parse_args(argv)

    scope = Scope.from_file(a.scope)
    if a.cmd == "list":
        print(f"allow ({len(scope.allow)}): " + ", ".join(scope.allow))
        print(f"deny  ({len(scope.deny)}): " + (", ".join(scope.deny) or "-"))
        return 0

    if a.cmd == "filter":
        targets = [t.strip() for t in sys.stdin if t.strip()]
    else:
        targets = a.targets
    if not targets:
        print("no targets given", file=sys.stderr)
        return 2

    bad = 0
    for t in targets:
        ok, why = scope.allows(t)
        if not ok:
            bad += 1
        if a.cmd == "filter":
            if ok:
                print(t)
        elif not a.quiet or not ok:
            print(f"{'ALLOW' if ok else 'DENY '}  {t:<45} {why}")
    if a.cmd == "check" and bad:
        print(f"\n{bad} target(s) out of scope — do not test these.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
