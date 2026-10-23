# scope-guard

A five-line gate between "this looks in scope" and "I ran a scanner against it".

Most testing incidents are not exotic. They are a hostname that looked close enough:
`staging.example.com` inside a programme that only covers production, or a CIDR that
happened to include the client's neighbour. `scope-guard` makes out-of-scope a hard
error instead of a judgement call.

```
$ scope-guard check api.example.com 203.0.113.5 staging.example.com

ALLOW  api.example.com                                 matches example.com
ALLOW  203.0.113.5                                     matches 203.0.113.0/24
DENY   staging.example.com                             explicitly denied by staging.example.com

1 target(s) out of scope — do not test these.
```

## Scope file

```yaml
allow:
  - example.com            # apex and every subdomain
  - "*.wild.test"          # subdomains only, NOT the apex
  - 203.0.113.0/24         # IPv4 CIDR
  - 2001:db8::/32          # IPv6 CIDR
deny:                      # evaluated first — always wins
  - staging.example.com
  - 203.0.113.9
```

## Commands

| Command | Behaviour |
|---|---|
| `scope-guard check <targets...>` | prints ALLOW/DENY with the matching rule; **exit 1** if anything is out of scope |
| `cat hosts.txt \| scope-guard filter` | prints only in-scope entries — pipe straight into `httpx`/`nuclei` |
| `scope-guard list` | dump the parsed rules |

Typical use — never let an out-of-scope host reach the scanner:

```bash
cat subdomains.txt | scope-guard filter | httpx -silent | nuclei -l /dev/stdin
```

## Semantics worth knowing

- `example.com` matches the apex **and** subdomains; `*.example.com` matches **only**
  subdomains. Both behaviours are needed, so they are different entries.
- `deny` is checked first, so you can allow a `/16` and carve out one host.
- IP/CIDR entries never match hostnames, and domain entries never match IPs — no silent
  cross-matching.
- Input is case-folded and trailing dots are stripped (`API.Example.COM.` → allowed).
- Lookalikes are rejected: `notexample.com` and `example.com.evil.test` do not match
  `example.com`, because matching is on label boundaries, not substrings.

## Install & test

```bash
pip install pyyaml
python3 scope_guard.py check api.example.com
python3 -m unittest discover -s tests -v     # 13 tests
```

## Why it is this small

Because the failure it prevents is a single missed check, and a tool you have to think
about is a tool you will skip at 2am. `Scope.allows(target)` is three lines of usage:

```python
from scope_guard import Scope
scope = Scope.from_file("scope.yaml")
ok, reason = scope.allows("api.example.com")
```

## Licence

MIT
