# publicdns-python

Programmatic access to [publicdns.info](https://publicdns.info) resolver data.

A zero-dependency Python library for querying, filtering, validating, and benchmarking public DNS resolvers using the largest live-tested directory on the internet (8,500+ servers re-verified every 72 hours).

**Replaces [`mehrdadrad/pubdns`](https://github.com/mehrdadrad/pubdns)** which wraps the stale `public-dns.info` dataset that stopped updating in 2020.

## Why publicdns-python?

| Feature | publicdns-python | mehrdadrad/pubdns |
|---------|-----------------|-------------------|
| Data source | [publicdns.info](https://publicdns.info) (live, 72h cycle) | public-dns.info (stale since 2020) |
| Resolvers | 8,500+ verified | ~3,000 unverified |
| NXDOMAIN hijack detection | Yes | No |
| Live validation | Yes (built-in) | No |
| Benchmarking | Yes (latency, jitter, P95/P99) | No |
| Privacy resolver list | Yes (curated) | No |
| Country filtering | Yes | Yes |
| Dependencies | **Zero** (stdlib only) | Go standard library |
| Language | Python 3.7+ | Go |
| Single file | Yes, just download it | Requires `go get` |

## Installation

No package manager needed. Just download the single file:

```bash
# Option 1: curl
curl -O https://raw.githubusercontent.com/riankellyjn-a11y/publicdns-python/main/publicdns.py

# Option 2: wget
wget https://raw.githubusercontent.com/riankellyjn-a11y/publicdns-python/main/publicdns.py
```

Or copy it into your project. That's it. No `pip install`, no virtual environments, no dependency conflicts.

## Quick Start (Library)

```python
import publicdns

# Get all resolvers from publicdns.info
resolvers = publicdns.get_resolvers()
print(f"Found {len(resolvers)} resolvers")

# Filter by country
irish = publicdns.get_resolvers_by_country("IE")
german = publicdns.get_resolvers_by_country("DE")

# Get the 10 fastest (live-tested from YOUR network)
fastest = publicdns.get_fastest(10)
for r in fastest:
    print(f"{r['ip']:16s} {r['avg_ms']:6.1f}ms  {r['country']}")

# Privacy-focused resolvers with metadata
private = publicdns.get_privacy_resolvers(validate=True)
for r in private:
    print(f"{r['ip']:16s} {r['provider']:14s} DoH:{r['doh']}  DoT:{r['dot']}")

# Validate a specific resolver
result = publicdns.validate_resolver("1.1.1.1")
print(f"Alive: {result['alive']}, Latency: {result['avg_ms']}ms")

# Full benchmark with statistics
stats = publicdns.benchmark_resolver("8.8.8.8", rounds=5)
print(f"Avg: {stats['avg_ms']}ms, Jitter: {stats['jitter_ms']}ms, P95: {stats['p95_ms']}ms")
```

## Quick Start (CLI)

```bash
# List all resolvers
python3 publicdns.py --list

# List and validate (slower, but shows latency and reliability)
python3 publicdns.py --list --do-validate

# Filter by country
python3 publicdns.py --country us
python3 publicdns.py --country ie --do-validate

# Find the 5 fastest resolvers from your network
python3 publicdns.py --fastest 5

# Privacy-focused resolvers
python3 publicdns.py --privacy --do-validate

# Validate a specific resolver
python3 publicdns.py --validate 1.1.1.1

# Full benchmark
python3 publicdns.py --benchmark 8.8.8.8

# JSON output (for scripts and piping)
python3 publicdns.py --fastest 10 --json
python3 publicdns.py --benchmark 9.9.9.9 --json
python3 publicdns.py --country de --json

# Limit output
python3 publicdns.py --list --limit 20

# Adjust timeout and rounds
python3 publicdns.py --benchmark 1.1.1.1 --rounds 10 --timeout 3.0
```

## API Reference

### `get_resolvers(validate=False, max_workers=50, timeout=2.0, rounds=2)`

Fetch all public DNS resolvers from publicdns.info.

**Parameters:**
- `validate` (bool): If True, live-test each resolver. Default False for speed.
- `max_workers` (int): Thread pool size for parallel validation.
- `timeout` (float): DNS query timeout in seconds.
- `rounds` (int): Queries per resolver during validation.

**Returns:** List of resolver dicts:
```python
{"ip": "1.1.1.1", "country": "US", "avg_ms": 12.3, "reliability": 100.0, "nxdomain_ok": True}
```

---

### `get_resolvers_by_country(country_code, validate=False, ...)`

Fetch resolvers for a specific country.

**Parameters:**
- `country_code` (str): ISO 3166-1 alpha-2 code (e.g. "US", "IE", "DE").

**Returns:** List of resolver dicts for that country.

---

### `get_fastest(n=10, country_code=None, ...)`

Get the top N fastest resolvers by measured latency. Always performs live validation.

**Parameters:**
- `n` (int): Number of resolvers to return.
- `country_code` (str, optional): Filter by country.

**Returns:** List of up to N resolver dicts, sorted fastest-first.

---

### `get_privacy_resolvers(validate=False, ...)`

Get privacy-focused DNS resolvers with extended metadata.

Includes: Cloudflare, Quad9, Mullvad, AdGuard, DNS.Watch, LibreDNS, NextDNS, Control D, CIRA Shield.

**Returns:** List of resolver dicts with extra fields:
```python
{
    "ip": "9.9.9.9",
    "provider": "Quad9",
    "no_log": True,
    "dnssec": True,
    "doh": True,    # DNS-over-HTTPS
    "dot": True,    # DNS-over-TLS
    ...
}
```

---

### `validate_resolver(ip, timeout=2.0, rounds=3)`

Test whether a single DNS resolver is working.

**Returns:**
```python
{
    "ip": "1.1.1.1",
    "alive": True,
    "avg_ms": 11.42,
    "reliability": 100.0,
    "nxdomain_ok": True,
    "queries_sent": 3,
    "queries_ok": 3
}
```

---

### `benchmark_resolver(ip, rounds=5, timeout=2.0)`

Full benchmark with detailed statistics.

**Returns:**
```python
{
    "ip": "8.8.8.8",
    "alive": True,
    "total_queries": 50,
    "successful_queries": 50,
    "failed_queries": 0,
    "reliability": 100.0,
    "avg_ms": 14.23,
    "min_ms": 10.11,
    "max_ms": 22.87,
    "median_ms": 13.45,
    "jitter_ms": 3.21,
    "p95_ms": 20.12,
    "p99_ms": 22.87,
    "nxdomain_ok": True,
    "latencies": [10.11, 11.23, ...]
}
```

---

### `clear_cache()`

Clear the internal HTTP page cache. Call this if you need fresh data from publicdns.info within the same process.

## Resolver Dict Schema

Every resolver dict returned by the library contains at minimum:

| Field | Type | Description |
|-------|------|-------------|
| `ip` | str | IPv4 address of the resolver |
| `country` | str | ISO 3166-1 alpha-2 country code (may be empty) |
| `avg_ms` | float | Average latency in milliseconds (0.0 if not validated) |
| `reliability` | float | Success rate 0-100 (0.0 if not validated) |
| `nxdomain_ok` | bool | True if NXDOMAIN is returned correctly (no hijacking) |

Privacy resolvers include additional fields: `provider`, `no_log`, `dnssec`, `doh`, `dot`.

## Use Cases

- **OSINT / Bug Bounty**: Feed validated resolver lists into tools like massdns, subfinder, or dnsx.
- **Network Monitoring**: Periodically benchmark your configured DNS and alert on degradation.
- **DNS Migration**: Compare resolvers from your actual network before switching.
- **Privacy Auditing**: Identify which resolvers support encrypted DNS and have no-log policies.
- **Gaming Optimization**: Find the lowest-latency resolver from your location.
- **CI/CD**: Validate that your infrastructure's DNS resolvers are healthy.

## How It Works

1. **Fetching**: Scrapes resolver IPs from publicdns.info HTML pages (main page or country-specific).
2. **Validation**: Sends raw DNS queries over UDP port 53 using Python's `socket` module. No external libraries.
3. **NXDOMAIN Check**: Queries a provably non-existent domain and verifies the server returns RCODE 3.
4. **Benchmarking**: Multiple rounds of queries across 10 popular domains, computing statistical measures.

All DNS wire-protocol handling is built from scratch using `struct.pack/unpack`, requiring zero dependencies beyond the Python standard library.

## Requirements

- Python 3.7 or later
- Network access to port 53 (UDP) for DNS queries
- Network access to publicdns.info (HTTPS) for fetching resolver lists

## License

MIT License. Copyright (c) 2026 Rian Kelly.

## Links

- **Data source**: [publicdns.info](https://publicdns.info)
- **DNS Privacy Check**: [publicdns.info/dns-privacy-check.html](https://publicdns.info/dns-privacy-check.html)
- **DNS Gaming Benchmark**: [publicdns.info/dns-gaming-benchmark.html](https://publicdns.info/dns-gaming-benchmark.html)
- **Author**: [Rian Kelly](https://github.com/riankellyjn-a11y)
