#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
publicdns-python - Programmatic access to publicdns.info resolver data.

Zero-dependency Python library for querying, filtering, validating, and
benchmarking public DNS resolvers using live-tested data from publicdns.info.

Replaces mehrdadrad/pubdns (which wraps the stale public-dns.info) with a
modern, actively maintained alternative backed by a directory of 8,500+
resolvers re-verified every 72 hours.

Library usage:
    import publicdns
    resolvers = publicdns.get_resolvers()
    fastest   = publicdns.get_fastest(10)
    irish     = publicdns.get_resolvers_by_country("IE")
    private   = publicdns.get_privacy_resolvers()
    ok        = publicdns.validate_resolver("1.1.1.1")
    stats     = publicdns.benchmark_resolver("8.8.8.8", rounds=10)

CLI usage:
    python3 publicdns.py --list
    python3 publicdns.py --list --do-validate
    python3 publicdns.py --country us
    python3 publicdns.py --country us --do-validate
    python3 publicdns.py --fastest 5
    python3 publicdns.py --validate 1.1.1.1
    python3 publicdns.py --benchmark 8.8.8.8
    python3 publicdns.py --privacy
    python3 publicdns.py --json

Author:  Rian Kelly (https://github.com/riankellyjn-a11y)
License: MIT
Source:  https://publicdns.info
Repo:    https://github.com/riankellyjn-a11y/publicdns-python

MIT License

Copyright (c) 2026 Rian Kelly

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import random
import re
import socket
import struct
import sys
import time
from statistics import mean, stdev
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen

__version__ = "1.0.0"
__author__ = "Rian Kelly"
__license__ = "MIT"
__url__ = "https://publicdns.info"
__repo__ = "https://github.com/riankellyjn-a11y/publicdns-python"

# ---------------------------------------------------------------------------
# Well-known privacy-focused providers (used by get_privacy_resolvers)
# ---------------------------------------------------------------------------

_PRIVACY_PROVIDERS: Dict[str, Dict[str, Any]] = {
    # Cloudflare 1.1.1.1 - committed no-logging policy, audited by KPMG
    "1.1.1.1": {"provider": "Cloudflare", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    "1.0.0.1": {"provider": "Cloudflare", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    # Quad9 - Swiss non-profit, DNSSEC enforced, threat-blocking
    "9.9.9.9": {"provider": "Quad9", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    "149.112.112.112": {"provider": "Quad9", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    # Mullvad DNS - VPN company, zero logging
    "194.242.2.2": {"provider": "Mullvad", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    # AdGuard DNS - ad/tracker blocking, DoH/DoT
    "94.140.14.14": {"provider": "AdGuard", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    "94.140.15.15": {"provider": "AdGuard", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    # DNS.Watch - no logging, no filtering, based in Germany
    "84.200.69.80": {"provider": "DNS.Watch", "no_log": True, "dnssec": True, "doh": False, "dot": False},
    "84.200.70.40": {"provider": "DNS.Watch", "no_log": True, "dnssec": True, "doh": False, "dot": False},
    # LibreDNS - OpenNIC project, no logging
    "116.202.176.26": {"provider": "LibreDNS", "no_log": True, "dnssec": False, "doh": True, "dot": True},
    # NextDNS - privacy-first, configurable filtering
    "45.90.28.0": {"provider": "NextDNS", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    "45.90.30.0": {"provider": "NextDNS", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    # Control D - privacy-first, DoH/DoT/DoQ
    "76.76.2.0": {"provider": "Control D", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    "76.76.10.0": {"provider": "Control D", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    # CIRA Canadian Shield - privacy mode (no filtering)
    "149.112.121.10": {"provider": "CIRA Shield", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    "149.112.122.10": {"provider": "CIRA Shield", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    # Cloudflare malware blocking (1.1.1.2)
    "1.1.1.2": {"provider": "Cloudflare (Malware)", "no_log": True, "dnssec": True, "doh": True, "dot": True},
    "1.0.0.2": {"provider": "Cloudflare (Malware)", "no_log": True, "dnssec": True, "doh": True, "dot": True},
}

# ---------------------------------------------------------------------------
# Raw DNS wire-protocol engine (zero dependencies)
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

_TEST_DOMAINS = [
    "google.com", "cloudflare.com", "amazon.com",
    "microsoft.com", "github.com", "apple.com",
    "netflix.com", "facebook.com", "reddit.com", "wikipedia.org",
]


def _build_dns_query(domain: str, qtype: int = 1) -> Tuple[bytes, int]:
    """Build a raw DNS query packet (A record by default).

    Args:
        domain: The domain name to query.
        qtype: DNS query type (1=A, 28=AAAA, etc.).

    Returns:
        Tuple of (packet_bytes, transaction_id).
    """
    tid = random.randint(0, 65535)
    flags = 0x0100  # Standard query, recursion desired
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)

    domain = domain.rstrip(".")
    if not domain:
        raise ValueError("Empty domain name")

    question = b""
    for label in domain.split("."):
        if not label:
            raise ValueError(f"Empty label in domain: {domain!r}")
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label!r} ({len(encoded)} bytes)")
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00"
    question += struct.pack(">HH", qtype, 1)  # QCLASS = IN

    return header + question, tid


def _parse_dns_response(data: bytes, expected_tid: int) -> Tuple[int, bool]:
    """Parse a DNS response packet.

    Args:
        data: Raw response bytes.
        expected_tid: Expected transaction ID.

    Returns:
        Tuple of (rcode, has_answer). rcode is -1 on parse failure.
    """
    if len(data) < 12:
        return -1, False
    tid, flags, _, ancount = struct.unpack(">HHHH", data[:8])
    if tid != expected_tid:
        return -1, False
    rcode = flags & 0x0F
    return rcode, ancount > 0


def _dns_query(server: str, domain: str, timeout: float = 2.0) -> Optional[float]:
    """Send a single DNS query and measure latency.

    Args:
        server: DNS server IP address.
        domain: Domain to resolve.
        timeout: Socket timeout in seconds.

    Returns:
        Latency in milliseconds, or None on failure.
    """
    packet, tid = _build_dns_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - start) * 1000
        rcode, has_answer = _parse_dns_response(data, tid)
        if rcode == 0 and has_answer:
            return elapsed
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def _check_nxdomain(server: str, timeout: float = 2.0) -> bool:
    """Test whether a server properly returns NXDOMAIN for non-existent names.

    Args:
        server: DNS server IP address.
        timeout: Socket timeout in seconds.

    Returns:
        True if the server returns NXDOMAIN (correct behavior).
        True if the server times out (cannot determine, assume OK).
        False if the server returns an answer (NXDOMAIN hijacking).
    """
    fake = f"nxtest-{random.randint(100000, 999999)}.definitelynotreal.example"
    packet, tid = _build_dns_query(fake)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        rcode, _ = _parse_dns_response(data, tid)
        return rcode == 3  # NXDOMAIN
    except (socket.timeout, OSError):
        return True  # Timeout, assume OK
    finally:
        sock.close()


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP is in a private, reserved, or non-routable range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    if a == 0 or a == 127 or a >= 224:
        return True
    # CGNAT (RFC 6598): 100.64.0.0/10
    if a == 100 and 64 <= b <= 127:
        return True
    # Benchmarking (RFC 2544): 198.18.0.0/15
    if a == 198 and 18 <= b <= 19:
        return True
    return False


# ---------------------------------------------------------------------------
# Country code to name mapping (ISO 3166-1 alpha-2, common subset)
# ---------------------------------------------------------------------------

_COUNTRY_NAMES: Dict[str, str] = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan",
    "AL": "Albania", "AM": "Armenia", "AR": "Argentina", "AT": "Austria",
    "AU": "Australia", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina",
    "BD": "Bangladesh", "BE": "Belgium", "BG": "Bulgaria", "BH": "Bahrain",
    "BR": "Brazil", "BY": "Belarus", "CA": "Canada", "CH": "Switzerland",
    "CL": "Chile", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
    "CY": "Cyprus", "CZ": "Czech Republic", "DE": "Germany", "DK": "Denmark",
    "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia",
    "EG": "Egypt", "ES": "Spain", "FI": "Finland", "FR": "France",
    "GB": "United Kingdom", "GE": "Georgia", "GH": "Ghana", "GR": "Greece",
    "GT": "Guatemala", "HK": "Hong Kong", "HR": "Croatia", "HU": "Hungary",
    "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India",
    "IQ": "Iraq", "IR": "Iran", "IS": "Iceland", "IT": "Italy",
    "JO": "Jordan", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan",
    "KH": "Cambodia", "KR": "South Korea", "KW": "Kuwait", "KZ": "Kazakhstan",
    "LA": "Laos", "LB": "Lebanon", "LI": "Liechtenstein", "LK": "Sri Lanka",
    "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "MA": "Morocco",
    "MD": "Moldova", "ME": "Montenegro", "MK": "North Macedonia",
    "MM": "Myanmar", "MN": "Mongolia", "MT": "Malta", "MX": "Mexico",
    "MY": "Malaysia", "MZ": "Mozambique", "NG": "Nigeria", "NL": "Netherlands",
    "NO": "Norway", "NP": "Nepal", "NZ": "New Zealand", "OM": "Oman",
    "PA": "Panama", "PE": "Peru", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal",
    "QA": "Qatar", "RO": "Romania", "RS": "Serbia", "RU": "Russia",
    "SA": "Saudi Arabia", "SE": "Sweden", "SG": "Singapore", "SI": "Slovenia",
    "SK": "Slovakia", "TH": "Thailand", "TN": "Tunisia", "TR": "Turkey",
    "TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda",
    "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan",
    "VE": "Venezuela", "VN": "Vietnam", "ZA": "South Africa",
}

# ---------------------------------------------------------------------------
# HTML scraper for publicdns.info (zero external dependencies)
# ---------------------------------------------------------------------------

_BASE_URL = "https://publicdns.info"
_USER_AGENT = f"publicdns-python/{__version__} ({__repo__})"

# Simple cache to avoid re-fetching within the same process
_page_cache: Dict[str, str] = {}


def _fetch_page(url: str, timeout: float = 30.0) -> str:
    """Fetch a URL and return its text content.

    Args:
        url: The URL to fetch.
        timeout: HTTP timeout in seconds.

    Returns:
        The page body as a string (empty string on failure).
    """
    if url in _page_cache:
        return _page_cache[url]

    headers = {"User-Agent": _USER_AGENT}
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(10 * 1024 * 1024).decode("utf-8", errors="ignore")
            _page_cache[url] = body
            return body
    except Exception as exc:
        print(f"publicdns: failed to fetch {url}: {exc}", file=sys.stderr)
        return ""


def _extract_ips(html: str) -> List[str]:
    """Extract unique public IPv4 addresses from HTML content.

    Filters out private, loopback, multicast, and broadcast addresses.

    Args:
        html: Raw HTML string.

    Returns:
        Deduplicated list of public IPv4 addresses in order of appearance.
    """
    skip = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
    seen: Set[str] = set()
    result: List[str] = []
    for ip in _IP_RE.findall(html):
        if ip not in seen and ip not in skip and not _is_private_ip(ip):
            seen.add(ip)
            result.append(ip)
    return result


def _extract_country_from_html(html: str, ip: str) -> str:
    """Attempt to extract the country code associated with an IP from the page HTML.

    publicdns.info embeds country flags and codes near each IP. This does a
    best-effort extraction using common HTML patterns around the IP address.

    Args:
        html: Full page HTML.
        ip: The IP address to search for context around.

    Returns:
        Two-letter country code (uppercase), or empty string if not found.
    """
    # Look for country code patterns near the IP
    escaped = re.escape(ip)
    # Pattern: /country/XX.html near the IP, or flag-XX class
    nearby = re.search(
        escaped + r".{0,300}?/country/([a-zA-Z]{2})\.html",
        html,
        re.DOTALL,
    )
    if nearby:
        return nearby.group(1).upper()

    # Reverse search: country link before IP
    nearby = re.search(
        r"/country/([a-zA-Z]{2})\.html.{0,300}?" + escaped,
        html,
        re.DOTALL,
    )
    if nearby:
        return nearby.group(1).upper()

    return ""


def _scrape_resolvers_main() -> List[Dict[str, Any]]:
    """Scrape the main publicdns.info page for resolver IPs.

    Returns:
        List of resolver dicts with keys: ip, country, avg_ms, reliability, nxdomain_ok.
        avg_ms, reliability, and nxdomain_ok are set to defaults until validated.
    """
    html = _fetch_page(_BASE_URL)
    if not html:
        return []

    ips = _extract_ips(html)
    resolvers = []
    for ip in ips:
        country = _extract_country_from_html(html, ip)
        resolvers.append({
            "ip": ip,
            "country": country,
            "avg_ms": 0.0,
            "reliability": 0.0,
            "nxdomain_ok": True,
        })
    return resolvers


def _scrape_resolvers_country(country_code: str) -> List[Dict[str, Any]]:
    """Scrape a country-specific page from publicdns.info.

    Args:
        country_code: ISO 3166-1 alpha-2 country code (e.g. "US", "IE").

    Returns:
        List of resolver dicts for that country.
    """
    code = country_code.strip().lower()
    url = f"{_BASE_URL}/country/{code}.html"
    html = _fetch_page(url)
    if not html:
        return []

    ips = _extract_ips(html)
    cc_upper = code.upper()
    resolvers = []
    for ip in ips:
        resolvers.append({
            "ip": ip,
            "country": cc_upper,
            "avg_ms": 0.0,
            "reliability": 0.0,
            "nxdomain_ok": True,
        })
    return resolvers


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_resolvers(
    validate: bool = False,
    max_workers: int = 50,
    timeout: float = 2.0,
    rounds: int = 2,
) -> List[Dict[str, Any]]:
    """Fetch all public DNS resolvers from publicdns.info.

    Scrapes the main page of publicdns.info and returns every resolver IP
    found, with optional live validation.

    Args:
        validate: If True, send test DNS queries to each resolver and
                  populate avg_ms, reliability, and nxdomain_ok fields.
                  This takes longer but gives you verified, working servers.
        max_workers: Thread pool size for parallel validation.
        timeout: DNS query timeout in seconds (used during validation).
        rounds: Number of query rounds per resolver during validation.

    Returns:
        List of resolver dicts. Each dict contains:
            - ip (str): IPv4 address of the resolver.
            - country (str): ISO 3166-1 alpha-2 country code (best-effort, may be empty).
            - avg_ms (float): Average latency in ms (0.0 if not validated).
            - reliability (float): Success rate 0-100 (0.0 if not validated).
            - nxdomain_ok (bool): True if NXDOMAIN is handled correctly.

    Example:
        >>> import publicdns
        >>> resolvers = publicdns.get_resolvers()
        >>> len(resolvers) > 0
        True
        >>> resolvers[0]["ip"]
        '...'
    """
    resolvers = _scrape_resolvers_main()

    if validate and resolvers:
        resolvers = _validate_batch(resolvers, max_workers, timeout, rounds)

    return resolvers


def get_resolvers_by_country(
    country_code: str,
    validate: bool = False,
    max_workers: int = 50,
    timeout: float = 2.0,
    rounds: int = 2,
) -> List[Dict[str, Any]]:
    """Fetch public DNS resolvers for a specific country.

    Args:
        country_code: ISO 3166-1 alpha-2 country code (e.g. "US", "DE", "IE").
                      Case-insensitive.
        validate: If True, test each resolver with live DNS queries.
        max_workers: Thread pool size for parallel validation.
        timeout: DNS query timeout in seconds.
        rounds: Number of query rounds per resolver during validation.

    Returns:
        List of resolver dicts for the given country.

    Raises:
        ValueError: If country_code is empty or not 2 characters.

    Example:
        >>> import publicdns
        >>> irish = publicdns.get_resolvers_by_country("IE")
        >>> all(r["country"] == "IE" for r in irish)
        True
    """
    code = country_code.strip().upper()
    if len(code) != 2 or not code.isalpha():
        raise ValueError(
            f"Invalid country code: {country_code!r}. "
            "Expected a 2-letter ISO 3166-1 alpha-2 code (e.g. 'US', 'IE')."
        )

    resolvers = _scrape_resolvers_country(code)

    if validate and resolvers:
        resolvers = _validate_batch(resolvers, max_workers, timeout, rounds)

    return resolvers


def get_fastest(
    n: int = 10,
    country_code: Optional[str] = None,
    max_workers: int = 50,
    timeout: float = 2.0,
    rounds: int = 3,
) -> List[Dict[str, Any]]:
    """Get the top N fastest resolvers by measured latency.

    This always performs live validation to measure actual latency from your
    network. Resolvers that fail validation are excluded.

    Args:
        n: Number of top resolvers to return.
        country_code: Optional country filter (ISO 3166-1 alpha-2).
        max_workers: Thread pool size for parallel validation.
        timeout: DNS query timeout in seconds.
        rounds: Number of query rounds per resolver.

    Returns:
        List of up to N resolver dicts, sorted by avg_ms ascending (fastest first).
        Only resolvers that responded to at least one query are included.

    Example:
        >>> import publicdns
        >>> top5 = publicdns.get_fastest(5)
        >>> len(top5) <= 5
        True
        >>> all(r["avg_ms"] > 0 for r in top5)
        True
    """
    if country_code:
        resolvers = get_resolvers_by_country(
            country_code, validate=True, max_workers=max_workers,
            timeout=timeout, rounds=rounds,
        )
    else:
        resolvers = get_resolvers(
            validate=True, max_workers=max_workers,
            timeout=timeout, rounds=rounds,
        )

    # Filter out non-responsive resolvers and sort by latency
    alive = [r for r in resolvers if r["avg_ms"] > 0]
    alive.sort(key=lambda r: r["avg_ms"])
    return alive[:n]


def get_privacy_resolvers(
    validate: bool = False,
    timeout: float = 2.0,
    rounds: int = 3,
) -> List[Dict[str, Any]]:
    """Get privacy-focused DNS resolvers with metadata about their privacy features.

    Returns resolvers from well-known privacy-first providers: Cloudflare,
    Quad9, Mullvad, AdGuard, DNS.Watch, LibreDNS, NextDNS, Control D, and
    CIRA Canadian Shield.

    Each returned dict includes additional fields beyond the standard resolver
    dict: provider, no_log, dnssec, doh (DNS-over-HTTPS), dot (DNS-over-TLS).

    Args:
        validate: If True, test each resolver with live DNS queries.
        timeout: DNS query timeout in seconds.
        rounds: Number of query rounds per resolver during validation.

    Returns:
        List of privacy resolver dicts with extended metadata.

    Example:
        >>> import publicdns
        >>> private = publicdns.get_privacy_resolvers(validate=True)
        >>> all(r["no_log"] for r in private)
        True
    """
    resolvers: List[Dict[str, Any]] = []
    for ip, meta in _PRIVACY_PROVIDERS.items():
        entry: Dict[str, Any] = {
            "ip": ip,
            "country": "",
            "avg_ms": 0.0,
            "reliability": 0.0,
            "nxdomain_ok": True,
            "provider": meta["provider"],
            "no_log": meta["no_log"],
            "dnssec": meta["dnssec"],
            "doh": meta["doh"],
            "dot": meta["dot"],
        }
        resolvers.append(entry)

    if validate:
        resolvers = _validate_batch(resolvers, max_workers=10, timeout=timeout, rounds=rounds)

    return resolvers


def validate_resolver(
    ip: str,
    timeout: float = 2.0,
    rounds: int = 3,
) -> Dict[str, Any]:
    """Test whether a single DNS resolver is working and measure basic performance.

    Sends multiple DNS queries to the resolver and checks NXDOMAIN handling.

    Args:
        ip: IPv4 address of the DNS resolver to test.
        timeout: Socket timeout per query in seconds.
        rounds: Number of test queries to send.

    Returns:
        Dict with keys:
            - ip (str): The resolver IP tested.
            - alive (bool): True if at least one query succeeded.
            - avg_ms (float): Average latency in ms (0.0 if dead).
            - reliability (float): Success rate 0-100.
            - nxdomain_ok (bool): True if NXDOMAIN is returned correctly.
            - queries_sent (int): Total queries attempted.
            - queries_ok (int): Successful queries.

    Example:
        >>> import publicdns
        >>> result = publicdns.validate_resolver("1.1.1.1")
        >>> result["alive"]
        True
    """
    ip = ip.strip()
    if not _IP_RE.fullmatch(ip):
        raise ValueError(f"Invalid IPv4 address: {ip!r}")

    successes = 0
    latencies: List[float] = []

    for _ in range(rounds):
        domain = random.choice(_TEST_DOMAINS)
        latency = _dns_query(ip, domain, timeout=timeout)
        if latency is not None:
            successes += 1
            latencies.append(latency)

    alive = successes > 0
    avg_ms = round(mean(latencies), 2) if latencies else 0.0
    reliability = round(successes / rounds * 100, 1) if rounds > 0 else 0.0
    nxdomain_ok = _check_nxdomain(ip, timeout=timeout) if alive else False

    return {
        "ip": ip,
        "alive": alive,
        "avg_ms": avg_ms,
        "reliability": reliability,
        "nxdomain_ok": nxdomain_ok,
        "queries_sent": rounds,
        "queries_ok": successes,
    }


def benchmark_resolver(
    ip: str,
    rounds: int = 5,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """Benchmark a single DNS resolver with detailed latency statistics.

    Sends multiple queries across various test domains and computes
    comprehensive statistics including min, max, average, median, jitter
    (standard deviation), and percentiles.

    Args:
        ip: IPv4 address of the DNS resolver.
        rounds: Number of test queries per domain. Total queries will be
                rounds * len(test_domains). Default 5 gives 50 total queries.
        timeout: Socket timeout per query in seconds.

    Returns:
        Dict with keys:
            - ip (str): The resolver IP tested.
            - alive (bool): True if at least one query succeeded.
            - total_queries (int): Total queries attempted.
            - successful_queries (int): Queries that returned a valid response.
            - failed_queries (int): Queries that timed out or failed.
            - reliability (float): Success rate 0-100.
            - avg_ms (float): Mean latency in ms.
            - min_ms (float): Minimum latency in ms.
            - max_ms (float): Maximum latency in ms.
            - median_ms (float): Median latency in ms.
            - jitter_ms (float): Standard deviation of latency (consistency metric).
            - p95_ms (float): 95th percentile latency.
            - p99_ms (float): 99th percentile latency.
            - nxdomain_ok (bool): NXDOMAIN integrity check.
            - latencies (list[float]): Raw latency values in ms.

    Example:
        >>> import publicdns
        >>> stats = publicdns.benchmark_resolver("8.8.8.8", rounds=3)
        >>> stats["alive"]
        True
        >>> stats["avg_ms"] > 0
        True
    """
    ip = ip.strip()
    if not _IP_RE.fullmatch(ip):
        raise ValueError(f"Invalid IPv4 address: {ip!r}")

    latencies: List[float] = []
    failures = 0
    total = 0

    for _ in range(rounds):
        for domain in _TEST_DOMAINS:
            total += 1
            latency = _dns_query(ip, domain, timeout=timeout)
            if latency is not None:
                latencies.append(latency)
            else:
                failures += 1

    alive = len(latencies) > 0

    if alive:
        sorted_lat = sorted(latencies)
        n = len(sorted_lat)
        avg = round(mean(sorted_lat), 2)
        min_ms = round(sorted_lat[0], 2)
        max_ms = round(sorted_lat[-1], 2)
        if n % 2 == 1:
            median = round(sorted_lat[n // 2], 2)
        else:
            median = round((sorted_lat[n // 2 - 1] + sorted_lat[n // 2]) / 2, 2)
        jitter = round(stdev(sorted_lat), 2) if n > 1 else 0.0
        p95 = round(sorted_lat[min(int(n * 0.95), n - 1)], 2) if n >= 20 else round(sorted_lat[-1], 2)
        p99 = round(sorted_lat[min(int(n * 0.99), n - 1)], 2) if n >= 100 else round(sorted_lat[-1], 2)
    else:
        avg = min_ms = max_ms = median = jitter = p95 = p99 = 0.0

    nxdomain_ok = _check_nxdomain(ip, timeout=timeout) if alive else False
    reliability = round(len(latencies) / total * 100, 1) if total > 0 else 0.0

    return {
        "ip": ip,
        "alive": alive,
        "total_queries": total,
        "successful_queries": len(latencies),
        "failed_queries": failures,
        "reliability": reliability,
        "avg_ms": avg,
        "min_ms": min_ms,
        "max_ms": max_ms,
        "median_ms": median,
        "jitter_ms": jitter,
        "p95_ms": p95,
        "p99_ms": p99,
        "nxdomain_ok": nxdomain_ok,
        "latencies": [round(lat, 2) for lat in latencies],
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_single(resolver: Dict[str, Any], timeout: float, rounds: int) -> Dict[str, Any]:
    """Validate and update a single resolver dict in-place."""
    ip = resolver["ip"]
    successes = 0
    latencies: List[float] = []

    for _ in range(rounds):
        domain = random.choice(_TEST_DOMAINS)
        latency = _dns_query(ip, domain, timeout=timeout)
        if latency is not None:
            successes += 1
            latencies.append(latency)

    if latencies:
        resolver["avg_ms"] = round(mean(latencies), 2)
        resolver["reliability"] = round(successes / rounds * 100, 1)
        resolver["nxdomain_ok"] = _check_nxdomain(ip, timeout=timeout)
    else:
        resolver["avg_ms"] = 0.0
        resolver["reliability"] = 0.0
        resolver["nxdomain_ok"] = False

    return resolver


def _validate_batch(
    resolvers: List[Dict[str, Any]],
    max_workers: int = 50,
    timeout: float = 2.0,
    rounds: int = 2,
) -> List[Dict[str, Any]]:
    """Validate a list of resolvers in parallel.

    Resolvers that fail all queries are kept but will have avg_ms=0 and
    reliability=0, so callers can filter them out as needed.

    Args:
        resolvers: List of resolver dicts to validate.
        max_workers: Thread pool size.
        timeout: DNS timeout per query.
        rounds: Queries per resolver.

    Returns:
        The same list with avg_ms, reliability, and nxdomain_ok populated.
    """
    total = len(resolvers)
    validated: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_validate_single, r, timeout, rounds): r
            for r in resolvers
        }
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            try:
                result = future.result()
                validated.append(result)
            except Exception as exc:
                r = futures[future]
                print(
                    f"publicdns: validation error for {r.get('ip', '?')}: {exc}",
                    file=sys.stderr,
                )
                validated.append(r)

            if sys.stderr.isatty() and (done % 50 == 0 or done == total):
                print(
                    f"\r  Validating: {done}/{total} resolvers tested",
                    end="", file=sys.stderr,
                )

    if sys.stderr.isatty() and total > 0:
        print(file=sys.stderr)  # newline after progress

    return validated


def clear_cache() -> None:
    """Clear the internal HTTP page cache.

    Call this if you want to force a fresh fetch from publicdns.info
    on the next API call within the same process.
    """
    _page_cache.clear()


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

class _Colors:
    """ANSI color codes for terminal output."""

    def __init__(self) -> None:
        self.RESET = "\033[0m"
        self.BOLD = "\033[1m"
        self.DIM = "\033[2m"
        self.GREEN = "\033[32m"
        self.YELLOW = "\033[33m"
        self.RED = "\033[31m"
        self.CYAN = "\033[36m"

    def disable(self) -> None:
        """Disable colors on this instance only (does not affect other instances)."""
        for attr in list(vars(self)):
            if attr.isupper() and not attr.startswith("_"):
                setattr(self, attr, "")


def _cli_print_resolvers(resolvers: List[Dict[str, Any]], co: _Colors, limit: int = 0) -> None:
    """Print a formatted resolver table to stdout."""
    if not resolvers:
        print(f"{co.YELLOW}No resolvers found.{co.RESET}")
        return

    has_provider = any("provider" in r for r in resolvers)
    header_extra = f"  {'Provider':<14}" if has_provider else ""

    print(f" {co.BOLD}{'#':>4}  {'IP':<16} {'Country':<10} {'Avg ms':>8} {'Rel %':>7} {'NX':>4}{header_extra}{co.RESET}")
    sep_extra = f"  {'---':<14}" if has_provider else ""
    print(f" {'---':>4}  {'---':<16} {'---':<10} {'---':>8} {'---':>7} {'---':>4}{sep_extra}")

    shown = resolvers[:limit] if limit > 0 else resolvers
    for i, r in enumerate(shown, 1):
        avg = r.get("avg_ms", 0)
        rel = r.get("reliability", 0)
        nx = "OK" if r.get("nxdomain_ok", True) else "HJ"
        cc = r.get("country", "")
        cc_name = _COUNTRY_NAMES.get(cc, cc)
        if len(cc_name) > 9:
            cc_name = cc_name[:9]

        if avg > 0:
            if avg < 20:
                lat_color = co.GREEN
            elif avg < 80:
                lat_color = co.YELLOW
            else:
                lat_color = co.RED
            avg_str = f"{lat_color}{avg:>6.1f}ms{co.RESET}"
        else:
            avg_str = f"{co.DIM}{'N/A':>8}{co.RESET}"

        rel_str = f"{rel:>6.0f}%" if rel > 0 else f"{co.DIM}{'N/A':>7}{co.RESET}"
        nx_color = co.GREEN if nx == "OK" else co.RED
        nx_str = f"{nx_color}{nx:>4}{co.RESET}"

        extra = ""
        if has_provider and "provider" in r:
            extra = f"  {r['provider']:<14}"

        print(f" {i:>4}  {r['ip']:<16} {cc_name:<10} {avg_str} {rel_str} {nx_str}{extra}")

    total = len(resolvers)
    if limit > 0 and total > limit:
        print(f"\n {co.DIM}Showing {limit} of {total} resolvers.{co.RESET}")

    print()


def _cli_print_validation(result: Dict[str, Any], co: _Colors) -> None:
    """Print a single resolver validation result."""
    ip = result["ip"]
    alive = result["alive"]
    status = f"{co.GREEN}ALIVE{co.RESET}" if alive else f"{co.RED}DEAD{co.RESET}"
    print(f"\n {co.BOLD}Resolver: {ip}{co.RESET}")
    print(f" Status:      {status}")

    if alive:
        print(f" Avg Latency: {result['avg_ms']:.2f} ms")
        print(f" Reliability: {result['reliability']:.1f}%")
        nx = "OK" if result["nxdomain_ok"] else "HIJACKING"
        nx_co = co.GREEN if result["nxdomain_ok"] else co.RED
        print(f" NXDOMAIN:    {nx_co}{nx}{co.RESET}")
        print(f" Queries:     {result['queries_ok']}/{result['queries_sent']} succeeded")
    else:
        print(f" {co.RED}Server did not respond to any queries.{co.RESET}")

    print()


def _cli_print_benchmark(result: Dict[str, Any], co: _Colors) -> None:
    """Print detailed benchmark results for a single resolver."""
    ip = result["ip"]
    alive = result["alive"]
    status = f"{co.GREEN}ALIVE{co.RESET}" if alive else f"{co.RED}DEAD{co.RESET}"

    print(f"\n {co.BOLD}{co.CYAN}Benchmark: {ip}{co.RESET}")
    print(f" Status:      {status}")

    if not alive:
        print(f" {co.RED}Server did not respond to any queries.{co.RESET}\n")
        return

    print(f" Queries:     {result['successful_queries']}/{result['total_queries']} succeeded")
    print(f" Reliability: {result['reliability']:.1f}%")
    print()

    # Latency stats table
    print(f" {co.BOLD}Latency Statistics{co.RESET}")
    print(f" {'Metric':<14} {'Value':>10}")
    print(f" {'------':<14} {'-----':>10}")
    print(f" {'Average':<14} {result['avg_ms']:>8.2f}ms")
    print(f" {'Minimum':<14} {result['min_ms']:>8.2f}ms")
    print(f" {'Maximum':<14} {result['max_ms']:>8.2f}ms")
    print(f" {'Median':<14} {result['median_ms']:>8.2f}ms")
    print(f" {'Jitter (SD)':<14} {result['jitter_ms']:>8.2f}ms")
    print(f" {'P95':<14} {result['p95_ms']:>8.2f}ms")
    print(f" {'P99':<14} {result['p99_ms']:>8.2f}ms")
    print()

    # NXDOMAIN
    nx = "OK" if result["nxdomain_ok"] else "HIJACKING"
    nx_co = co.GREEN if result["nxdomain_ok"] else co.RED
    print(f" NXDOMAIN:    {nx_co}{nx}{co.RESET}")

    # Grade
    avg = result["avg_ms"]
    jitter = result["jitter_ms"]
    rel = result["reliability"]
    lat_score = max(0, 100 - avg * 1.5)
    jit_score = max(0, 100 - jitter * 5)
    rel_score = rel
    nx_score = 100 if result["nxdomain_ok"] else 0
    score = lat_score * 0.3 + jit_score * 0.2 + rel_score * 0.35 + nx_score * 0.15

    if score >= 90:
        grade_str = f"{co.GREEN}{co.BOLD}A+{co.RESET}"
    elif score >= 80:
        grade_str = f"{co.GREEN}A{co.RESET}"
    elif score >= 70:
        grade_str = f"{co.GREEN}B{co.RESET}"
    elif score >= 60:
        grade_str = f"{co.YELLOW}C{co.RESET}"
    elif score >= 50:
        grade_str = f"{co.YELLOW}D{co.RESET}"
    else:
        grade_str = f"{co.RED}F{co.RESET}"

    print(f" Score:       {score:.0f}/100  Grade: {grade_str}")
    print()
    print(f" {co.DIM}Web benchmark: https://publicdns.info/dns-gaming-benchmark.html{co.RESET}")
    print()


def main() -> None:
    """CLI entry point for publicdns-python."""
    parser = argparse.ArgumentParser(
        prog="publicdns",
        description=(
            "publicdns-python - Programmatic access to publicdns.info resolver data.\n"
            "Fetches, filters, validates, and benchmarks public DNS resolvers."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 publicdns.py --list                  # List all resolvers\n"
            "  python3 publicdns.py --list --validate       # List and validate all\n"
            "  python3 publicdns.py --country us             # US resolvers only\n"
            "  python3 publicdns.py --fastest 5              # Top 5 by latency\n"
            "  python3 publicdns.py --privacy                # Privacy-focused resolvers\n"
            "  python3 publicdns.py --validate 1.1.1.1       # Test a specific resolver\n"
            "  python3 publicdns.py --benchmark 8.8.8.8      # Full benchmark\n"
            "  python3 publicdns.py --json --fastest 10      # JSON output\n"
            "\n"
            "Source: https://publicdns.info\n"
            "Repo:   https://github.com/riankellyjn-a11y/publicdns-python"
        ),
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--list", action="store_true",
        help="List all resolvers from publicdns.info",
    )
    group.add_argument(
        "--country", metavar="CC", type=str,
        help="List resolvers for a country (ISO 3166-1 alpha-2, e.g. US, IE, DE)",
    )
    group.add_argument(
        "--fastest", metavar="N", type=int,
        help="Show the N fastest resolvers (always validated)",
    )
    group.add_argument(
        "--privacy", action="store_true",
        help="List privacy-focused resolvers",
    )
    group.add_argument(
        "--validate", metavar="IP", type=str,
        help="Validate a specific resolver IP",
    )
    group.add_argument(
        "--benchmark", metavar="IP", type=str,
        help="Benchmark a specific resolver IP with detailed stats",
    )

    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON instead of a table",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--timeout", type=float, default=2.0,
        help="DNS query timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--rounds", type=int, default=None,
        help="Number of validation/benchmark rounds (default varies by mode)",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Limit the number of results displayed (0=all)",
    )
    parser.add_argument(
        "--do-validate", action="store_true", dest="do_validate",
        help="Validate resolvers when using --list or --country (off by default for speed)",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"publicdns-python {__version__}",
    )

    args = parser.parse_args()

    co = _Colors()
    if args.no_color or args.json or not sys.stdout.isatty():
        co.disable()

    timeout = max(0.5, min(args.timeout, 30.0))

    # --- Dispatch ---

    if args.list:
        rounds = args.rounds if args.rounds else 2
        if not args.json:
            print(f"\n {co.BOLD}publicdns-python v{__version__}{co.RESET}")
            print(f" {co.DIM}Source: {_BASE_URL}{co.RESET}")
            msg = " with validation" if args.do_validate else ""
            print(f" {co.DIM}Fetching resolvers{msg}...{co.RESET}\n")

        resolvers = get_resolvers(validate=args.do_validate, timeout=timeout, rounds=rounds)

        if args.json:
            print(json.dumps(resolvers, indent=2))
        else:
            _cli_print_resolvers(resolvers, co, limit=args.limit)
            print(f" {co.DIM}Total: {len(resolvers)} resolvers{co.RESET}")
            if not args.do_validate:
                print(f" {co.DIM}Tip: add --do-validate to test each resolver.{co.RESET}")
            print()

    elif args.country:
        rounds = args.rounds if args.rounds else 2
        cc = args.country.upper()
        cc_name = _COUNTRY_NAMES.get(cc, cc)
        if not args.json:
            print(f"\n {co.BOLD}publicdns-python v{__version__}{co.RESET}")
            print(f" {co.DIM}Resolvers for {cc_name} ({cc}){co.RESET}\n")

        resolvers = get_resolvers_by_country(
            cc, validate=args.do_validate, timeout=timeout, rounds=rounds,
        )

        if args.json:
            print(json.dumps(resolvers, indent=2))
        else:
            _cli_print_resolvers(resolvers, co, limit=args.limit)
            print(f" {co.DIM}Total: {len(resolvers)} resolvers in {cc_name}{co.RESET}")
            print()

    elif args.fastest is not None:
        n = max(1, args.fastest)
        rounds = args.rounds if args.rounds else 3
        if not args.json:
            print(f"\n {co.BOLD}publicdns-python v{__version__}{co.RESET}")
            print(f" {co.DIM}Finding {n} fastest resolvers (live test)...{co.RESET}\n")

        resolvers = get_fastest(n=n, timeout=timeout, rounds=rounds)

        if args.json:
            print(json.dumps(resolvers, indent=2))
        else:
            _cli_print_resolvers(resolvers, co)

    elif args.privacy:
        rounds = args.rounds if args.rounds else 3
        if not args.json:
            print(f"\n {co.BOLD}publicdns-python v{__version__}{co.RESET}")
            print(f" {co.DIM}Privacy-focused DNS resolvers{co.RESET}\n")

        resolvers = get_privacy_resolvers(validate=args.do_validate, timeout=timeout, rounds=rounds)

        if args.json:
            print(json.dumps(resolvers, indent=2))
        else:
            _cli_print_resolvers(resolvers, co, limit=args.limit)

    elif args.validate:
        rounds = args.rounds if args.rounds else 3
        if not args.json:
            print(f"\n {co.BOLD}publicdns-python v{__version__}{co.RESET}")

        result = validate_resolver(args.validate, timeout=timeout, rounds=rounds)

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            _cli_print_validation(result, co)

    elif args.benchmark:
        rounds = args.rounds if args.rounds else 5
        if not args.json:
            print(f"\n {co.BOLD}publicdns-python v{__version__}{co.RESET}")

        result = benchmark_resolver(args.benchmark, rounds=rounds, timeout=timeout)

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            _cli_print_benchmark(result, co)


if __name__ == "__main__":
    main()
