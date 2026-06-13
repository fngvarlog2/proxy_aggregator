#!/usr/bin/env python3
"""
Proxy Aggregator & Validator (Async v2.2 - TCP Reachability Edition)
Aggregates V2Ray, Shadowsocks, and Trojan configurations, deduplicates them,
validates them via TCP handshake (httpx does NOT support vless/vmess/trojan
as proxy protocols — so we do reachability checks instead), measures latency,
and sorts the output.
"""

import asyncio
import base64
import json
import logging
import re
import time
from urllib.parse import unquote, urlparse

import httpx

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
TELEGRAM_CHANNELS = [
    "ConfigsHUB2",
    "5sWf3ePcSLo3YTVk",   # removed leading '+' — t.me/s/ doesn't accept it
    "3qTKfGn3u1EzOWQ8",
    "dailyv2rayCF",
    "V2rayNGn",
]

GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1",
]

OUTPUT_PLAIN = "sub.txt"
OUTPUT_BASE64 = "sub_base64.txt"

SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://")

# How many TCP checks run in parallel
MAX_CONCURRENT_CHECKS = 100

# Seconds to wait for TCP connection to succeed
TCP_TIMEOUT = 3.0

# Seconds for HTTP scraping requests
REQUEST_TIMEOUT = 10.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── HELPERS ───────────────────────────────────────────────────────────────────

async def _http_get(client: httpx.AsyncClient, url: str) -> str | None:
    """Async GET with a browser-like user-agent."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        response = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            return response.text
        log.debug("HTTP %d for %s", response.status_code, url)
    except Exception as exc:
        log.warning("Scrape failed for %s — %s", url, exc)
    return None


def _try_base64_decode(text: str) -> str:
    """Return decoded text if it contains proxy URIs, else return original."""
    stripped = text.strip()
    # Already plain-text URIs
    if any(p in stripped for p in SUPPORTED_PROTOCOLS):
        return stripped
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        if any(p in decoded for p in SUPPORTED_PROTOCOLS):
            return decoded
    except Exception:
        pass
    return stripped


def _extract_uris(text: str) -> list[str]:
    """Pull every proxy URI out of arbitrary text."""
    pattern = (
        r"(?:"
        + "|".join(re.escape(p) for p in SUPPORTED_PROTOCOLS)
        + r')[^\s<>"\'\\]+'
    )
    raw = re.findall(pattern, text)
    cleaned = []
    for uri in raw:
        # Strip trailing punctuation that sometimes gets included
        uri = re.sub(r'[&;,\'"]+$', "", uri)
        cleaned.append(uri)
    return cleaned


def _parse_host_port(uri: str) -> tuple[str, int] | None:
    """
    Extract (host, port) from any supported URI.
    Returns None if parsing fails or host is IPv6 (we skip those for simplicity).
    """
    try:
        if uri.startswith("vmess://"):
            b64_part = uri[len("vmess://"):].split("#")[0]
            try:
                padded = b64_part + "=" * (-len(b64_part) % 4)
                payload = base64.b64decode(padded).decode("utf-8", errors="replace")
                obj = json.loads(payload)
                host = str(obj.get("add", "")).strip()
                port = int(obj.get("port", 0))
                if host and port:
                    return host, port
            except Exception:
                pass
            return None

        parsed = urlparse(uri)
        host = parsed.hostname
        port = parsed.port

        # Fallback: manual parse after the last '@'
        if (not host or not port) and "@" in uri:
            try:
                net_part = uri.split("#")[0].split("@")[-1]
                # Handle IPv6 brackets like [::1]:443
                if net_part.startswith("["):
                    bracket_end = net_part.index("]")
                    host = net_part[1:bracket_end]
                    port_str = net_part[bracket_end + 2:]  # skip ']:' 
                    port = int(re.sub(r"\D", "", port_str))
                elif ":" in net_part:
                    h_part, p_part = net_part.rsplit(":", 1)
                    host = h_part.strip("[]")
                    port = int(re.sub(r"\D", "", p_part))
            except Exception:
                pass

        if not host or not port:
            return None

        # Skip IPv6 addresses (contain ':')
        host = host.strip("[]")
        if ":" in host:
            return None

        return host, int(port)

    except Exception:
        return None


# ── ASYNC SCRAPING ────────────────────────────────────────────────────────────

async def fetch_telegram(client: httpx.AsyncClient, channel: str) -> list[str]:
    url = f"https://t.me/s/{channel}"
    html = await _http_get(client, url)
    if not html:
        return []
    uris = [unquote(u) for u in _extract_uris(html)]
    log.info("Telegram → %3d URIs  @%s", len(uris), channel)
    return uris


async def fetch_github(client: httpx.AsyncClient, url: str) -> list[str]:
    text = await _http_get(client, url)
    if not text:
        return []
    text = _try_base64_decode(text)
    uris = _extract_uris(text)
    log.info("GitHub   → %3d URIs  %s", len(uris), url[:60])
    return uris


# ── TCP REACHABILITY CHECK ────────────────────────────────────────────────────
#
# WHY NOT httpx proxy routing?
# httpx only supports http://, https://, socks4://, socks5:// as proxy URLs.
# vless://, vmess://, trojan://, ss:// are NOT supported and will raise errors.
#
# The correct production approach is:
#   1. Write the config to a temp file
#   2. Spawn xray-core / sing-box with that config (local SOCKS5 on a random port)
#   3. Route httpx through socks5://127.0.0.1:<port>
#   4. Kill the subprocess after the test
#
# For a GitHub Actions environment without xray/sing-box installed, a fast TCP
# handshake is a good proxy (pun intended) for "server is alive and reachable".
# Dead IPs, blocked ports, and wrong addresses all fail here.

async def tcp_check(
    uri: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, float] | None:
    """
    Open a TCP connection to the proxy host:port and measure round-trip time.
    Returns (uri, latency_ms) on success, None on failure.
    """
    hp = _parse_host_port(uri)
    if hp is None:
        return None

    host, port = hp

    async with semaphore:
        start = time.perf_counter()
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
            latency_ms = (time.perf_counter() - start) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return uri, latency_ms
        except Exception:
            return None


# ── ORCHESTRATION ─────────────────────────────────────────────────────────────

async def main() -> None:
    t0 = time.time()
    log.info("═" * 60)
    log.info("Proxy Aggregator v2.2  (TCP Reachability Engine)")
    log.info("═" * 60)

    # ── 1. Scrape all sources concurrently ────────────────────────────────────
    all_uris: list[str] = []
    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = (
            [fetch_telegram(client, ch) for ch in TELEGRAM_CHANNELS]
            + [fetch_github(client, url) for url in GITHUB_SOURCES]
        )
        results = await asyncio.gather(*tasks)

    for batch in results:
        all_uris.extend(batch)

    unique_uris = list(set(all_uris))
    log.info("Unique URIs collected : %d", len(unique_uris))

    if not unique_uris:
        log.warning("No URIs discovered — writing empty output files.")
        for path in (OUTPUT_PLAIN, OUTPUT_BASE64):
            open(path, "w").close()
        return

    # ── 2. TCP reachability checks ────────────────────────────────────────────
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    log.info("Running TCP checks on %d nodes (timeout=%.1fs)…", len(unique_uris), TCP_TIMEOUT)

    check_tasks = [tcp_check(uri, semaphore) for uri in unique_uris]
    raw_results = await asyncio.gather(*check_tasks)

    valid: list[tuple[str, float]] = [r for r in raw_results if r is not None]
    valid.sort(key=lambda x: x[1])   # fastest first

    log.info("Reachable nodes : %d / %d", len(valid), len(unique_uris))

    # ── 3. Write outputs ──────────────────────────────────────────────────────
    timestamp = time.strftime("%Y-%m-%d_%H:%M", time.localtime())

    # Build a valid ss:// status placeholder (chacha20-ietf-poly1305 / password)
    userinfo = base64.b64encode(b"chacha20-ietf-poly1305:password").decode()
    status_node = f"ss://{userinfo}@127.0.0.1:1234#Updated_{timestamp}"

    final_configs = [status_node] + [uri for uri, _ in valid]
    plain_text = "\n".join(final_configs) + "\n"

    with open(OUTPUT_PLAIN, "w", encoding="utf-8") as f:
        f.write(plain_text)

    encoded = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")
    with open(OUTPUT_BASE64, "w", encoding="utf-8") as f:
        f.write(encoded)

    elapsed = time.time() - t0
    log.info("Done in %.1f s — wrote %s and %s", elapsed, OUTPUT_PLAIN, OUTPUT_BASE64)
    log.info("═" * 60)


if __name__ == "__main__":
    asyncio.run(main())