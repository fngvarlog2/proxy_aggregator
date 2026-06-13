#!/usr/bin/env python3
"""
Proxy Aggregator & Validator (Async v2.0)
Aggregates V2Ray, Shadowsocks, and Trojan configurations, deduplicates them,
validates them via async TCP handshakes, measures latency, and sorts the output.
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
    "+5sWf3ePcSLo3YTVk",
    "+3qTKfGn3u1EzOWQ8",
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
MAX_CONCURRENT_CHECKS = 100  # Semaphores keep your network from choking
CONNECT_TIMEOUT = 2.5  # Seconds per proxy test
REQUEST_TIMEOUT = 10.0  # Seconds for HTTP scraping

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── HELPERS ───────────────────────────────────────────────────────────────────


async def _http_get(client: httpx.AsyncClient, url: str) -> str | None:
    """Async GET request with explicit user agent."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        response = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            return response.text
    except Exception as exc:
        log.warning("Scrape failed for %s — %s", url, exc)
    return None


def _try_base64_decode(text: str) -> str:
    stripped = text.strip()
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
    pattern = (
        r"(?:" + "|".join(re.escape(p) for p in SUPPORTED_PROTOCOLS) + r')[^\s<>"\'\\]+'
    )
    raw = re.findall(pattern, text)
    cleaned = []
    for uri in raw:
        uri = re.sub(r'[&;,\'"]+$', "", uri)
        cleaned.append(uri)
    return cleaned

#parse host and port from URI, return None if invalid
def _parse_host_port(uri: str) -> tuple[str, int] | None:
    try:
        if uri.startswith("vmess://"):
            b64_part = uri[len("vmess://") :].split("#")[0]
            try:
                padded = b64_part + "=" * (-len(b64_part) % 4)
                payload = base64.b64decode(padded).decode("utf-8", errors="replace")
                obj = json.loads(payload)
                host = str(obj.get("add", ""))
                port = int(obj.get("port", 0))
                if host and port:
                    return host, port
            except Exception:
                pass
            return None

        parsed = urlparse(uri)
        host = parsed.hostname
        port = parsed.port

        if (not host or not port) and "@" in uri:
            try:
                clean_net = uri.split("#")[0].split("@")[-1]
                if ":" in clean_net:
                    h_part, p_part = clean_net.split(":")[:2]
                    p_part = int(re.sub(r"\D", "", p_part))
                    return h_part.strip("[]"), p_part
            except Exception:
                pass

        if not host or not port:
            return None

        return host.strip("[]"), int(port)
    except Exception:
        return None


# ── ASYNC SCRAPING ────────────────────────────────────────────────────────────


async def fetch_telegram(client: httpx.AsyncClient, channel: str) -> list[str]:
    url = f"https://t.me/s/{channel}"
    html = await _http_get(client, url)
    if not html:
        return []
    uris = [unquote(u) for u in _extract_uris(html)]
    log.info("Telegram → Found %d URIs in @%s", len(uris), channel)
    return uris


async def fetch_github(client: httpx.AsyncClient, url: str) -> list[str]:
    text = await _http_get(client, url)
    if not text:
        return []
    text = _try_base64_decode(text)
    uris = _extract_uris(text)
    log.info("GitHub   → Found %d URIs from %s", len(uris), url[:45] + "...")
    return uris


# ── ASYNC VALIDATION ──────────────────────────────────────────────────────────


async def test_config(
    uri: str, semaphore: asyncio.Semaphore
) -> tuple[str, float] | None:
    """
    Validates a single proxy config using a lightweight non-blocking TCP connection.
    Returns (uri, latency_ms) if valid, or None if it fails.
    """
    hp = _parse_host_port(uri)
    if not hp or ":" in hp[0]:  # Strict IPv4 exclusion rule retained
        return None
    host, port = hp

    async with semaphore:
        start_time = time.perf_counter()
        try:
            # Non-blocking connection attempt
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
            )
            latency = (time.perf_counter() - start_time) * 1000
            writer.close()
            await writer.wait_closed()
            return uri, latency
        except Exception:
            return None


# ── ORCHESTRATION ─────────────────────────────────────────────────────────────


async def main():
    t0 = time.time()
    log.info("═" * 60)
    log.info("Proxy Aggregator v2.0 (Async Core Starting...)")
    log.info("═" * 60)

    # 1. Scrape all sources concurrently
    all_uris = []
    async with httpx.AsyncClient(follow_redirects=True) as client:
        tg_tasks = [fetch_telegram(client, chan) for chan in TELEGRAM_CHANNELS]
        gh_tasks = [fetch_github(client, url) for url in GITHUB_SOURCES]

        results = await asyncio.gather(*tg_tasks, *gh_tasks)
        for uris in results:
            all_uris.extend(uris)

    unique_uris = list(set(all_uris))
    log.info("Total unique URIs collected: %d", len(unique_uris))

    if not unique_uris:
        log.warning("No URIs found to validate.")
        return

    # 2. Validate concurrently with a connection throttle
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    val_tasks = [test_config(uri, semaphore) for uri in unique_uris]

    log.info("Validating with max concurrency pool of %d...", MAX_CONCURRENT_CHECKS)
    validation_results = await asyncio.gather(*val_tasks)

    # Filter out failed checks and sort by latency (Fastest First)
    valid_nodes = [res for res in validation_results if res is not None]
    valid_nodes.sort(key=lambda x: x[1])

    log.info(
        "Valid configs after TCP check: %d / %d", len(valid_nodes), len(unique_uris)
    )

    # 3. Format and output results
    current_time = time.strftime("%Y-%m-%d_%H:%M", time.localtime())
    status_node = f"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@127.0.0.1:1234#⏱️_Updated:_{current_time}"

    # Reassemble the final URI array using the sorted values
    final_configs = [status_node] + [node[0] for node in valid_nodes]
    plain_text = "\n".join(final_configs) + "\n"

    # Write files out
    with open(OUTPUT_PLAIN, "w", encoding="utf-8") as f:
        f.write(plain_text)

    encoded = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")
    with open(OUTPUT_BASE64, "w", encoding="utf-8") as f:
        f.write(encoded)

    elapsed = time.time() - t0
    log.info("Done in %.1f seconds. Outputs successfully generated.", elapsed)
    log.info("═" * 60)


if __name__ == "__main__":
    asyncio.run(main())
