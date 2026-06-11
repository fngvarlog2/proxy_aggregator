#!/usr/bin/env python3
"""
e
Proxy Aggregator & Validator (Strict IPv4 Edition)
Aggregates V2Ray, Shadowsocks, and Trojan proxy configurations from public
Telegram channels and GitHub sources, deduplicates them, validates via TCP
handshake using STRICT IPv4 resolution, and outputs subscription files.
"""

import re
import socket
import base64
import time
import json
import logging
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  ← Edit these lists to add or remove your channels and sources
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
MAX_WORKERS = 50
CONNECT_TIMEOUT = 2.5  # seconds per TCP test
RETRY_PER_SOURCE = 1  # extra attempts on transient error
REQUEST_TIMEOUT = 10  # seconds for HTTP requests
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── helpers ───────────────────────────────────────────────────────────────────


def _http_get(url: str, retries: int = RETRY_PER_SOURCE) -> str | None:
    """GET a URL, return text or None on failure."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            return r.text
        except requests.RequestException as exc:
            log.warning(
                "  [%d/%d] GET failed for %s — %s", attempt + 1, retries + 1, url, exc
            )
            if attempt < retries:
                time.sleep(1)
    return None


def _try_base64_decode(text: str) -> str:
    """Decode text if it's a Base64 subscription list."""
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
    """Pull all supported proxy URIs from raw content blocks."""
    pattern = (
        r"(?:" + "|".join(re.escape(p) for p in SUPPORTED_PROTOCOLS) + r')[^\s<>"\'\\]+'
    )
    raw = re.findall(pattern, text)
    cleaned = []
    for uri in raw:
        uri = re.sub(r'[&;,\'"]+$', "", uri)
        cleaned.append(uri)
    return cleaned


# ── source fetchers ───────────────────────────────────────────────────────────


def fetch_telegram(channel: str) -> list[str]:
    """Scrape a Telegram channel public preview page for proxy URIs."""
    url = f"https://t.me/s/{channel}"
    log.info("Telegram  → %s", url)
    html = _http_get(url)
    if not html:
        return []
    uris = _extract_uris(html)
    uris = [unquote(u) for u in uris]
    log.info("  Found %d URIs in @%s", len(uris), channel)
    return uris


def fetch_github(url: str) -> list[str]:
    """Fetch a raw GitHub subscription file."""
    log.info("GitHub    → %s", url)
    text = _http_get(url)
    if not text:
        return []
    text = _try_base64_decode(text)
    uris = _extract_uris(text)
    log.info("  Found %d URIs from %s", len(uris), url)
    return uris


# ── TCP validation ────────────────────────────────────────────────────────────


def _parse_host_port(uri: str) -> tuple[str, int] | None:
    """Extract (host, port) from standard and non-standard proxy URIs."""
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

        # Fallback handling for messy/unpadded configurations (especially some legacy ss:// links)
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


def test_config(uri: str) -> bool:
    """
    Return True if the proxy endpoint accepts a basic TCP handshake loop.
    Strictly filters out and ignores IPv6 endpoints or dual-stack IPv6 records.
    """
    hp = _parse_host_port(uri)
    if not hp:
        return False
    host, port = hp

    # Skip if the raw host is explicitly a literal IPv6 address
    if ":" in host:
        return False

    try:
        # Force DNS resolution to ONLY look up IPv4 (AF_INET) addresses
        addr_info = socket.getaddrinfo(
            host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        ipv4_address = addr_info[0][4][0]
    except Exception:
        return False

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((ipv4_address, port))
        return True
    except (OSError, socket.timeout):
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ── orchestration ─────────────────────────────────────────────────────────────


def collect_all() -> set[str]:
    """Fetch from all sources and return a deduplicated set of URIs."""
    all_uris: list[str] = []

    for channel in TELEGRAM_CHANNELS:
        all_uris.extend(fetch_telegram(channel))

    for url in GITHUB_SOURCES:
        all_uris.extend(fetch_github(url))

    unique = set(all_uris)
    log.info("Total unique URIs collected: %d", len(unique))
    return unique


def validate_all(uris: set[str]) -> list[str]:
    """TCP-test every URI in parallel; return sorted list of passing ones."""
    log.info(
        "Validating %d configs with %d workers (timeout=%.1fs) [IPv4 Force Mode Enabled] …",
        len(uris),
        MAX_WORKERS,
        CONNECT_TIMEOUT,
    )

    valid: list[str] = []
    uri_list = list(uris)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_uri = {pool.submit(test_config, u): u for u in uri_list}
        for future in as_completed(future_to_uri):
            uri = future_to_uri[future]
            try:
                if future.result():
                    valid.append(uri)
            except Exception as exc:
                log.debug("Validation error for %s — %s", uri, exc)

    log.info("Valid configs after TCP check: %d / %d", len(valid), len(uris))
    return sorted(valid)


def write_outputs(valid_configs: list[str]) -> None:
    """Write output payload feeds directly out onto destination assets."""
    # ── TIMESTAMP TRICK ──────────────────────────────────────────────────────
    # Create a harmless fake configuration string that serves as a text notice
    current_time = time.strftime("%Y-%m-%d_%H:%M", time.localtime())
    status_node = f"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@127.0.0.1:1234#⏱️_Updated:_{current_time}"

    # Place the timestamp node at the very top of your verified list
    final_list = [status_node] + valid_configs
    # ___________________________________________________________________________

    plain_text = "\n".join(final_list) + "\n"

    with open(OUTPUT_PLAIN, "w", encoding="utf-8") as f:
        f.write(plain_text)
    log.info("Written -> %s (%d lines)", OUTPUT_PLAIN, len(final_list))

    encoded = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")
    with open(OUTPUT_BASE64, "w", encoding="utf-8") as f:
        f.write(encoded)
    log.info("Written -> %s", OUTPUT_BASE64)


def main() -> None:
    t0 = time.time()
    log.info("═" * 60)
    log.info("Proxy Aggregator starting …")
    log.info("═" * 60)

    # 1. Grab everything (~1444 raw nodes)
    raw = collect_all()
    if not raw:
        log.warning("No URIs collected — check source availability.")
        return

    # 2. Keep only the working IPv4 nodes (~50 nodes)
    valid = validate_all(raw)

    # 3. Overwrite the files with just the clean, working data
    if not valid:
        log.warning("No configs passed TCP validation.")
    else:
        write_outputs(valid)

    elapsed = time.time() - t0
    log.info("Done in %.1f seconds. Valid configs: %d", elapsed, len(valid))
    log.info("═" * 60)


if __name__ == "__main__":
    main()
