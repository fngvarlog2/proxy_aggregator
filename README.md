# Strict IPv4 Proxy Aggregator & Validator

An automated proxy configuration scraper, deduplicator, and validator designed to maintain a high-quality subscription feed. This project automatically collects configurations from public Telegram channels and GitHub repositories every 30 minutes, filters out inactive nodes via parallel TCP handshakes, enforces a strict IPv4-only policy, and exports optimized subscription feeds.

---

##  Active Subscription Feeds

To use these feeds in your proxy client (e.g., **v2rayNG**, **NekoBox**, **NekoRay**, **v2rayN**), copy one of the **Raw links** below and paste it into your app's subscription settings.

| Feed Type | Format | Public Raw Subscription URL |
| :--- | :--- | :--- |
| **Base64 Encoded** *(Recommended)* | Scrambled | `https://raw.githubusercontent.com/fhcpvarlog/proxy-aggregator/main/sub_base64.txt` |
| **Plaintext List** | Raw URIs | `https://raw.githubusercontent.com/fhcpvarlog/proxy-aggregator/main/sub.txt` |

---

##  Key Features

* **Strict IPv4 Execution:** Automatically resolves and filters out dual-stack IPv6 endpoints to ensure compatibility with network environments where IPv6 is restricted or blocked.
* **Automated Cron Sync:** Powered entirely by GitHub Actions, executing systematically every 30 minutes with zero downtime or hosting costs.
* **High-Speed Parallel Handshakes:** Leverages a concurrent multi-threaded worker pool (`ThreadPoolExecutor`) to test thousands of collected nodes within seconds.
* **Universal Protocol Support:** Extracts and validates `vless://`, `vmess://`, `trojan://`, and `ss://` subscription string patterns.
* **Clean Artifact Diffs:** Only commits updates to your repository if the validation output changes, keeping your commit history light and efficient.

---

##  Project Structure

```text
├── .github/workflows/auto_fetch.yml   # The GitHub Actions automation configuration
├── scraper.py                         # Core multi-threaded Python engine
├── requirements.txt                   # Execution dependencies (requests)
├── sub.txt                            # Verified plaintext configurations output
└── sub_base64.txt                     # Verified Base64 subscription string output

If you want to customize the scraped feeds, open scraper.py and modify the global target blocks:


TELEGRAM_CHANNELS = [
    "v2rayng_org",
    "Proxy_Center",
    # Add your custom channel names here...
]

GITHUB_SOURCES = [
    "[https://raw.githubusercontent.com/.../sub.txt](https://raw.githubusercontent.com/.../sub.txt)",
    # Add your custom raw txt URLs here...
]

Tuning Performance

You can change execution mechanics depending on your connection tolerances:

    MAX_WORKERS = 50: Change this number to alter thread concurrency.

    CONNECT_TIMEOUT = 2.5: Lower this threshold (e.g., to 1.5) to drop high-latency endpoints faster and speed up runtime intervals.
