# 🌐 Proxy Aggregator

An automated proxy collector and validator that scrapes **V2Ray**, **Shadowsocks**, **VLESS**, and **Trojan** configurations from public Telegram channels and GitHub sources, validates them via TCP reachability, and publishes sorted subscription files every 2 hours.

---

## 📦 Output Files

| File | Description |
|---|---|
| `sub.txt` | Plain-text list of working proxies, sorted by latency |
| `sub_base64.txt` | Base64-encoded version for apps that require it |

---

## 🚀 Quick Subscribe

Copy one of the links below into your proxy client:

```
https://raw.githubusercontent.com/<YOUR_USERNAME>/<YOUR_REPO>/main/sub.txt
```
```
https://raw.githubusercontent.com/<YOUR_USERNAME>/<YOUR_REPO>/main/sub_base64.txt
```

> Replace `<YOUR_USERNAME>` and `<YOUR_REPO>` with your actual GitHub username and repository name.

### Compatible Clients

| Platform | App |
|---|---|
| Windows | v2rayN, Nekoray |
| macOS | V2RayXS, Clash Verge |
| Android | v2rayNG, Clash Meta |
| iOS | Shadowrocket, Streisand |
| Linux | Nekoray, sing-box |

---

## ⚙️ How It Works

```
Telegram Channels ──┐
                     ├──► Scrape URIs ──► Deduplicate ──► TCP Check ──► Sort by latency ──► sub.txt
GitHub Sources ──────┘
```

1. **Scrape** — fetches proxy URIs from configured Telegram channels and GitHub raw files
2. **Decode** — handles both plain-text and Base64-encoded subscription sources
3. **Deduplicate** — removes exact duplicate URIs
4. **TCP Validate** — opens a real TCP connection to each server to confirm it is reachable
5. **Sort** — orders results fastest-first by TCP latency
6. **Publish** — commits `sub.txt` and `sub_base64.txt` back to the repository

> **Note:** Validation uses TCP handshake, not full proxy routing. A passing node means the server is online and the port is open — not that the protocol credentials are valid.

---

## 🔄 Update Schedule

Proxies are refreshed automatically via GitHub Actions:

- **Every 2 hours** (scheduled)
- **On demand** — trigger manually from the Actions tab

---

## 🛠️ Setup (Fork & Run)

### 1. Fork this repository

Click **Fork** in the top-right corner of this page.

### 2. Enable GitHub Actions

Go to your fork → **Actions** tab → click **"I understand my workflows, enable them"**

### 3. Set workflow permissions

Go to **Settings → Actions → General → Workflow permissions**
Select **Read and write permissions** → Save

### 4. Trigger the first run

Go to **Actions → Auto Update Proxies → Run workflow**

After ~1 minute, `sub.txt` and `sub_base64.txt` will appear in your repository.

---

## ✏️ Customization

Edit `main.py` to change sources or behavior:

### Add/remove Telegram channels

```python
TELEGRAM_CHANNELS = [
    "YourChannelName",   # without @ or +
    ...
]
```

### Add/remove GitHub sources

```python
GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/user/repo/main/sub.txt",
    ...
]
```

### Tune validation

```python
MAX_CONCURRENT_CHECKS = 100   # parallel TCP checks
TCP_TIMEOUT = 3.0             # seconds per check
```

---

## 📁 Project Structure

```
├── main.py                          # Aggregator & validator script
├── sub.txt                          # Output: plain-text proxies
├── sub_base64.txt                   # Output: Base64-encoded proxies
└── .github/
    └── workflows/
        └── update.yml               # GitHub Actions workflow
```

---

## 📋 Requirements

Only needed if running locally:

```bash
pip install "httpx[socks]"
```

Run manually:

```bash
python main.py
```

---

## ⚠️ Disclaimer

This project aggregates publicly available proxy configurations for educational and research purposes. The author does not host, operate, or endorse any of the proxy servers listed. Use at your own risk and in compliance with the laws of your country.

---

## 📄 License

MIT License — free to use, fork, and modify.
