# 🛡️Wi‑Fi Intrusion Detection (WIDS)

## 🏷️ Project Badges
![Platform](https://img.shields.io/badge/platform-ESP8266%20%7C%20Linux-blue)
![Language](https://img.shields.io/badge/language-Python%20%7C%20Arduino-green)
![Security](https://img.shields.io/badge/focus-Wi--Fi%20Security-red)
![License](https://img.shields.io/badge/license-Educational-lightgrey)
![Status](https://img.shields.io/badge/status-Active-success)

---

A defensive Wi‑Fi Intrusion Detection Script that detects deauthentication storms and evil‑twin activity from 802.11 management frames. Emits structured JSON alerts suitable for logging pipelines or SIEM ingestion.

## ⚖️ Defensive Focus & Ethics
- Designed for authorized monitoring and protection of networks you administer.
- ❌ Do not use this project to attack, disrupt, or intrude into any network.
- ✅ Comply with local laws, organizational policies, and regulatory requirements.

## ✨ Features
- ⚡ Real‑time detection of deauth/disassoc storms with configurable thresholds.
- 🧬 Evil‑twin detection by tracking SSID→BSSID mappings and crypto consistency.
- 🎯 Live capture (`--interface`) or offline PCAP analysis (`--pcap`).
- 📤 JSON alerts to stdout for easy processing.

## 🧩 Requirements
- Python 3.9+
- `scapy` (see `requirements.txt`)
- For live capture: Linux and a Wi‑Fi adapter/driver that supports monitor mode and management frame capture.

## 📦 Installation
```bash
python -m venv .venv
. .venv/bin/activate   # On Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 📡 Adapter Setup (Live Monitoring)
Monitor mode is typically required for live 802.11 management frame capture.
```bash
# Example using iw (Linux)
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
# Or use airmon-ng to create wlan0mon
sudo airmon-ng start wlan0
```
Use the monitor interface (e.g., `wlan0mon`) with the tool.

## ▶️ Usage
Live capture:
```bash
python wids.py --interface wlan0mon
```
Offline PCAP:
```bash
python wids.py --pcap path/to/capture.pcap
```
Threshold tuning:
```bash
python wids.py --interface wlan0mon \
  --deauth-window 5 \
  --deauth-threshold 30 \
  --per-target-threshold 10 \
  --allowed-bssid-per-ssid 2
```

## 🚨 Alert Format Examples
Deauth storm:
```json
{"type":"deauth_attack","severity":"high","ts":1730000000.0,
 "details":{"attacker":"aa:bb:cc:dd:ee:ff","bssid":"11:22:33:44:55:66",
 "global_rate":35,"attacker_rate":35,"target_rate":12,"window_seconds":5}}
```
Evil‑twin crypto mismatch:
```json
{"type":"evil_twin_crypto_mismatch","severity":"high","ts":1730000000.0,
 "details":{"ssid":"CorpWiFi","cryptos":["OPEN","WPA2/RSN"],
 "bssid_map":{"11:22:33:44:55:66":"WPA2/RSN","aa:bb:cc:dd:ee:ff":"OPEN"}}}
```

## 🧠 Architecture Overview
- Entry point and CLI: `wids.py:217` (`main`) handles `--interface`/`--pcap`.
- Pipeline: `wids.py:185` (`WIDS.handle_packet`) routes packets to detectors.
- Deauth detection: `wids.py:89` (`DeauthDetector`) counts deauth/disassoc per window, attacker, and target.
- Evil‑twin detection: `wids.py:141` (`EvilTwinDetector`) tracks SSID→BSSID, channel, and crypto; flags multiplicity and crypto mismatches.
- Utilities: SSID `wids.py:45`, channel `wids.py:58`, crypto `wids.py:69`.

## 🧪 Lab‑Safe Testing
- Offline validation with known PCAPs containing deauth/disassoc and beacon frames:
```bash
python wids.py --pcap test_samples/deauth_storm.pcap
python wids.py --pcap test_samples/evil_twin_crypto_mismatch.pcap
```
- Live tests only in an isolated RF lab:
  - Stand up two APs with the same SSID but different encryption to trigger crypto mismatch.
  - Do not send deauth frames against real users; use test clients in isolation.

## 🧩 Extending
- Add detectors for probe anomalies, beacon flooding, or association spoofing.
- Integrate alert sink with file logging, syslog, or webhooks.
- Persist baseline SSID/BSSID/channel/crypto profiles and alert on deviations.

## 🛠️ Troubleshooting
- No alerts in live mode: verify monitor interface, driver support, and that management frames are captured.
- Permission errors: run with sufficient privileges for raw capture.
- Windows note: most adapters/drivers do not support monitor mode on Windows; prefer Linux.

-----

- ## 📡 ESP8266 Wi-Fi Intrusion Detection (WIDS) – Arduino (.ino)
 * ESP8266 Wi-Fi Intrusion Detection System (WIDS)
 * Passive monitor-mode sniffer
 * Detects deauthentication / disassociation floods
 * Defensive & educational use only

-----

## 🛡️ Legal Disclaimer

This project is intended **strictly for defensive security, educational, and research purposes**.

By using this software, you agree that:
- You will only monitor networks that you **own or have explicit authorization** to test.
- You will **not** use this tool to disrupt, attack, or spy on users or networks.
- You understand that misuse of wireless monitoring tools may violate local laws and regulations.

The author(s) assume **no liability** for misuse, damage, or legal consequences resulting from the use of this software.

⚠️ **Unauthorized monitoring of Wi-Fi networks is illegal in many countries.**

-----
## 🔒 Authorized Use Only
This project is provided for defensive monitoring and educational purposes. Use only on networks you are authorized to administer.

