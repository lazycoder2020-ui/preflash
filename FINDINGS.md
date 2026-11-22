# What preflash found in 249 public ESP32 / ESP8266 projects

*November 2026. Repo names are deliberately not published. Notify owners privately before any public write-up.*

## Method

- Searched GitHub for 12 hobbyist IoT topics ("esp32 mqtt", "esp8266 home automation",
  "esp32 telegram bot", "esp32 blynk", "nodemcu iot", ...): **359 repos**, forks excluded.
- **249** of those contained firmware source (`.ino/.cpp/.c/.h`) and were scanned.
  Third-party `lib/` and `libraries/` folders were skipped.
- The same repos were scanned with **gitleaks** (v8, default rules) for comparison.
- 60 random high-severity findings were checked by hand: **57 were real (95%)**. The 3 false
  positives (MQTT client IDs and usernames) were fixed in the rules afterwards.

## Results

| Issue | Repos affected |
|---|---|
| At least one high/critical issue | **98 / 249 (39%)** |
| Hard-coded Wi-Fi password | 56 (22%) |
| Web control panel with no login | 48 (19%) |
| MQTT with no encryption | 38 (15%) |
| Hard-coded API key / token (Blynk, Firebase, Telegram, ThingsBoard...) | 35 (14%) |
| TLS certificate checks turned off (`setInsecure()`) | 19 (8%) |
| OTA firmware updates open to anyone | 13 (5%) |
| Secrets printed to serial | 8 (3%) |

## How existing secret scanners compare

| | preflash | gitleaks also caught |
|---|---|---|
| Hard-coded Wi-Fi passwords | 86 findings | **1 (1%)** |
| API keys / tokens in firmware | 53 findings | 12 (23%) |
| MQTT passwords | 2 | 0 |
| TLS off, open OTA, no-login web panels, open APs | 128 findings | not in scope |

General-purpose secret scanners look for known key formats and high-entropy strings.
A Wi-Fi password like `school100` or `86669443` looks like neither, so it slips through.
That is the gap preflash fills.

gitleaks did find things outside firmware (Firebase keys in web dashboards and Android
`google-services.json`, keys in Python scripts and READMEs). **Use both**: gitleaks for the
whole repo, preflash for the device code.

## Limits

- GitHub "best match" search favours popular repos, so the true rate across all hobby
  projects is probably higher, not lower.
- Some flagged repos are tutorials or examples, where the "victim" is whoever copies the code.
- Rules are pattern-based. They will miss creative code and occasionally flag test code.
