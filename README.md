# preflash

**Security scanner for Arduino, ESP32 and ESP8266 code. Scan before you flash.**

In a scan of 249 public ESP32/ESP8266 projects, **39% had at least one serious security
issue**. 22% had a Wi-Fi password in the code, and general secret scanners caught just
**1%** of those. ([full results](FINDINGS.md))

preflash reads your sketch or PlatformIO project and flags the mistakes that matter on
devices: credentials in code, open firmware updates, web panels with no login, TLS turned off.
It has no dependencies, needs no account, runs offline and takes milliseconds.

```
$ preflash .
HIGH     PF001 Hard-coded Wi-Fi password
         src/main.cpp:13
         const char* password = "gr********4!";
         Wi-Fi password stored in `password`. Anyone who sees this code can join your network.
         Fix: Move credentials to a git-ignored secrets.h (or arduino_secrets.h), or use
         WiFiManager / Improv so the password is entered on the device.

HIGH     PF008 Firmware updates (OTA) accept anyone
         src/main.cpp:46
         ArduinoOTA.begin();
         ...
14 issue(s) in 2 file(s): 7 high, 6 medium, 1 low
```

Secrets are masked in the output, so a screenshot of the report doesn't leak them again.

## Install

```bash
pip install git+https://github.com/lazycoder2020-ui/preflash
preflash path/to/your/project
```

## Rules

| ID | Severity | Catches |
|---|---|---|
| PF001 | high | Wi-Fi password in code (`WiFi.begin("ssid","pass")`, `#define WIFI_PASSWORD`, `STAPSK`...) |
| PF002 | high | MQTT password in code |
| PF003 | high | API keys/tokens: Blynk, Telegram, Firebase/Google, OpenAI, AWS, Adafruit IO, Twilio, Discord/Slack/IFTTT webhooks, plus generic `*_TOKEN`/`*_KEY` |
| PF004 | critical | Private keys (AWS IoT device keys etc.) in source or `.pem`/`.key` files |
| PF005 | high | TLS checks disabled: `setInsecure()`, `skip_cert_common_name_check`, ESP-TLS insecure sdkconfig |
| PF006 | medium | MQTT on port 1883 / `mqtt://` with no TLS |
| PF007 | medium | API key in an `http://` URL |
| PF008 | high | ArduinoOTA with no password, ElegantOTA / HTTPUpdateServer with no login |
| PF009 | medium | OTA password hard-coded (source or `platformio.ini --auth=`) |
| PF010 | medium | Web server routes with no authentication anywhere |
| PF011 | medium | Passwords/tokens printed to Serial |
| PF012 | medium | `softAP` with no password or a weak one (`12345678`...) |
| PF013 | high | Passwords/tokens sent back in an HTTP response |
| PF014 | low | `CORE_DEBUG_LEVEL` 4-5 left on |
| PF015 | low | Telnet / RemoteDebug consoles |

Placeholders like `"YOUR_PASSWORD"`, `"********"` or `"wifi pass"` are ignored. Values in
`secrets.h` are still flagged if the file is committed, because a committed secret is a leaked secret.

## Use it in CI (GitHub Action)

```yaml
# .github/workflows/preflash.yml
on: [push, pull_request]
permissions: { contents: read, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: lazycoder2020-ui/preflash@v0.1.0
        with: { fail-on: high }
```

Findings show up in the repo's **Security → Code scanning** tab (SARIF).

## pre-commit

```yaml
- repo: https://github.com/lazycoder2020-ui/preflash
  rev: v0.1.0
  hooks: [{ id: preflash }]
```

## Options

```
preflash [path] [--format text|json|sarif] [-o FILE] [--fail-on critical|high|medium|low|never]
                [--rules PF001,PF005] [--include-libs] [--list-rules]
```

## The fix for most findings

1. Create `arduino_secrets.h` (or `secrets.h`), put credentials there, add it to `.gitignore`.
2. Commit an `arduino_secrets.example.h` with placeholders.
3. **Rotate anything that was ever pushed.** Deleting it from the latest commit doesn't remove it from git history.

## Roadmap

- `--fix` to move secrets into `secrets.h` automatically
- ESP-IDF rules (flash encryption, secure boot, NVS encryption)
- VS Code / PlatformIO extension
- Semgrep-compatible rule pack

## Licence

MIT
