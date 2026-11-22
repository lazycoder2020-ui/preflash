"""Security rules for Arduino / ESP32 / ESP8266 / PlatformIO projects.

Each rule is a function(project_files) -> list[Finding]. Rules work on source
text (not compiled firmware), so they run in milliseconds and can sit in a
pre-commit hook or a GitHub Action.
"""
import re
from dataclasses import dataclass, asdict

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    file: str
    line: int
    message: str
    fix: str
    snippet: str = ""

    def to_dict(self):
        return asdict(self)


RULES = {}


def rule(rid, severity, title, fix):
    def deco(fn):
        RULES[rid] = {"id": rid, "severity": severity, "title": title,
                      "fix": fix, "fn": fn}
        return fn
    return deco


# ---------------------------------------------------------------- helpers
STR = r'"((?:\\.|[^"\\\n])*)"'

PLACEHOLDER_WORDS = (
    "your", "enter", "insert", "replace", "placeholder", "example", "changeme",
    "change_me", "xxxx", "****", "<", ">", "here", "dummy", "sample", "todo",
    "fill", "mynetwork", "my_network", "mypassword", "my_password",
    "_here", "put_", "write_", "redacted", "hidden", "...", "default",
)
PLACEHOLDER_EXACT = {
    "", "password", "pass", "passwd", "pwd", "ssid", "wifi", "secret", "token",
    "key", "apikey", "api_key", "user", "username", "none", "null", "test",
    "mqtt", "mqtt_user", "mqtt_pass", "mqttuser", "mqttpass", "wifi_ssid",
    "wifi_password", "auth", "authtoken", "auth_token", "ssid_name", "string", "text",
    "abc", "abcd", "abcdef", "qwerty", "foo", "bar", "foobar", "default",
}


def is_placeholder(v: str) -> bool:
    lv = v.strip().lower()
    if lv in PLACEHOLDER_EXACT:
        return True
    if re.fullmatch(r"[x*.\-_#?0]+", lv):
        return True
    if "%" in lv or "{" in lv or "\\x" in lv:      # format strings / templates
        return True
    if any(w in lv for w in PLACEHOLDER_WORDS):
        return True
    # "wifiPass", "WIFI PASS", "device-password", "PASSPASS": names, not values
    if re.search(r"pass|pwd|ssid|wifi|token|secret|apikey|api_key", lv) and \
            (not re.search(r"\d", lv) or " " in lv):
        return True
    # plain words with spaces ("my network name")
    if " " in lv and re.fullmatch(r"[a-z ]+", lv):
        return True
    return False


def mask(v: str) -> str:
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * min(8, len(v) - 4) + v[-2:]


def snippet(sf, line, secret=None):
    s = sf.lines[line - 1].strip() if 0 < line <= len(sf.lines) else ""
    if secret:
        s = s.replace(secret, mask(secret))
    return s[:160]


def strip_strings(s: str) -> str:
    return re.sub(STR, '""', s)


def f(rid, sf, line, message, secret=None):
    r = RULES[rid]
    return Finding(rid, r["severity"], r["title"], str(sf.path), line,
                   message, r["fix"], snippet(sf, line, secret))


# Variable / #define assignments of a string literal:
#   const char* password = "x";   char pass[] = "x";   String token = "x";
#   #define WIFI_PASSWORD "x"      static const char PSK[] PROGMEM = "x";
ASSIGN = re.compile(
    r'(?:#\s*define\s+(?P<d>\w+)\s+'
    r'|\b(?:const\s+|static\s+|constexpr\s+)*(?:char|String|std::string|auto)\b'
    r'[\s*&]*(?:const\s+)?(?P<v>\w+)\s*(?:\[[^\]]*\])?\s*(?:PROGMEM\s*)?=\s*)'
    + STR
)

NAME_WIFI_PASS = re.compile(r"(pass|pwd|psk|passphrase|wifikey|wifi_key|wpa)", re.I)
NAME_NOT_WIFI = re.compile(r"(mqtt|ota|admin|http|web|www|blynk|api|ftp|smtp|"
                           r"mail|db|sql|influx|firebase|user|login|ap_|_ap|soft|"
                           r"portal|update|auth|telegram|bot|hash|text|label|msg|prompt|lang|hint|"
                           r"placeholder|caption|title|str_|_str|html|json|field)", re.I)
NAME_MQTT = re.compile(r"mqtt", re.I)
NAME_CRED = re.compile(r"(pass|pwd|token|key|secret)", re.I)   # usernames alone aren't secrets
NAME_NOT_CRED = re.compile(r"(client_?id|topic|server|host|port|broker|url|user)", re.I)
NAME_TOKEN = re.compile(r"(token|api_?key|apikey|secret|auth|bearer|"
                        r"write_?key|read_?key|access_?key|private_?key|"
                        r"client_?secret|webhook|chat_?id|bot)", re.I)
NAME_NOT_TOKEN = re.compile(r"(keyboard|keypad|keycode|keypress|key_?pin|"
                            r"monkey|turkey|hotkey|keyframe|tokenizer|"
                            r"pass|pwd|user|mqtt|ssid|host|url|server|topic|"
                            r"name|path|header|prefix|format|fmt|label|type|"
                            r"len|size|idx|index|count|_?id$)", re.I)
NAME_SSID = re.compile(r"ssid", re.I)
SECRET_IDENT = re.compile(r"\b\w*(?:pass(?:word)?|pwd|psk|token|api_?key|apikey|"
                          r"secret)\w*\b", re.I)


def assignments(sf):
    # raw text on purpose: a commented-out password is still a leaked password
    for m in ASSIGN.finditer(sf.text):
        name = m.group("d") or m.group("v") or ""
        yield name, m.group(3), sf.line_of(m.start())


# ---------------------------------------------------------------- rules
@rule("PF001", "high", "Hard-coded Wi-Fi password",
      "Move credentials to a git-ignored secrets.h (or arduino_secrets.h), or "
      "use WiFiManager / Improv so the password is entered on the device.")
def wifi_password(files):
    out = []
    for sf in files:
        if sf.is_config:
            continue
        for name, val, ln in assignments(sf):
            if NAME_WIFI_PASS.search(name) and not NAME_NOT_WIFI.search(name) \
                    and not is_placeholder(val) and len(val) >= 4:
                out.append(f("PF001", sf, ln,
                             f"Wi-Fi password stored in `{name}`. Anyone who "
                             "sees this code can join your network.", val))
        for m in re.finditer(r"\b(?:WiFi|wifiMulti|WiFiMulti|wifi_multi)\s*"
                             r"\.\s*(?:begin|addAP)\s*\(\s*" + STR + r"\s*,\s*" + STR,
                             sf.code):
            val = m.group(2)
            if not is_placeholder(val) and len(val) >= 4:
                out.append(f("PF001", sf, sf.line_of(m.start()),
                             "Wi-Fi password passed as a literal to WiFi.begin/addAP.",
                             val))
    return out


@rule("PF002", "high", "Hard-coded MQTT credentials",
      "Keep broker credentials in a git-ignored secrets file and use a "
      "per-device username/password or client certificate.")
def mqtt_creds(files):
    out = []
    for sf in files:
        if sf.is_config:
            continue
        for name, val, ln in assignments(sf):
            if NAME_MQTT.search(name) and NAME_CRED.search(name) \
                    and not NAME_NOT_CRED.search(name) \
                    and not is_placeholder(val) and len(val) >= 3:
                out.append(f("PF002", sf, ln,
                             f"MQTT credential stored in `{name}`.", val))
        for m in re.finditer(r"\.\s*connect\s*\(\s*[^,()]+,\s*" + STR + r"\s*,\s*" + STR,
                             sf.code):
            val = m.group(2)
            if not is_placeholder(val) and len(val) >= 3:
                out.append(f("PF002", sf, sf.line_of(m.start()),
                             "MQTT username/password passed as literals to connect().",
                             val))
    return out


KNOWN_TOKENS = [
    ("Blynk auth token", re.compile(r'BLYNK_AUTH_TOKEN\s+"([A-Za-z0-9_\-]{28,40})"')),
    ("Blynk auth token", re.compile(r'Blynk\.begin\s*\(\s*"([A-Za-z0-9_\-]{28,40})"')),
    ("Telegram bot token", re.compile(r'"(\d{8,10}:[A-Za-z0-9_\-]{35})"')),
    ("Google / Firebase API key", re.compile(r'"(AIza[0-9A-Za-z_\-]{35})"')),
    ("OpenAI API key", re.compile(r'"(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})"')),
    ("AWS access key", re.compile(r'"((?:AKIA|ASIA)[0-9A-Z]{16})"')),
    ("Discord webhook", re.compile(r'(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+)')),
    ("Slack webhook", re.compile(r'(https://hooks\.slack\.com/services/[\w/]+)')),
    ("Adafruit IO key", re.compile(r'"(aio_[A-Za-z0-9]{28})"')),
    ("Twilio auth", re.compile(r'"((?:AC|SK)[0-9a-f]{32})"')),
    ("IFTTT webhook key", re.compile(r'maker\.ifttt\.com/trigger/[^"]*/with/key/([A-Za-z0-9_\-]{20,})')),
]


@rule("PF003", "high", "Hard-coded API key or token",
      "Rotate this key now, then load it from a git-ignored secrets file. "
      "Prefer short-lived or device-scoped tokens.")
def api_tokens(files):
    out, seen = [], set()
    for sf in files:
        if sf.is_config:
            continue
        for label, rx in KNOWN_TOKENS:
            for m in rx.finditer(sf.text):
                ln = sf.line_of(m.start())
                seen.add((str(sf.path), ln))
                out.append(f("PF003", sf, ln, f"{label} found in source.", m.group(1)))
        for name, val, ln in assignments(sf):
            if (str(sf.path), ln) in seen:
                continue
            if NAME_TOKEN.search(name) and not NAME_NOT_TOKEN.search(name) \
                    and not is_placeholder(val) and len(val) >= 12 \
                    and re.fullmatch(r"[A-Za-z0-9_\-:.=+/]+", val) \
                    and re.search(r"\d", val) and re.search(r"[A-Za-z]", val):
                out.append(f("PF003", sf, ln,
                             f"Secret-looking value stored in `{name}`.", val))
    return out


@rule("PF004", "critical", "Private key embedded in firmware source",
      "Never commit device private keys. Provision them per device (e.g. into "
      "NVS / secure element) and revoke this key with the issuer (AWS IoT, etc.).")
def private_key(files):
    out = []
    for sf in files:
        for m in re.finditer(r"-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----"
                             r"(?:\\n|\\r|[\s\"])*[A-Za-z0-9+/]{40,}", sf.text):
            out.append(f("PF004", sf, sf.line_of(m.start()),
                         "A private key is committed with the code. Anyone can "
                         "impersonate this device."))
    return out


@rule("PF005", "high", "TLS certificate checking disabled",
      "Use setCACert() with the server's root CA (or a certificate bundle) "
      "instead of setInsecure().")
def tls_insecure(files):
    out = []
    pats = [
        (r"\.\s*setInsecure\s*\(\s*\)", "setInsecure() accepts any certificate, "
         "so the connection can be intercepted."),
        (r"skip_cert_common_name_check\s*=\s*true", "Server name check is skipped."),
        (r"^CONFIG_ESP_TLS_INSECURE\s*=\s*y", "ESP-TLS insecure mode is enabled."),
        (r"^CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY\s*=\s*y",
         "Server certificate verification is turned off."),
    ]
    for sf in files:
        for p, msg in pats:
            for m in re.finditer(p, sf.code, re.M):
                out.append(f("PF005", sf, sf.line_of(m.start()), msg))
    return out


@rule("PF006", "medium", "MQTT traffic is not encrypted",
      "Use port 8883 with WiFiClientSecure (or mqtts://) so credentials and "
      "data are not sent in plain text.")
def mqtt_plain(files):
    out = []
    uses_mqtt = any(re.search(r"PubSubClient|AsyncMqttClient|esp_mqtt_client|MQTTClient|mqtt",
                              sf.code, re.I) for sf in files if not sf.is_config)
    if not uses_mqtt:
        return out
    for sf in files:
        if sf.is_config:
            continue
        for m in re.finditer(r'(?:setServer\s*\([^,)]+,\s*|port\w*\s*=\s*|\bMQTT_PORT\s+)'
                             r'1883\b|"mqtts?://[^"]*"|"(?:tcp|ws)://[^"]*"', sf.code, re.I):
            txt = m.group(0)
            if "mqtts://" in txt.lower():
                continue
            out.append(f("PF006", sf, sf.line_of(m.start()),
                         "MQTT is configured without TLS (port 1883 / mqtt://)."))
    return out


@rule("PF007", "medium", "Secret sent over plain HTTP",
      "Use https:// and send keys in a header, not in the URL.")
def http_secret(files):
    out = []
    rx = re.compile(r'"(http://[^"\s]*[?&](?:key|apikey|api_key|appid|token|'
                    r'access_token|auth|secret|password|pass)=([^"&\s]+)[^"]*)"', re.I)
    for sf in files:
        if sf.is_config:
            continue
        for m in rx.finditer(sf.code):
            val = m.group(2)
            if is_placeholder(val) or val.startswith('"'):
                continue
            out.append(f("PF007", sf, sf.line_of(m.start()),
                         "An API key/token is placed in an http:// URL and sent "
                         "unencrypted.", val))
    return out


@rule("PF008", "high", "Firmware updates (OTA) accept anyone",
      "Call ArduinoOTA.setPassword()/setPasswordHash() before begin(), and give "
      "web updaters a username and password.")
def ota_open(files):
    out = []
    code = "\n".join(sf.code for sf in files if not sf.is_config)
    has_pw = re.search(r"ArduinoOTA\s*\.\s*setPassword(?:Hash)?\s*\(", code)
    for sf in files:
        if sf.is_config:
            continue
        if not has_pw:
            for m in re.finditer(r"ArduinoOTA\s*\.\s*begin\s*\(", sf.code):
                out.append(f("PF008", sf, sf.line_of(m.start()),
                             "ArduinoOTA is started with no password: anyone on "
                             "the network can flash new firmware."))
        for m in re.finditer(r"\b(?:Async)?ElegantOTA\s*\.\s*begin\s*\(\s*[^,()]+\)"
                             r"|\.\s*setup\s*\(\s*&\s*\w+\s*\)", sf.code):
            if "setup" in m.group(0) and not re.search(r"HTTPUpdateServer|ESP8266HTTPUpdateServer",
                                                       code):
                continue
            out.append(f("PF008", sf, sf.line_of(m.start()),
                         "Web firmware-update page has no login."))
    return out


@rule("PF009", "medium", "Hard-coded OTA password",
      "Use setPasswordHash() with an MD5 hash kept out of the repo, and keep "
      "upload passwords out of platformio.ini (use an env variable).")
def ota_hardcoded(files):
    out = []
    for sf in files:
        if sf.is_config:
            for m in re.finditer(r"--auth[= ]\s*([^\s;\"']+)", sf.text):
                val = m.group(1)
                if not val.startswith("${") and not is_placeholder(val):
                    out.append(f("PF009", sf, sf.line_of(m.start()),
                                 "OTA upload password stored in platformio.ini.", val))
            continue
        for m in re.finditer(r"ArduinoOTA\s*\.\s*setPassword\s*\(\s*" + STR, sf.code):
            val = m.group(1)
            if not is_placeholder(val):
                out.append(f("PF009", sf, sf.line_of(m.start()),
                             "OTA password written in the source.", val))
        for m in re.finditer(r"ElegantOTA\s*\.\s*begin\s*\([^,]+,\s*" + STR + r"\s*,\s*" + STR,
                             sf.code):
            val = m.group(2)
            if not is_placeholder(val):
                out.append(f("PF009", sf, sf.line_of(m.start()),
                             "OTA web-updater password written in the source.", val))
    return out


@rule("PF010", "medium", "Web control panel has no login",
      "Protect routes with server.authenticate()/requestAuthentication() "
      "(or ESPAsyncWebServer setAuthentication), at least for routes that change state.")
def web_no_auth(files):
    out = []
    code = "\n".join(sf.code for sf in files if not sf.is_config)
    if re.search(r"authenticate\s*\(|requestAuthentication\s*\(|setAuthentication\s*\(|"
                 r"checkAuth|isAuthenticated|basicAuth|digestAuth", code):
        return out
    for sf in files:
        if sf.is_config:
            continue
        routes = [m for m in re.finditer(r"\b\w+\s*(?:\.|->)\s*on\s*\(\s*\"(/[^\"]*)\"", sf.code)]
        if not routes:
            continue
        risky = [r for r in routes if r.group(1) != "/" and not re.search(
            r"\.(?:css|js|png|jpe?g|ico|svg|gif|woff2?|ttf|map|txt)$", r.group(1), re.I)]
        if not risky:
            continue
        names = ", ".join(sorted({r.group(1) for r in risky})[:6])
        out.append(f("PF010", sf, sf.line_of(risky[0].start()),
                     f"{len(risky)} web route(s) ({names}) with no authentication "
                     "anywhere in the project. Anyone on the network can use them."))
    return out


@rule("PF011", "medium", "Secret printed to the serial console",
      "Don't print passwords or tokens. Serial logs end up in screenshots, "
      "forum posts and bug reports.")
def serial_secret(files):
    out = []
    rx = re.compile(r"\b(?:Serial\d?|DEBUG_PORT|Serial\.printf|Log)\s*\.\s*"
                    r"(?:print|println|printf|write)\s*\(([^;]*)\)\s*;")
    for sf in files:
        if sf.is_config:
            continue
        for m in rx.finditer(sf.code):
            args = strip_strings(m.group(1))
            hit = next((h for h in SECRET_IDENT.finditer(args)
                        if not re.match(r"\s*\(", args[h.end():])
                        and not re.search(r"type|error|status|info|len|valid|expir|"
                                          r"count|size|ok|set|required", h.group(0), re.I)),
                       None)
            if hit and not re.search(r"\.length\(\)|sizeof|strlen", args):
                out.append(f("PF011", sf, sf.line_of(m.start()),
                             f"`{hit.group(0)}` is printed to serial."))
    return out


WEAK_AP = {"12345678", "123456789", "1234567890", "password", "password1",
           "00000000", "11111111", "87654321", "qwertyui", "admin123",
           "esp32esp32", "esp8266esp8266", "configesp", "12341234"}


@rule("PF012", "medium", "Open or weak Wi-Fi access point",
      "Give the device's own access point a long unique password (ideally per "
      "device, e.g. printed on a label), or close the AP after setup.")
def soft_ap(files):
    out = []
    for sf in files:
        if sf.is_config:
            continue
        for m in re.finditer(r"softAP\s*\(\s*" + STR + r"\s*(?:\)|,\s*" + STR + r"\s*[,)]"
                             r"|,\s*(?:NULL|nullptr|0)\s*[,)])", sf.code):
            pw = m.group(2)
            ln = sf.line_of(m.start())
            if pw is None or pw == "":
                out.append(f("PF012", sf, ln,
                             "Access point has no password; anyone nearby can connect."))
            elif pw.lower() in WEAK_AP or len(pw) < 10 or pw.isdigit():
                out.append(f("PF012", sf, ln,
                             "Access point uses a weak, guessable password.", pw))
    return out


@rule("PF013", "high", "Credentials returned in a web response",
      "Never send stored passwords or tokens back to the browser; show masked "
      "values instead.")
def web_leak(files):
    out = []
    rx = re.compile(r"(?:\bserver\w*|\bwebServer\w*|\brequest|\breq)\s*(?:\.|->)\s*"
                    r"(?:send|send_P|sendContent|print|println)\s*\(([^;]*)\)\s*;")
    for sf in files:
        if sf.is_config:
            continue
        for m in rx.finditer(sf.code):
            args = strip_strings(m.group(1))
            hit = next((h for h in SECRET_IDENT.finditer(args)
                        if not re.match(r"\s*\(", args[h.end():])
                        and not re.search(r"type|error|status|len|valid|required",
                                          h.group(0), re.I)), None)
            if hit:
                out.append(f("PF013", sf, sf.line_of(m.start()),
                             f"`{hit.group(0)}` is sent back in an HTTP response."))
    return out


@rule("PF014", "low", "Verbose debug logging enabled",
      "Use CORE_DEBUG_LEVEL=1 (errors only) or lower for release builds.")
def debug_level(files):
    out = []
    for sf in files:
        for m in re.finditer(r"CORE_DEBUG_LEVEL\s*=\s*[45]\b|"
                             r"^CONFIG_LOG_DEFAULT_LEVEL_(?:DEBUG|VERBOSE)\s*=\s*y", sf.code, re.M):
            out.append(f("PF014", sf, sf.line_of(m.start()),
                         "Debug/verbose logs can leak keys, URLs and memory contents."))
    return out


@rule("PF015", "low", "Remote debug console enabled",
      "Remove Telnet/RemoteDebug in release builds or protect it with a password.")
def remote_debug(files):
    out = []
    for sf in files:
        if sf.is_config:
            continue
        for m in re.finditer(r"\bRemoteDebug\b\s+\w+\s*;|TelnetStream\s*\.\s*begin\s*\(|"
                             r"\bESPTelnet\b\s+\w+\s*;", sf.code):
            out.append(f("PF015", sf, sf.line_of(m.start()),
                         "A network debug console (telnet) is enabled with no login."))
    return out


def run_all(files, only=None):
    findings = []
    for rid, r in RULES.items():
        if only and rid not in only:
            continue
        findings.extend(r["fn"](files))
    uniq = {}
    for x in findings:
        uniq.setdefault((x.rule, x.file, x.line), x)
    return sorted(uniq.values(),
                  key=lambda x: (-SEV_ORDER[x.severity], x.file, x.line))
