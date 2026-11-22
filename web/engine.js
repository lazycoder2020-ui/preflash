/* preflash engine (JavaScript port of preflash/rules.py).
 * Runs entirely in the browser or in Node. Keep in sync with rules.py:
 * tests/parity.mjs runs both on the same inputs and fails on any difference.
 */
(function (root) {
  "use strict";

  const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
  const CODE_EXT = [".ino", ".pde", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"];
  const CONFIG_NAMES = ["platformio.ini", "sdkconfig", "sdkconfig.defaults", "partitions.csv"];
  const KEY_EXT = [".key", ".pem"];
  const SKIP_DIRS = [".git", ".pio", "build", "node_modules", ".vscode", "__pycache__",
    "managed_components", "components", "lib_deps", ".github"];
  const LIB_DIRS = ["libraries", "lib", "libdeps", "vendor", "third_party", "external"];

  // ------------------------------------------------------------ files
  function ext(name) { const i = name.lastIndexOf("."); return i < 0 ? "" : name.slice(i).toLowerCase(); }
  function base(p) { return p.split("/").pop(); }

  function shouldScan(path, includeLibs) {
    const parts = path.split("/");
    const dirs = parts.slice(0, -1);
    for (const d of dirs) {
      if (SKIP_DIRS.includes(d)) return false;
      if (!includeLibs && LIB_DIRS.includes(d.toLowerCase())) return false;
    }
    const name = parts[parts.length - 1];
    return CODE_EXT.includes(ext(name)) || CONFIG_NAMES.includes(name) || KEY_EXT.includes(ext(name));
  }

  const COMMENT_RE = /\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g;
  function stripComments(text) {
    return text.replace(COMMENT_RE, (s) => (s[0] === "/" ? s.replace(/[^\n]/g, " ") : s));
  }

  function makeFile(path, text) {
    const name = base(path);
    const isConfig = CONFIG_NAMES.includes(name) || KEY_EXT.includes(ext(name));
    // newline offsets for fast line lookup
    const nl = [];
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) nl.push(i);
    return {
      path, text, isConfig,
      lines: text.split(/\r\n|\r|\n/),
      code: isConfig ? text : stripComments(text),
      lineOf(off) { let lo = 0, hi = nl.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (nl[mid] < off) lo = mid + 1; else hi = mid; } return lo + 1; },
    };
  }

  // ------------------------------------------------------------ helpers
  const STR = String.raw`"((?:\\.|[^"\\\n])*)"`;
  const PLACEHOLDER_WORDS = ["your", "enter", "insert", "replace", "placeholder", "example", "changeme",
    "change_me", "xxxx", "****", "<", ">", "here", "dummy", "sample", "todo",
    "fill", "mynetwork", "my_network", "mypassword", "my_password",
    "_here", "put_", "write_", "redacted", "hidden", "...", "default"];
  const PLACEHOLDER_EXACT = new Set(["", "password", "pass", "passwd", "pwd", "ssid", "wifi", "secret", "token",
    "key", "apikey", "api_key", "user", "username", "none", "null", "test",
    "mqtt", "mqtt_user", "mqtt_pass", "mqttuser", "mqttpass", "wifi_ssid",
    "wifi_password", "auth", "authtoken", "auth_token", "ssid_name", "string", "text",
    "abc", "abcd", "abcdef", "qwerty", "foo", "bar", "foobar", "default"]);

  function isPlaceholder(v) {
    const lv = v.trim().toLowerCase();
    if (PLACEHOLDER_EXACT.has(lv)) return true;
    if (/^[x*.\-_#?0]+$/.test(lv)) return true;
    if (lv.includes("%") || lv.includes("{") || lv.includes("\\x")) return true;
    if (PLACEHOLDER_WORDS.some((w) => lv.includes(w))) return true;
    if (/pass|pwd|ssid|wifi|token|secret|apikey|api_key/.test(lv) && (!/\d/.test(lv) || lv.includes(" "))) return true;
    if (lv.includes(" ") && /^[a-z ]+$/.test(lv)) return true;
    return false;
  }

  function mask(v) {
    if (v.length <= 4) return "*".repeat(v.length);
    return v.slice(0, 2) + "*".repeat(Math.min(8, v.length - 4)) + v.slice(-2);
  }

  function snippet(sf, line, secret) {
    let s = line > 0 && line <= sf.lines.length ? sf.lines[line - 1].trim() : "";
    if (secret) s = s.split(secret).join(mask(secret));
    return s.slice(0, 160);
  }

  const stripStrings = (s) => s.replace(new RegExp(STR, "g"), '""');
  const all = (re, s) => s.matchAll(re);
  const R = (src, flags = "") => new RegExp(src, "g" + flags);

  const RULES = {};
  function rule(id, severity, title, fix, fn) { RULES[id] = { id, severity, title, fix, fn }; }
  function F(id, sf, line, message, secret) {
    const r = RULES[id];
    return { rule: id, severity: r.severity, title: r.title, file: sf.path, line,
      message, fix: r.fix, snippet: snippet(sf, line, secret) };
  }

  const ASSIGN = R(String.raw`(?:#\s*define\s+(?<d>\w+)\s+|\b(?:const\s+|static\s+|constexpr\s+)*(?:char|String|std::string|auto)\b[\s*&]*(?:const\s+)?(?<v>\w+)\s*(?:\[[^\]]*\])?\s*(?:PROGMEM\s*)?=\s*)` + STR);
  const NAME_WIFI_PASS = /(pass|pwd|psk|passphrase|wifikey|wifi_key|wpa)/i;
  const NAME_NOT_WIFI = /(mqtt|ota|admin|http|web|www|blynk|api|ftp|smtp|mail|db|sql|influx|firebase|user|login|ap_|_ap|soft|portal|update|auth|telegram|bot|hash|text|label|msg|prompt|lang|hint|placeholder|caption|title|str_|_str|html|json|field)/i;
  const NAME_MQTT = /mqtt/i;
  const NAME_CRED = /(pass|pwd|token|key|secret)/i;
  const NAME_NOT_CRED = /(client_?id|topic|server|host|port|broker|url|user)/i;
  const NAME_TOKEN = /(token|api_?key|apikey|secret|auth|bearer|write_?key|read_?key|access_?key|private_?key|client_?secret|webhook|chat_?id|bot)/i;
  const NAME_NOT_TOKEN = /(keyboard|keypad|keycode|keypress|key_?pin|monkey|turkey|hotkey|keyframe|tokenizer|pass|pwd|user|mqtt|ssid|host|url|server|topic|name|path|header|prefix|format|fmt|label|type|len|size|idx|index|count|_?id$)/i;
  const SECRET_IDENT = String.raw`\b\w*(?:pass(?:word)?|pwd|psk|token|api_?key|apikey|secret)\w*\b`;

  function* assignments(sf) {
    for (const m of all(ASSIGN, sf.text)) {
      yield [m.groups.d || m.groups.v || "", m[3], sf.lineOf(m.index)];
    }
  }

  // ------------------------------------------------------------ rules
  rule("PF001", "high", "Hard-coded Wi-Fi password",
    "Move credentials to a git-ignored secrets.h (or arduino_secrets.h), or use WiFiManager / Improv so the password is entered on the device.",
    (files) => {
      const out = [];
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const [name, val, ln] of assignments(sf)) {
          if (NAME_WIFI_PASS.test(name) && !NAME_NOT_WIFI.test(name) && !isPlaceholder(val) && val.length >= 4)
            out.push(F("PF001", sf, ln, `Wi-Fi password stored in \`${name}\`. Anyone who sees this code can join your network.`, val));
        }
        for (const m of all(R(String.raw`\b(?:WiFi|wifiMulti|WiFiMulti|wifi_multi)\s*\.\s*(?:begin|addAP)\s*\(\s*` + STR + String.raw`\s*,\s*` + STR), sf.code)) {
          const val = m[2];
          if (!isPlaceholder(val) && val.length >= 4)
            out.push(F("PF001", sf, sf.lineOf(m.index), "Wi-Fi password passed as a literal to WiFi.begin/addAP.", val));
        }
      }
      return out;
    });

  rule("PF002", "high", "Hard-coded MQTT credentials",
    "Keep broker credentials in a git-ignored secrets file and use a per-device username/password or client certificate.",
    (files) => {
      const out = [];
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const [name, val, ln] of assignments(sf)) {
          if (NAME_MQTT.test(name) && NAME_CRED.test(name) && !NAME_NOT_CRED.test(name) && !isPlaceholder(val) && val.length >= 3)
            out.push(F("PF002", sf, ln, `MQTT credential stored in \`${name}\`.`, val));
        }
        for (const m of all(R(String.raw`\.\s*connect\s*\(\s*[^,()]+,\s*` + STR + String.raw`\s*,\s*` + STR), sf.code)) {
          const val = m[2];
          if (!isPlaceholder(val) && val.length >= 3)
            out.push(F("PF002", sf, sf.lineOf(m.index), "MQTT username/password passed as literals to connect().", val));
        }
      }
      return out;
    });

  const KNOWN_TOKENS = [
    ["Blynk auth token", String.raw`BLYNK_AUTH_TOKEN\s+"([A-Za-z0-9_\-]{28,40})"`],
    ["Blynk auth token", String.raw`Blynk\.begin\s*\(\s*"([A-Za-z0-9_\-]{28,40})"`],
    ["Telegram bot token", String.raw`"(\d{8,10}:[A-Za-z0-9_\-]{35})"`],
    ["Google / Firebase API key", String.raw`"(AIza[0-9A-Za-z_\-]{35})"`],
    ["OpenAI API key", String.raw`"(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})"`],
    ["AWS access key", String.raw`"((?:AKIA|ASIA)[0-9A-Z]{16})"`],
    ["Discord webhook", String.raw`(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+)`],
    ["Slack webhook", String.raw`(https://hooks\.slack\.com/services/[\w/]+)`],
    ["Adafruit IO key", String.raw`"(aio_[A-Za-z0-9]{28})"`],
    ["Twilio auth", String.raw`"((?:AC|SK)[0-9a-f]{32})"`],
    ["IFTTT webhook key", String.raw`maker\.ifttt\.com/trigger/[^"]*/with/key/([A-Za-z0-9_\-]{20,})`],
  ];

  rule("PF003", "high", "Hard-coded API key or token",
    "Rotate this key now, then load it from a git-ignored secrets file. Prefer short-lived or device-scoped tokens.",
    (files) => {
      const out = [], seen = new Set();
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const [label, src] of KNOWN_TOKENS) {
          for (const m of all(R(src), sf.text)) {
            const ln = sf.lineOf(m.index);
            seen.add(sf.path + "\0" + ln);
            out.push(F("PF003", sf, ln, `${label} found in source.`, m[1]));
          }
        }
        for (const [name, val, ln] of assignments(sf)) {
          if (seen.has(sf.path + "\0" + ln)) continue;
          if (NAME_TOKEN.test(name) && !NAME_NOT_TOKEN.test(name) && !isPlaceholder(val) && val.length >= 12
              && /^[A-Za-z0-9_\-:.=+/]+$/.test(val) && /\d/.test(val) && /[A-Za-z]/.test(val))
            out.push(F("PF003", sf, ln, `Secret-looking value stored in \`${name}\`.`, val));
        }
      }
      return out;
    });

  rule("PF004", "critical", "Private key embedded in firmware source",
    "Never commit device private keys. Provision them per device (e.g. into NVS / secure element) and revoke this key with the issuer (AWS IoT, etc.).",
    (files) => {
      const out = [];
      for (const sf of files)
        for (const m of all(R(String.raw`-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----(?:\\n|\\r|[\s"])*[A-Za-z0-9+/]{40,}`), sf.text))
          out.push(F("PF004", sf, sf.lineOf(m.index), "A private key is committed with the code. Anyone can impersonate this device."));
      return out;
    });

  rule("PF005", "high", "TLS certificate checking disabled",
    "Use setCACert() with the server's root CA (or a certificate bundle) instead of setInsecure().",
    (files) => {
      const out = [];
      const pats = [
        [String.raw`\.\s*setInsecure\s*\(\s*\)`, "setInsecure() accepts any certificate, so the connection can be intercepted."],
        [String.raw`skip_cert_common_name_check\s*=\s*true`, "Server name check is skipped."],
        [String.raw`^CONFIG_ESP_TLS_INSECURE\s*=\s*y`, "ESP-TLS insecure mode is enabled."],
        [String.raw`^CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY\s*=\s*y`, "Server certificate verification is turned off."],
      ];
      for (const sf of files)
        for (const [p, msg] of pats)
          for (const m of all(R(p, "m"), sf.code)) out.push(F("PF005", sf, sf.lineOf(m.index), msg));
      return out;
    });

  rule("PF006", "medium", "MQTT traffic is not encrypted",
    "Use port 8883 with WiFiClientSecure (or mqtts://) so credentials and data are not sent in plain text.",
    (files) => {
      const out = [];
      const uses = files.some((sf) => !sf.isConfig && /PubSubClient|AsyncMqttClient|esp_mqtt_client|MQTTClient|mqtt/i.test(sf.code));
      if (!uses) return out;
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const m of all(R(String.raw`(?:setServer\s*\([^,)]+,\s*|port\w*\s*=\s*|\bMQTT_PORT\s+)1883\b|"mqtts?://[^"]*"|"(?:tcp|ws)://[^"]*"`, "i"), sf.code)) {
          if (m[0].toLowerCase().includes("mqtts://")) continue;
          out.push(F("PF006", sf, sf.lineOf(m.index), "MQTT is configured without TLS (port 1883 / mqtt://)."));
        }
      }
      return out;
    });

  rule("PF007", "medium", "Secret sent over plain HTTP",
    "Use https:// and send keys in a header, not in the URL.",
    (files) => {
      const out = [];
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const m of all(R(String.raw`"(http://[^"\s]*[?&](?:key|apikey|api_key|appid|token|access_token|auth|secret|password|pass)=([^"&\s]+)[^"]*)"`, "i"), sf.code)) {
          const val = m[2];
          if (isPlaceholder(val) || val.startsWith('"')) continue;
          out.push(F("PF007", sf, sf.lineOf(m.index), "An API key/token is placed in an http:// URL and sent unencrypted.", val));
        }
      }
      return out;
    });

  rule("PF008", "high", "Firmware updates (OTA) accept anyone",
    "Call ArduinoOTA.setPassword()/setPasswordHash() before begin(), and give web updaters a username and password.",
    (files) => {
      const out = [];
      const code = files.filter((s) => !s.isConfig).map((s) => s.code).join("\n");
      const hasPw = /ArduinoOTA\s*\.\s*setPassword(?:Hash)?\s*\(/.test(code);
      for (const sf of files) {
        if (sf.isConfig) continue;
        if (!hasPw)
          for (const m of all(R(String.raw`ArduinoOTA\s*\.\s*begin\s*\(`), sf.code))
            out.push(F("PF008", sf, sf.lineOf(m.index), "ArduinoOTA is started with no password: anyone on the network can flash new firmware."));
        for (const m of all(R(String.raw`\b(?:Async)?ElegantOTA\s*\.\s*begin\s*\(\s*[^,()]+\)|\.\s*setup\s*\(\s*&\s*\w+\s*\)`), sf.code)) {
          if (m[0].includes("setup") && !/HTTPUpdateServer|ESP8266HTTPUpdateServer/.test(code)) continue;
          out.push(F("PF008", sf, sf.lineOf(m.index), "Web firmware-update page has no login."));
        }
      }
      return out;
    });

  rule("PF009", "medium", "Hard-coded OTA password",
    "Use setPasswordHash() with an MD5 hash kept out of the repo, and keep upload passwords out of platformio.ini (use an env variable).",
    (files) => {
      const out = [];
      for (const sf of files) {
        if (sf.isConfig) {
          for (const m of all(R(String.raw`--auth[= ]\s*([^\s;"']+)`), sf.text)) {
            const val = m[1];
            if (!val.startsWith("${") && !isPlaceholder(val))
              out.push(F("PF009", sf, sf.lineOf(m.index), "OTA upload password stored in platformio.ini.", val));
          }
          continue;
        }
        for (const m of all(R(String.raw`ArduinoOTA\s*\.\s*setPassword\s*\(\s*` + STR), sf.code)) {
          if (!isPlaceholder(m[1])) out.push(F("PF009", sf, sf.lineOf(m.index), "OTA password written in the source.", m[1]));
        }
        for (const m of all(R(String.raw`ElegantOTA\s*\.\s*begin\s*\([^,]+,\s*` + STR + String.raw`\s*,\s*` + STR), sf.code)) {
          if (!isPlaceholder(m[2])) out.push(F("PF009", sf, sf.lineOf(m.index), "OTA web-updater password written in the source.", m[2]));
        }
      }
      return out;
    });

  rule("PF010", "medium", "Web control panel has no login",
    "Protect routes with server.authenticate()/requestAuthentication() (or ESPAsyncWebServer setAuthentication), at least for routes that change state.",
    (files) => {
      const out = [];
      const code = files.filter((s) => !s.isConfig).map((s) => s.code).join("\n");
      if (/authenticate\s*\(|requestAuthentication\s*\(|setAuthentication\s*\(|checkAuth|isAuthenticated|basicAuth|digestAuth/.test(code)) return out;
      for (const sf of files) {
        if (sf.isConfig) continue;
        const routes = [...all(R(String.raw`\b\w+\s*(?:\.|->)\s*on\s*\(\s*"(/[^"]*)"`), sf.code)];
        const risky = routes.filter((r) => r[1] !== "/" && !/\.(?:css|js|png|jpe?g|ico|svg|gif|woff2?|ttf|map|txt)$/i.test(r[1]));
        if (!risky.length) continue;
        const names = [...new Set(risky.map((r) => r[1]))].sort().slice(0, 6).join(", ");
        out.push(F("PF010", sf, sf.lineOf(risky[0].index), `${risky.length} web route(s) (${names}) with no authentication anywhere in the project. Anyone on the network can use them.`));
      }
      return out;
    });

  function firstSecret(args, excl) {
    for (const h of all(R(SECRET_IDENT, "i"), args)) {
      const after = args.slice(h.index + h[0].length);
      if (/^\s*\(/.test(after)) continue;
      if (excl.test(h[0])) continue;
      return h[0];
    }
    return null;
  }

  rule("PF011", "medium", "Secret printed to the serial console",
    "Don't print passwords or tokens. Serial logs end up in screenshots, forum posts and bug reports.",
    (files) => {
      const out = [];
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const m of all(R(String.raw`\b(?:Serial\d?|DEBUG_PORT|Serial\.printf|Log)\s*\.\s*(?:print|println|printf|write)\s*\(([^;]*)\)\s*;`), sf.code)) {
          const args = stripStrings(m[1]);
          const hit = firstSecret(args, /type|error|status|info|len|valid|expir|count|size|ok|set|required/i);
          if (hit && !/\.length\(\)|sizeof|strlen/.test(args))
            out.push(F("PF011", sf, sf.lineOf(m.index), `\`${hit}\` is printed to serial.`));
        }
      }
      return out;
    });

  const WEAK_AP = new Set(["12345678", "123456789", "1234567890", "password", "password1",
    "00000000", "11111111", "87654321", "qwertyui", "admin123",
    "esp32esp32", "esp8266esp8266", "configesp", "12341234"]);

  rule("PF012", "medium", "Open or weak Wi-Fi access point",
    "Give the device's own access point a long unique password (ideally per device, e.g. printed on a label), or close the AP after setup.",
    (files) => {
      const out = [];
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const m of all(R(String.raw`softAP\s*\(\s*` + STR + String.raw`\s*(?:\)|,\s*` + STR + String.raw`\s*[,)]|,\s*(?:NULL|nullptr|0)\s*[,)])`), sf.code)) {
          const pw = m[2]; const ln = sf.lineOf(m.index);
          if (pw === undefined || pw === "")
            out.push(F("PF012", sf, ln, "Access point has no password; anyone nearby can connect."));
          else if (WEAK_AP.has(pw.toLowerCase()) || pw.length < 10 || /^\d+$/.test(pw))
            out.push(F("PF012", sf, ln, "Access point uses a weak, guessable password.", pw));
        }
      }
      return out;
    });

  rule("PF013", "high", "Credentials returned in a web response",
    "Never send stored passwords or tokens back to the browser; show masked values instead.",
    (files) => {
      const out = [];
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const m of all(R(String.raw`(?:\bserver\w*|\bwebServer\w*|\brequest|\breq)\s*(?:\.|->)\s*(?:send|send_P|sendContent|print|println)\s*\(([^;]*)\)\s*;`), sf.code)) {
          const hit = firstSecret(stripStrings(m[1]), /type|error|status|len|valid|required/i);
          if (hit) out.push(F("PF013", sf, sf.lineOf(m.index), `\`${hit}\` is sent back in an HTTP response.`));
        }
      }
      return out;
    });

  rule("PF014", "low", "Verbose debug logging enabled",
    "Use CORE_DEBUG_LEVEL=1 (errors only) or lower for release builds.",
    (files) => {
      const out = [];
      for (const sf of files)
        for (const m of all(R(String.raw`CORE_DEBUG_LEVEL\s*=\s*[45]\b|^CONFIG_LOG_DEFAULT_LEVEL_(?:DEBUG|VERBOSE)\s*=\s*y`, "m"), sf.code))
          out.push(F("PF014", sf, sf.lineOf(m.index), "Debug/verbose logs can leak keys, URLs and memory contents."));
      return out;
    });

  rule("PF015", "low", "Remote debug console enabled",
    "Remove Telnet/RemoteDebug in release builds or protect it with a password.",
    (files) => {
      const out = [];
      for (const sf of files) {
        if (sf.isConfig) continue;
        for (const m of all(R(String.raw`\bRemoteDebug\b\s+\w+\s*;|TelnetStream\s*\.\s*begin\s*\(|\bESPTelnet\b\s+\w+\s*;`), sf.code))
          out.push(F("PF015", sf, sf.lineOf(m.index), "A network debug console (telnet) is enabled with no login."));
      }
      return out;
    });

  // ------------------------------------------------------------ run
  function scan(inputs, opts = {}) {
    // inputs: [{path, text}]
    const files = inputs.filter((f) => opts.force || shouldScan(f.path, opts.includeLibs))
      .map((f) => makeFile(f.path, f.text));
    let findings = [];
    for (const id of Object.keys(RULES)) findings = findings.concat(RULES[id].fn(files));
    const uniq = new Map();
    for (const x of findings) { const k = `${x.rule}\0${x.file}\0${x.line}`; if (!uniq.has(k)) uniq.set(k, x); }
    // Python sorts str paths by code point; mimic that (not localeCompare)
    const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
    const sorted = [...uniq.values()].sort((a, b) =>
      SEV_ORDER[b.severity] - SEV_ORDER[a.severity] || cmp(a.file, b.file) || a.line - b.line);
    return { filesScanned: files.length, findings: sorted };
  }

  const api = { scan, shouldScan, isPlaceholder, mask, RULES, SEV_ORDER, version: "0.1.0" };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.preflash = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
