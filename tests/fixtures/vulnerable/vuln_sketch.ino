// Smart greenhouse controller - ESP32
// Typical hobbyist / AI-generated sketch. Every issue below is deliberate.
#include <WiFi.h>
#include <WebServer.h>
#include <PubSubClient.h>
#include <HTTPClient.h>
#include <ArduinoOTA.h>
#include <BlynkSimpleEsp32.h>

#define BLYNK_AUTH_TOKEN "Xk3vQ9pLm2RtY7wZbN4cF8dH1jS6gA0e"   // [T1] Blynk token

const char* ssid = "VirginMedia4521";                        // [T2] Wi-Fi SSID
const char* password = "greenhouse2024!";                    // [T3] Wi-Fi password

const char* mqtt_server = "broker.hivemq.com";               // [T4] public broker, no TLS
const int mqtt_port = 1883;
const char* mqtt_user = "farmuser";                          // [T5] MQTT username
const char* mqtt_pass = "Turmeric@123";                      // [T6] MQTT password

String telegramToken = "7412589630:AAFh3kLqZ9xYv2mNpRtW8sDcE4gBhJ5uK1o"; // [T7] Telegram bot token
String weatherApi = "http://api.openweathermap.org/data/2.5/weather?q=Bristol&appid=8f3c2a1b9d7e6f5a4c3b2a1d0e9f8a7b"; // [T8] API key in URL over HTTP

WebServer server(80);
WiFiClient espClient;
PubSubClient client(espClient);

void handleRelay() {                                          // [T9] web control with no auth
  String state = server.arg("state");
  digitalWrite(5, state == "on" ? HIGH : LOW);
  server.send(200, "text/plain", "OK");
}

void handleConfig() {                                         // [T10] leaks creds over HTTP
  server.send(200, "text/plain", String("ssid=") + ssid + " pass=" + password);
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) delay(500);
  Serial.print("Connected with password: ");                  // [T11] secret printed to serial
  Serial.println(password);

  WiFi.softAP("Greenhouse-Setup", "12345678");                // [T12] weak hard-coded AP password

  ArduinoOTA.begin();                                         // [T13] OTA with no password

  server.on("/relay", handleRelay);
  server.on("/config", handleConfig);
  server.begin();

  client.setServer(mqtt_server, mqtt_port);
  client.connect("esp32", mqtt_user, mqtt_pass);

  WiFiClientSecure secure;
  secure.setInsecure();                                       // [T14] TLS verification disabled

  HTTPClient http;
  http.begin(weatherApi);
  http.GET();

  Blynk.begin(BLYNK_AUTH_TOKEN, ssid, password);
}

void loop() {
  server.handleClient();
  ArduinoOTA.handle();
  client.loop();
  Blynk.run();
}
