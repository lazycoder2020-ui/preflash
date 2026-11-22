// Same greenhouse controller, written safely
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <WebServer.h>
#include <ArduinoOTA.h>
#include "arduino_secrets.h"   // git-ignored

const char* ssid = "YOUR_SSID";
const char* password = "YOUR_PASSWORD";   // placeholder, real one in secrets
const char* mqtt_server = "broker.example.com";
const int mqtt_port = 8883;
char keyboardLayout[] = "en-GB-layout-2024";

WebServer server(80);
WiFiClientSecure net;
PubSubClient client(net);

void handleRelay() {
  if (!server.authenticate(WEB_USER, WEB_PASS)) return server.requestAuthentication();
  server.send(200, "text/plain", "OK");
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(SECRET_SSID, SECRET_PASS);
  Serial.printf("password length: %d\n", strlen(SECRET_PASS));
  Serial.println("Enter your password in the portal");
  net.setCACert(ROOT_CA);
  ArduinoOTA.setPasswordHash(OTA_HASH);
  ArduinoOTA.begin();
  server.on("/relay", handleRelay);
  server.begin();
  client.setServer(mqtt_server, mqtt_port);
  client.connect("esp32", MQTT_USER, MQTT_PASS);
  WiFi.softAP("Greenhouse-Setup", AP_PASS);
}
void loop() { server.handleClient(); ArduinoOTA.handle(); }
