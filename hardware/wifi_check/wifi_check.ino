// Wi-Fi diagnostic for the HID bridge: scan, connect, report, probe the server.
//
// Flash with the same FQBN as hid_bridge (USBMode=default,CDCOnBoot=cdc) so that
// `Serial` is routed to the native USB CDC, then read the port to see exactly
// what the radio is doing: which 2.4 GHz networks exist, whether the target SSID
// is among them, what the connect attempt returns, and whether the server port
// is actually reachable from the board.

#include <WiFi.h>
#include "secrets.h"

const char *statusName(wl_status_t s) {
  switch (s) {
    case WL_IDLE_STATUS: return "IDLE";
    case WL_NO_SSID_AVAIL: return "NO_SSID_AVAIL (not found / out of range)";
    case WL_SCAN_COMPLETED: return "SCAN_COMPLETED";
    case WL_CONNECTED: return "CONNECTED";
    case WL_CONNECT_FAILED: return "CONNECT_FAILED (bad password?)";
    case WL_CONNECTION_LOST: return "CONNECTION_LOST";
    case WL_DISCONNECTED: return "DISCONNECTED";
    default: return "UNKNOWN";
  }
}

void setup() {
  Serial.begin(115200);
  delay(2500);  // let the USB CDC enumerate before we start talking
  Serial.println();
  Serial.println("=== hid_bridge wifi_check ===");
  Serial.printf("target SSID   : \"%s\"\n", WIFI_SSID);
  Serial.printf("target server : %s:%d\n", SERVER_HOST, SERVER_PORT);
  Serial.printf("station MAC   : %s\n", WiFi.macAddress().c_str());

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(300);

  Serial.println("\n--- scan (2.4 GHz only) ---");
  int n = WiFi.scanNetworks();
  Serial.printf("found %d networks\n", n);
  bool found = false;
  for (int i = 0; i < n; i++) {
    bool hit = WiFi.SSID(i) == WIFI_SSID;
    if (hit) found = true;
    Serial.printf("%s ch%-3d %4d dBm  %-30s %s\n", hit ? "*" : " ", WiFi.channel(i), WiFi.RSSI(i),
                  WiFi.SSID(i).c_str(), WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "open" : "encrypted");
  }
  if (!found) {
    Serial.println("\n!! TARGET SSID NOT FOUND in the 2.4 GHz scan");
    Serial.println("   -> misspelled SSID, out of range, or the AP is 5 GHz only");
  }

  Serial.println("\n--- connecting ---");
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 25000) {
    delay(500);
    Serial.printf("  %5lu ms  status=%d %s\n", millis() - t0, WiFi.status(), statusName(WiFi.status()));
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\nCONNECTED in %lu ms\n", millis() - t0);
    Serial.printf("  ip      : %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("  gateway : %s\n", WiFi.gatewayIP().toString().c_str());
    Serial.printf("  netmask : %s\n", WiFi.subnetMask().toString().c_str());
    Serial.printf("  dns     : %s\n", WiFi.dnsIP().toString().c_str());
    Serial.printf("  rssi    : %d dBm\n", WiFi.RSSI());
    Serial.printf("  channel : %d\n", WiFi.channel());

    Serial.println("\n--- probing server port ---");
    WiFiClient c;
    if (c.connect(SERVER_HOST, SERVER_PORT, 4000)) {
      Serial.printf("  %s:%d OPEN\n", SERVER_HOST, SERVER_PORT);
      c.stop();
    } else {
      Serial.printf("  %s:%d UNREACHABLE (server down, or AP client isolation)\n", SERVER_HOST, SERVER_PORT);
    }
  } else {
    Serial.printf("\nFAILED after %lu ms: %s\n", millis() - t0, statusName(WiFi.status()));
  }
  Serial.println("=== done; live status below ===");
}

void loop() {
  static unsigned long last = 0;
  if (millis() - last > 20000) {
    last = millis();
    Serial.printf("\n[%8lu] wifi=%s ip=%s rssi=%d heap=%u\n", millis(), statusName(WiFi.status()),
                  WiFi.localIP().toString().c_str(), WiFi.RSSI(), (unsigned)ESP.getFreeHeap());
    Serial.println("--- rescan ---");
    int n = WiFi.scanNetworks();
    Serial.printf("found %d networks\n", n);
    for (int i = 0; i < n && i < 25; i++) {
      bool hit = WiFi.SSID(i) == WIFI_SSID;
      Serial.printf("%s ch%-3d %4d dBm  %-30s %s\n", hit ? "*" : " ", WiFi.channel(i), WiFi.RSSI(i),
                    WiFi.SSID(i).c_str(), WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "open" : "enc");
    }
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("retrying WiFi.begin()...");
      WiFi.begin(WIFI_SSID, WIFI_PASS);
    }
  }
  delay(100);
}
