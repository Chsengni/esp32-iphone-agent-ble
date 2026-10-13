// Two last association hypotheses, after plain/WPA2-only/pinned-BSSID all failed with
// reason=2 (WIFI_REASON_AUTH_EXPIRE, and no STA_CONNECTED ever fires):
//
//   E  spoof a random locally-administered MAC -> if the AP has a stale or blocked
//      entry for f0:9e:9e:11:55:1c (MAC filter / whitelist / duplicate), this connects.
//   F  force threshold.authmode=WIFI_AUTH_WPA3_PSK -> if the AP is actually WPA3-only
//      (the RSN IE advertises GCMP+CCMP), this connects.
//
// It also proves the transmitter works: an ACTIVE scan gets probe responses, a PASSIVE
// scan only hears beacons. If active returns many more APs than passive, TX is fine.

#include <WiFi.h>
#include <esp_wifi.h>
#include "secrets.h"

static volatile int lastReason = -1;

const char *reasonName(int r) {
  switch (r) {
    case 0: return "UNSPECIFIED";
    case 2: return "AUTH_EXPIRE";
    case 3: return "AUTH_LEAVE";
    case 4: return "ASSOC_EXPIRE/INACTIVITY";
    case 5: return "ASSOC_TOOMANY";
    case 6: return "NOT_AUTHED";
    case 7: return "NOT_ASSOCED";
    case 8: return "ASSOC_LEAVE";
    case 15: return "4WAY_HANDSHAKE_TIMEOUT";
    case 16: return "GROUP_KEY_UPDATE_TIMEOUT";
    case 23: return "802_1X_AUTH_FAILED";
    case 24: return "CIPHER_SUITE_REJECTED";
    case 36: return "STA_LEAVING(local)";
    case 200: return "BEACON_TIMEOUT";
    case 201: return "NO_AP_FOUND";
    case 202: return "AUTH_FAIL";
    case 203: return "ASSOC_FAIL";
    case 204: return "HANDSHAKE_TIMEOUT";
    case 205: return "CONNECTION_FAIL";
    default: return "?";
  }
}

void onWifiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_START:
      Serial.println("    [evt] STA_START");
      break;
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      Serial.println("    [evt] *** STA_CONNECTED (associated) ***");
      break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      Serial.printf("    [evt] GOT_IP %s\n", IPAddress(info.got_ip.ip_info.ip.addr).toString().c_str());
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      lastReason = info.wifi_sta_disconnected.reason;
      break;
    default:
      break;
  }
}

bool waitConnected(const char *label, unsigned long ms) {
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < ms) {
    delay(500);
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("  >>> %s: CONNECTED ip=%s rssi=%d ch=%d\n", label, WiFi.localIP().toString().c_str(),
                  WiFi.RSSI(), WiFi.channel());
    return true;
  }
  Serial.printf("  >>> %s: FAILED after %lu ms (lastReason=%d %s)\n", label, millis() - t0, lastReason,
                reasonName(lastReason));
  return false;
}

void reset_wifi() {
  WiFi.disconnect(false, false);
  delay(400);
  WiFi.mode(WIFI_OFF);
  delay(400);
  WiFi.mode(WIFI_STA);
  delay(400);
  lastReason = -1;
}

void setup() {
  Serial.begin(115200);
  delay(2500);
  Serial.println("\n=== wifi: MAC-spoof and WPA3-SAE tests ===");
  Serial.printf("chip=%s\n", ESP.getChipModel());

  WiFi.onEvent(onWifiEvent);
  WiFi.persistent(false);
  WiFi.setSleep(false);
  WiFi.mode(WIFI_STA);
  delay(300);
  Serial.printf("factory station MAC : %s\n", WiFi.macAddress().c_str());

  // ---- TX proof: active vs passive scan ----
  int act = WiFi.scanNetworks(false, false, false, 300, 0);
  WiFi.scanDelete();
  delay(500);
  int pas = WiFi.scanNetworks(false, true, true, 300, 0);  // async=false, show_hidden=true, passive=true
  WiFi.scanDelete();
  Serial.printf("scan ACTIVE=%d  PASSIVE=%d  -> TX %s\n", act, pas,
                act >= pas ? "OK (probe requests answered)" : "SUSPECT");

  // ---- E: random locally-administered MAC ----
  Serial.println("\n[E] spoofed random MAC + plain WPA2 begin");
  reset_wifi();
  uint8_t mac[6] = {0x02, 0x00, 0x00, 0x11, 0x22, 0x33};
  mac[3] = (uint8_t)random(0, 256);
  mac[4] = (uint8_t)random(0, 256);
  mac[5] = (uint8_t)random(0, 256);
  esp_err_t e = esp_wifi_set_mac(WIFI_IF_STA, mac);
  Serial.printf("  esp_wifi_set_mac -> %s\n", esp_err_to_name(e));
  Serial.printf("  station MAC now     : %s\n", WiFi.macAddress().c_str());
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  if (waitConnected("E spoofed-mac", 25000)) goto done;

  // ---- F: WPA3-SAE only ----
  Serial.println("\n[F] threshold.authmode=WPA3_PSK (SAE only)");
  reset_wifi();
  {
    wifi_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy((char *)cfg.sta.ssid, WIFI_SSID, sizeof(cfg.sta.ssid) - 1);
    strncpy((char *)cfg.sta.password, WIFI_PASS, sizeof(cfg.sta.password) - 1);
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA3_PSK;
    cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    Serial.printf("  esp_wifi_set_config -> %s\n", esp_err_to_name(esp_wifi_set_config(WIFI_IF_STA, &cfg)));
  }
  esp_wifi_connect();
  if (waitConnected("F wpa3-sae", 25000)) goto done;

done:
  Serial.println("\n=== done ===");
}

void loop() {
  static unsigned long last = 0;
  if (millis() - last > 20000) {
    last = millis();
    Serial.printf("[%8lu] status=%d ip=%s lastReason=%d(%s)\n", millis(), (int)WiFi.status(),
                  WiFi.localIP().toString().c_str(), lastReason, reasonName(lastReason));
  }
  delay(100);
}
