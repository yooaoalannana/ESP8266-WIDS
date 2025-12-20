/*************************************************
 * ESP8266 Wi-Fi WIDS (Sensor Node)
 * Board: NodeMCU / ESP8266
 * Mode : Passive Sniffer
 *************************************************/

extern "C" {
  #include "user_interface.h"
}

#include <Arduino.h>

// ================= CONFIG =================
#define DEAUTH_WINDOW_MS 5000
#define DEAUTH_THRESHOLD 25
#define MAX_SSIDS 10
#define MAX_BSSID_PER_SSID 3

// ================= STRUCTS =================
struct DeauthEvent {
  unsigned long ts;
};

struct SSIDEntry {
  String ssid;
  uint8_t bssid_count;
  uint8_t bssids[6 * MAX_BSSID_PER_SSID];
};

// ================= GLOBAL =================
DeauthEvent deauthEvents[100];
int deauthIndex = 0;

SSIDEntry ssidTable[MAX_SSIDS];
int ssidCount = 0;

// ================= HELPERS =================
void pruneDeauth(unsigned long now) {
  int j = 0;
  for (int i = 0; i < deauthIndex; i++) {
    if (now - deauthEvents[i].ts <= DEAUTH_WINDOW_MS) {
      deauthEvents[j++] = deauthEvents[i];
    }
  }
  deauthIndex = j;
}

void emitAlert(const char* type, const char* severity, const char* msg) {
  Serial.print("{\"type\":\"");
  Serial.print(type);
  Serial.print("\",\"severity\":\"");
  Serial.print(severity);
  Serial.print("\",\"msg\":\"");
  Serial.print(msg);
  Serial.println("\"}");
}

// ================= SNIFFER =================
void sniffer(uint8_t *buf, uint16_t len) {
  if (len < 12) return;

  uint8_t frameType = buf[0];
  unsigned long now = millis();

  // ===== Deauth / Disassoc =====
  if (frameType == 0xC0 || frameType == 0xA0) {
    deauthEvents[deauthIndex++].ts = now;
    pruneDeauth(now);

    if (deauthIndex >= DEAUTH_THRESHOLD) {
      emitAlert("deauth_attack", "high", "Deauthentication flood detected");
      deauthIndex = 0;
    }
  }

  // ===== Beacon (Evil Twin heuristic) =====
  if (frameType == 0x80 && len > 38) {
    uint8_t *bssid = buf + 10;
    uint8_t *ssidElt = buf + 36;

    if (ssidElt[0] == 0 && ssidElt[1] <= 32) {
      char ssid[33];
      memcpy(ssid, ssidElt + 2, ssidElt[1]);
      ssid[ssidElt[1]] = '\0';

      int idx = -1;
      for (int i = 0; i < ssidCount; i++) {
        if (ssidTable[i].ssid == ssid) {
          idx = i;
          break;
        }
      }

      if (idx == -1 && ssidCount < MAX_SSIDS) {
        ssidTable[ssidCount].ssid = ssid;
        ssidTable[ssidCount].bssid_count = 0;
        idx = ssidCount++;
      }

      if (idx >= 0) {
        SSIDEntry &e = ssidTable[idx];
        bool known = false;

        for (int i = 0; i < e.bssid_count; i++) {
          if (memcmp(e.bssids + i * 6, bssid, 6) == 0) {
            known = true;
            break;
          }
        }

        if (!known && e.bssid_count < MAX_BSSID_PER_SSID) {
          memcpy(e.bssids + e.bssid_count * 6, bssid, 6);
          e.bssid_count++;

          if (e.bssid_count >= MAX_BSSID_PER_SSID) {
            emitAlert("evil_twin", "medium", ssid);
          }
        }
      }
    }
  }
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  delay(200);

  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(sniffer);
  wifi_promiscuous_enable(1);

  Serial.println("{\"status\":\"ESP8266 WIDS started\"}");
}

void loop() {
  // passive sniffer
}
