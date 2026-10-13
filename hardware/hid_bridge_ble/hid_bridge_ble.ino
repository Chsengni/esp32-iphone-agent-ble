// HID bridge over BLE: the board presents itself to the phone as a Bluetooth
// mouse + keyboard (HID over GATT), so it works on boards whose native USB pins
// never reach a connector (e.g. the CH340-based ESP32-S3 UNO, which has a single
// USB-C port wired to the CH340 UART bridge instead of to IO19/IO20).
//
// Same line protocol as hid_bridge, so the server needs no changes:
//   ping | home | move <dx> <dy> | press | release | click
//   scroll <v> <h> | type <ascii text> | key <combo, e.g. cmd+h, enter>
//   hid  -> diagnostics (works with no phone attached)
//
// Pairing on iOS:
//   设置 -> 辅助功能 -> 触控 -> 辅助触控 -> 设备(Devices) -> 蓝牙设备(Bluetooth Devices)
//   -> pick "HID Bridge S3". (Turn AssistiveTouch on first; that is what draws the pointer.)
//
// ---------------------------------------------------------------------------
// WHY THIS FILE LOOKS THE WAY IT DOES  (the pointer would not move)
// ---------------------------------------------------------------------------
// A working reference implementation of the same idea (github.com/boboabw/phone-agent,
// ESP-IDF + NimBLE) requires THREE things before it will send a single HID report:
//
//     static bool ready(void) {
//       return link_exists(hid_connection) && encrypted(hid_connection) && subscribed() && !suspended;
//     }
//
// and it configures security explicitly:
//
//     ble_hs_cfg.sm_bonding = 1;  ble_hs_cfg.sm_mitm = 0;  ble_hs_cfg.sm_sc = 1;
//
// arduino-esp32's NimBLE port instead defaults to  ble_hs_cfg.sm_bonding = 0
// (BLEDevice.cpp), and its server connect path never calls ble_gap_security_initiate()
// -- only the Bluedroid path does. The result is a board that iOS can connect to, and
// that reports "connected" in AssistiveTouch, while the HID host never binds it as a
// *paired* pointing device: every report is accepted and ignored, so the pointer sits
// still and nothing ever errors out.
//
// So this sketch now: enables bonding + LE Secure Connections, initiates pairing on
// connect, and refuses to claim success for a move until the link is encrypted --
// turning a silent no-op into an actionable error.
//
// Its docs also warn that a host caches the HID descriptor of a bonded device, so after
// a firmware/descriptor change you must forget the device on the phone and re-pair.
// The advertised name therefore carries a generation suffix; bump it whenever the
// report map changes so iOS is forced to treat the board as new.
// ---------------------------------------------------------------------------

#include <WiFi.h>
#include <esp_task_wdt.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLESecurity.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <BLEHIDDevice.h>
#include <HIDTypes.h>
#include "secrets.h"  // WIFI_SSID, WIFI_PASS, SERVER_HOST, SERVER_PORT

#ifndef DEBUG_SERIAL
#define DEBUG_SERIAL 1  // echo every command over the CH340 UART at 115200
#endif

// Refuse to report success for a pointer move unless the link is encrypted. This is what
// the known-good reference firmware does, and it converts the worst failure mode (moves
// silently doing nothing) into a message the operator can act on.
#define REQUIRE_ENCRYPTED 1

// Bump this whenever the HID report map or the service layout changes: iOS caches the
// descriptor of a bonded accessory, and a new name is the reliable way to defeat it.
#define DEVICE_NAME "HID Bridge S3"

const int STEP = 10;      // max pointer delta per report while moving
const int STEP_MS = 12;   // BLE notifications are slower than USB: keep a calmer pace
const int HOME_REPORTS = 40;
const int WATCHDOG_MS = 8000;

// NimBLE IO capability 3 = NoInputNoOutput ("Just Works", no passkey to type); this is the
// same value Bluedroid calls ESP_IO_CAP_NONE. Kept numeric so the sketch does not depend
// on NimBLE host headers being reachable.
static const uint8_t IO_CAP_NO_INPUT_OUTPUT = 3;

// ---- modifier bits (HID keyboard report byte 0) ----
#define MOD_LCTRL 0x01
#define MOD_LSHIFT 0x02
#define MOD_LALT 0x04
#define MOD_LGUI 0x08
#define MOD_RCTRL 0x10
#define MOD_RSHIFT 0x20
#define MOD_RALT 0x40
#define MOD_RGUI 0x80

// ---- HID keycodes we name explicitly ----
#define KC_ENTER 0x28
#define KC_ESC 0x29
#define KC_BACKSPACE 0x2A
#define KC_TAB 0x2B
#define KC_SPACE 0x2C
#define KC_RIGHT 0x4F
#define KC_LEFT 0x50
#define KC_DOWN 0x51
#define KC_UP 0x52
#define KC_HOME 0x4A
#define KC_END 0x4D
#define KC_DELETE 0x4C
#define KC_PAGEUP 0x4B
#define KC_PAGEDOWN 0x4E

// Combined mouse (report ID 1) + keyboard (report ID 2) descriptor.
// Byte-for-byte identical to the report map of the known-good iOS reference firmware.
static const uint8_t hidReportDescriptor[] = {
    // ---------- Mouse ----------
    0x05, 0x01,  // USAGE_PAGE (Generic Desktop)
    0x09, 0x02,  // USAGE (Mouse)
    0xA1, 0x01,  // COLLECTION (Application)
    0x85, 0x01,  //   REPORT_ID (1)
    0x09, 0x01,  //   USAGE (Pointer)
    0xA1, 0x00,  //   COLLECTION (Physical)
    0x05, 0x09,  //     USAGE_PAGE (Button)
    0x19, 0x01,  //     USAGE_MINIMUM (Button 1)
    0x29, 0x03,  //     USAGE_MAXIMUM (Button 3)
    0x15, 0x00,  //     LOGICAL_MINIMUM (0)
    0x25, 0x01,  //     LOGICAL_MAXIMUM (1)
    0x95, 0x03,  //     REPORT_COUNT (3)
    0x75, 0x01,  //     REPORT_SIZE (1)
    0x81, 0x02,  //     INPUT (Data,Var,Abs)
    0x95, 0x01,  //     REPORT_COUNT (1)
    0x75, 0x05,  //     REPORT_SIZE (5)
    0x81, 0x03,  //     INPUT (Cnst,Var,Abs)
    0x05, 0x01,  //     USAGE_PAGE (Generic Desktop)
    0x09, 0x30,  //     USAGE (X)
    0x09, 0x31,  //     USAGE (Y)
    0x09, 0x38,  //     USAGE (Wheel)
    0x15, 0x81,  //     LOGICAL_MINIMUM (-127)
    0x25, 0x7F,  //     LOGICAL_MAXIMUM (127)
    0x75, 0x08,  //     REPORT_SIZE (8)
    0x95, 0x03,  //     REPORT_COUNT (3)
    0x81, 0x06,  //     INPUT (Data,Var,Rel)
    0xC0,        //   END_COLLECTION
    0xC0,        // END_COLLECTION

    // ---------- Keyboard ----------
    0x05, 0x01,  // USAGE_PAGE (Generic Desktop)
    0x09, 0x06,  // USAGE (Keyboard)
    0xA1, 0x01,  // COLLECTION (Application)
    0x85, 0x02,  //   REPORT_ID (2)
    0x05, 0x07,  //   USAGE_PAGE (Keyboard)
    0x19, 0xE0,  //   USAGE_MINIMUM (Left Control)
    0x29, 0xE7,  //   USAGE_MAXIMUM (Right GUI)
    0x15, 0x00,  //   LOGICAL_MINIMUM (0)
    0x25, 0x01,  //   LOGICAL_MAXIMUM (1)
    0x75, 0x01,  //   REPORT_SIZE (1)
    0x95, 0x08,  //   REPORT_COUNT (8)
    0x81, 0x02,  //   INPUT (Data,Var,Abs)   modifiers
    0x95, 0x01,  //   REPORT_COUNT (1)
    0x75, 0x08,  //   REPORT_SIZE (8)
    0x81, 0x03,  //   INPUT (Cnst,Var,Abs)   reserved
    0x95, 0x06,  //   REPORT_COUNT (6)
    0x75, 0x08,  //   REPORT_SIZE (8)
    0x15, 0x00,  //   LOGICAL_MINIMUM (0)
    0x25, 0x65,  //   LOGICAL_MAXIMUM (101)
    0x05, 0x07,  //   USAGE_PAGE (Keyboard)
    0x19, 0x00,  //   USAGE_MINIMUM (0)
    0x29, 0x65,  //   USAGE_MAXIMUM (101)
    0x81, 0x00,  //   INPUT (Data,Ary,Abs)   keycodes
    0x05, 0x08,  //   USAGE_PAGE (LEDs)
    0x19, 0x01,  //   USAGE_MINIMUM (Num Lock)
    0x29, 0x05,  //   USAGE_MAXIMUM (Kana)
    0x95, 0x05,  //   REPORT_COUNT (5)
    0x75, 0x01,  //   REPORT_SIZE (1)
    0x91, 0x02,  //   OUTPUT (Data,Var,Abs)
    0x95, 0x01,  //   REPORT_COUNT (1)
    0x75, 0x03,  //   REPORT_SIZE (3)
    0x91, 0x03,  //   OUTPUT (Cnst,Var,Abs)
    0xC0         // END_COLLECTION
};

BLEServer *bleServer = nullptr;
BLEHIDDevice *hid = nullptr;
BLECharacteristic *inputMouse = nullptr;
BLECharacteristic *inputKeyboard = nullptr;
BLECharacteristic *bootMouse = nullptr;  // 0x2A33 Boot Mouse Input Report (3-byte, no report ID)
volatile bool phoneConnected = false;

// ---------------------------------------------------------------- link state
//
// Everything the host needs before a report can be acted on. Tracked separately because
// "connected" is the least interesting of them -- that is the state that used to fool us.

static volatile uint16_t connHandle = 0xFFFF;
static volatile bool linkEncrypted = false;
static volatile bool mouseSubscribed = false;
static volatile bool kbdSubscribed = false;
static volatile bool bootSubscribed = false;
static volatile uint16_t peerMtu = 0;
static volatile uint8_t protocolMode = 1;  // 1 = Report Protocol, 0 = Boot Protocol

// Positive proof of transmission: notify() reports SUCCESS_NOTIFY only when the stack
// really handed the report to the controller. A silent MTU==0 skip increments nothing and
// logs nothing, so these counters are the only way to tell "sent" from "swallowed".
static volatile uint32_t mouseSent = 0;
static volatile uint32_t kbdSent = 0;
static volatile uint32_t bootSent = 0;

WiFiClient server;
uint8_t mouseButtons = 0;

// ---------------------------------------------------------------- diagnostics

class HidStatusCallbacks : public BLECharacteristicCallbacks {
 public:
  HidStatusCallbacks(const char *label, volatile uint32_t *sent) : _label(label), _sent(sent) {}

  void onStatus(BLECharacteristic *, Status s, uint32_t code) override {
    if (s == SUCCESS_NOTIFY) {  // the normal case: count it, stay quiet
      (*_sent)++;
      return;
    }
    Serial.printf("[hid] %s notify dropped: status=%d code=%u\n", _label, (int)s, code);
  }

  // NimBLE only. This is the definitive proof that the host enabled notifications:
  // BLECharacteristic::notify() bails out (or silently skips on MTU==0) without it.
  void onSubscribe(BLECharacteristic *c, ble_gap_conn_desc *desc, uint16_t subValue) override {
    bool on = subValue != 0;
    if (c == inputMouse) {
      mouseSubscribed = on;
    } else if (c == inputKeyboard) {
      kbdSubscribed = on;
    } else if (c == bootMouse) {
      bootSubscribed = on;
    }
    Serial.printf("[hid] %s SUBSCRIBE val=%u conn=%u\n", _label, (unsigned)subValue,
                  (unsigned)(desc ? desc->conn_handle : 0));
  }

 private:
  const char *_label;
  volatile uint32_t *_sent;
};

// A host may ask for Boot Protocol (0x00) instead of Report Protocol (0x01). Boot mode
// uses the 3-byte 0x2A33 report and ignores the wheel, so the mode has to be honoured.
class ProtocolModeCallbacks : public BLECharacteristicCallbacks {
 public:
  void onWrite(BLECharacteristic *c) override {
    if (c->getValue().length() < 1) return;
    protocolMode = c->getValue()[0] ? 1 : 0;
    Serial.printf("[hid] PROTOCOL MODE -> %u (%s)\n", (unsigned)protocolMode,
                  protocolMode ? "report" : "BOOT");
  }
};

class SecurityCallbacks : public BLESecurityCallbacks {
 public:
  // status is 0 on success; the desc carries the resulting security state.
  void onAuthenticationComplete(ble_gap_conn_desc *desc, int status) override {
    linkEncrypted = desc != nullptr && desc->sec_state.encrypted;
    Serial.printf("[ble] AUTH status=%d encrypted=%d bonded=%d\n", status, linkEncrypted,
                  desc ? (int)desc->sec_state.bonded : 0);
  }
  uint32_t onPassKeyRequest() override { return 0; }
  bool onConfirmPIN(uint32_t) override { return true; }
  void onPassKeyNotify(uint32_t) override {}
  bool onSecurityRequest() override { return true; }
};

static bool linkReady() {
#if REQUIRE_ENCRYPTED
  return phoneConnected && linkEncrypted;
#else
  return phoneConnected;
#endif
}

String hidState() {
  String s = "conns=";
  s += (int)(bleServer ? bleServer->getConnectedCount() : 0);
  s += " enc=";
  s += (linkEncrypted ? 1 : 0);
  s += " proto=";
  s += (int)protocolMode;
  s += " mtu=";
  s += (int)peerMtu;
  s += " mouseSub=";
  s += (mouseSubscribed ? 1 : 0);
  s += " kbdSub=";
  s += (kbdSubscribed ? 1 : 0);
  s += " bootSub=";
  s += (bootSubscribed ? 1 : 0);
  s += " sent=";
  s += (unsigned long)mouseSent;
  s += " kbdSent=";
  s += (unsigned long)kbdSent;
  s += " mouseHandle=";
  s += (int)(inputMouse ? inputMouse->getHandle() : 0);
  s += " kbdHandle=";
  s += (int)(inputKeyboard ? inputKeyboard->getHandle() : 0);
  s += " bootHandle=";
  s += (int)(bootMouse ? bootMouse->getHandle() : 0);
  return s;
}

// ---------------------------------------------------------------- BLE plumbing

class ServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer *s) override {
    phoneConnected = true;
  }

  // NimBLE gives us the descriptor, so the handle and the security state are visible here.
  void onConnect(BLEServer *s, ble_gap_conn_desc *desc) override {
    phoneConnected = true;
    if (desc) {
      connHandle = desc->conn_handle;
      linkEncrypted = desc->sec_state.encrypted;
    }
    Serial.printf("[ble] phone connected handle=%u encrypted=%d bonded=%d\n",
                  (unsigned)connHandle, linkEncrypted, desc ? (int)desc->sec_state.bonded : 0);
    if (desc) {
      // arduino-esp32 only initiates pairing from its Bluedroid paths; on NimBLE the
      // server must ask. Without this the phone connects but never bonds, and an
      // unbonded link is not a pointing device as far as AssistiveTouch is concerned.
      int rc = 0;
      BLESecurity::startSecurity(desc->conn_handle, &rc);
      Serial.printf("[ble] security_initiate rc=%d\n", rc);
    }
  }

  void onDisconnect(BLEServer *s) override {
    phoneConnected = false;
    linkEncrypted = false;
    mouseSubscribed = kbdSubscribed = bootSubscribed = false;
    peerMtu = 0;
    mouseButtons = 0;
    Serial.println("[ble] phone disconnected; re-advertising");
    delay(300);
    s->startAdvertising();  // be findable again straight away
  }

  void onMtuChanged(BLEServer *s, ble_gap_conn_desc *desc, uint16_t mtu) override {
    peerMtu = mtu;
    Serial.printf("[ble] MTU=%u\n", (unsigned)mtu);
  }
};

// ---------------------------------------------------------------- HID reports

void mouseReport(int8_t dx, int8_t dy, int8_t wheel = 0) {
  if (!phoneConnected) return;
  if (protocolMode == 0) {
    // Boot protocol: 3 bytes, no report ID, no wheel.
    if (bootMouse == nullptr) return;
    uint8_t boot[3] = {mouseButtons, (uint8_t)dx, (uint8_t)dy};
    bootMouse->setValue(boot, sizeof(boot));
    bootMouse->notify();
    return;
  }
  if (inputMouse == nullptr) return;
  uint8_t report[4] = {mouseButtons, (uint8_t)dx, (uint8_t)dy, (uint8_t)wheel};
  inputMouse->setValue(report, sizeof(report));
  inputMouse->notify();
}

void keyboardReport(uint8_t mod, uint8_t code) {
  if (!phoneConnected || inputKeyboard == nullptr) return;
  uint8_t report[8] = {mod, 0, code, 0, 0, 0, 0, 0};
  inputKeyboard->setValue(report, sizeof(report));
  inputKeyboard->notify();
}

void keyboardRelease() { keyboardReport(0, 0); }

void movePaced(long dx, long dy) {
  while (dx || dy) {
    int sx = constrain(dx, -STEP, STEP), sy = constrain(dy, -STEP, STEP);
    mouseReport(sx, sy);
    dx -= sx;
    dy -= sy;
    delay(STEP_MS);
  }
}

// US-layout ASCII -> (modifier, keycode). {0,0} means "cannot type this".
void asciiToKey(char c, uint8_t &mod, uint8_t &code) {
  mod = 0;
  code = 0;
  if (c >= 'a' && c <= 'z') { code = 0x04 + (c - 'a'); return; }
  if (c >= 'A' && c <= 'Z') { mod = MOD_LSHIFT; code = 0x04 + (c - 'A'); return; }
  if (c >= '1' && c <= '9') { code = 0x1E + (c - '1'); return; }
  if (c == '0') { code = 0x27; return; }
  if (c == '\n' || c == '\r') { code = KC_ENTER; return; }
  if (c == '\t') { code = KC_TAB; return; }
  if (c == ' ') { code = KC_SPACE; return; }
  switch (c) {
    case '-': code = 0x2D; return;
    case '=': code = 0x2E; return;
    case '[': code = 0x2F; return;
    case ']': code = 0x30; return;
    case '\\': code = 0x31; return;
    case ';': code = 0x33; return;
    case '\'': code = 0x34; return;
    case '`': code = 0x35; return;
    case ',': code = 0x36; return;
    case '.': code = 0x37; return;
    case '/': code = 0x38; return;
    case '!': mod = MOD_LSHIFT; code = 0x1E; return;
    case '@': mod = MOD_LSHIFT; code = 0x1F; return;
    case '#': mod = MOD_LSHIFT; code = 0x20; return;
    case '$': mod = MOD_LSHIFT; code = 0x21; return;
    case '%': mod = MOD_LSHIFT; code = 0x22; return;
    case '^': mod = MOD_LSHIFT; code = 0x23; return;
    case '&': mod = MOD_LSHIFT; code = 0x24; return;
    case '*': mod = MOD_LSHIFT; code = 0x25; return;
    case '(': mod = MOD_LSHIFT; code = 0x26; return;
    case ')': mod = MOD_LSHIFT; code = 0x27; return;
    case '_': mod = MOD_LSHIFT; code = 0x2D; return;
    case '+': mod = MOD_LSHIFT; code = 0x2E; return;
    case '{': mod = MOD_LSHIFT; code = 0x2F; return;
    case '}': mod = MOD_LSHIFT; code = 0x30; return;
    case '|': mod = MOD_LSHIFT; code = 0x31; return;
    case ':': mod = MOD_LSHIFT; code = 0x33; return;
    case '"': mod = MOD_LSHIFT; code = 0x34; return;
    case '~': mod = MOD_LSHIFT; code = 0x35; return;
    case '<': mod = MOD_LSHIFT; code = 0x36; return;
    case '>': mod = MOD_LSHIFT; code = 0x37; return;
    case '?': mod = MOD_LSHIFT; code = 0x38; return;
  }
}

// A named key from the protocol: returns true and fills mod/code.
bool namedKey(const String &k, uint8_t &mod, uint8_t &code) {
  mod = 0;
  code = 0;
  if (k == "enter") { code = KC_ENTER; return true; }
  if (k == "esc") { code = KC_ESC; return true; }
  if (k == "tab") { code = KC_TAB; return true; }
  if (k == "backspace") { code = KC_BACKSPACE; return true; }
  if (k == "space") { code = KC_SPACE; return true; }
  if (k == "up") { code = KC_UP; return true; }
  if (k == "down") { code = KC_DOWN; return true; }
  if (k == "left") { code = KC_LEFT; return true; }
  if (k == "right") { code = KC_RIGHT; return true; }
  if (k == "home") { code = KC_HOME; return true; }
  if (k == "end") { code = KC_END; return true; }
  if (k == "delete") { code = KC_DELETE; return true; }
  if (k == "pageup") { code = KC_PAGEUP; return true; }
  if (k == "pagedown") { code = KC_PAGEDOWN; return true; }
  // bare modifiers: reported alone, no keycode
  if (k == "cmd" || k == "gui" || k == "win") { mod = MOD_LGUI; return true; }
  if (k == "ctrl" || k == "control") { mod = MOD_LCTRL; return true; }
  if (k == "alt" || k == "opt") { mod = MOD_LALT; return true; }
  if (k == "shift") { mod = MOD_LSHIFT; return true; }
  if (k.length() == 1) {
    asciiToKey(k[0], mod, code);
    return mod || code;
  }
  return false;
}

// "cmd+h" -> LGUI + h. Modifiers may appear in any order and any number.
bool pressCombo(String combo) {
  combo += '+';
  uint8_t mod = 0, code = 0;
  for (int i; (i = combo.indexOf('+')) >= 0; combo = combo.substring(i + 1)) {
    String part = combo.substring(0, i);
    if (!part.length()) continue;
    uint8_t m = 0, c = 0;
    if (!namedKey(part, m, c)) return false;
    mod |= m;
    if (c) code = c;
  }
  keyboardReport(mod, code);
  delay(40);
  keyboardRelease();
  return true;
}

void typeText(const String &text) {
  for (size_t i = 0; i < text.length(); i++) {
    uint8_t mod = 0, code = 0;
    asciiToKey(text[i], mod, code);
    if (!code && !mod) continue;  // skip anything we cannot map (e.g. CJK)
    keyboardReport(mod, code);
    delay(20);
    keyboardRelease();
    delay(20);
  }
}

// ---------------------------------------------------------------- the protocol

String run(const String &line) {
  int sp = line.indexOf(' ');
  String cmd = sp < 0 ? line : line.substring(0, sp);
  String arg = sp < 0 ? "" : line.substring(sp + 1);
  long a = 0, b = 0;
  sscanf(arg.c_str(), "%ld %ld", &a, &b);

  if (cmd == "ping") return "ok";
  if (cmd == "hid") return hidState();  // diagnostics: reachable even with no phone
  if (!phoneConnected) return "err phone ble not connected (pair it in AssistiveTouch)";
#if REQUIRE_ENCRYPTED
  if (!linkEncrypted)
    return "err link not encrypted: forget the device in Settings > Bluetooth, then re-pair in "
           "AssistiveTouch > Devices > Bluetooth Devices";
#endif
  if (cmd == "home") {  // slam the pointer into the top-left corner
    for (int i = 0; i < HOME_REPORTS; i++) { mouseReport(-127, -127); delay(4); }
    return "ok";
  }
  if (cmd == "move") { movePaced(a, b); return "ok"; }
  if (cmd == "press") { mouseButtons |= 0x01; mouseReport(0, 0); return "ok"; }
  if (cmd == "release") { mouseButtons &= ~0x01; mouseReport(0, 0); return "ok"; }
  if (cmd == "click") {
    mouseButtons |= 0x01; mouseReport(0, 0);
    delay(60);
    mouseButtons &= ~0x01; mouseReport(0, 0);
    return "ok";
  }
  if (cmd == "scroll") { mouseReport(0, 0, (int8_t)a); return "ok"; }
  if (cmd == "type") { typeText(arg); return "ok"; }
  if (cmd == "key") return pressCombo(arg) ? "ok" : "err unknown key";
  return "err unknown command";
}

const char *resetReason() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON: return "power-on";
    case ESP_RST_BROWNOUT: return "brownout";
    case ESP_RST_TASK_WDT: case ESP_RST_INT_WDT: case ESP_RST_WDT: return "watchdog";
    case ESP_RST_PANIC: return "crash";
    case ESP_RST_SW: return "software";
    case ESP_RST_USB: return "usb";
    default: return "other";
  }
}

void startBleHid() {
  BLEDevice::init(DEVICE_NAME);

  // Security must be configured AFTER init(): BLEDevice::init() resets ble_hs_cfg and
  // installs its own defaults, which include sm_bonding = 0.
  BLESecurity::setAuthenticationMode(true, false, true);  // bond, no MITM, LE Secure Connections
  BLESecurity::setCapability(IO_CAP_NO_INPUT_OUTPUT);     // "Just Works": nothing to type
  BLEDevice::setSecurityCallbacks(new SecurityCallbacks());

  bleServer = BLEDevice::createServer();
  bleServer->setCallbacks(new ServerCallbacks());

  hid = new BLEHIDDevice(bleServer);
  inputMouse = hid->inputReport(1);     // report ID 1
  inputKeyboard = hid->inputReport(2);  // report ID 2
  // Boot Mouse Input Report (0x2A33): 3 bytes, used when the host selects Boot Protocol.
  bootMouse = hid->hidService()->createCharacteristic(
    (uint16_t)0x2A33, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY
  );
  inputMouse->setCallbacks(new HidStatusCallbacks("mouse", &mouseSent));
  inputKeyboard->setCallbacks(new HidStatusCallbacks("kbd", &kbdSent));
  if (bootMouse != nullptr) bootMouse->setCallbacks(new HidStatusCallbacks("boot", &bootSent));
  hid->protocolMode()->setCallbacks(new ProtocolModeCallbacks());

  hid->manufacturer()->setValue("Espressif");
  hid->pnp(0x02, 0x303A, 0x1001, 0x0100);
  hid->hidInfo(0x00, 0x02);  // flags 0x02 = normally connectable (matches the iOS-accepted reference)
  hid->reportMap((uint8_t *)hidReportDescriptor, sizeof(hidReportDescriptor));
  hid->startServices();
  hid->setBatteryLevel(100);

  BLEAdvertising *adv = bleServer->getAdvertising();
  adv->setAppearance(0x03C0);  // Generic HID (mouse + keyboard), as the working reference does
  adv->addServiceUUID(hid->hidService()->getUUID());
  adv->setScanResponse(true);
  adv->setMinInterval(0x20);
  adv->setMaxInterval(0x40);
  adv->start();

#if DEBUG_SERIAL
  Serial.printf("[ble] advertising as \"%s\" (mouse + keyboard)\n", DEVICE_NAME);
  // Handle allocation is the quickest way to see a characteristic that never made it into
  // the service definition: 65535 (0xFFFF) is the library's NULL_HANDLE.
  Serial.printf("[ble] handles mouse=%u kbd=%u boot=%u\n",
                (unsigned)(inputMouse ? inputMouse->getHandle() : 0),
                (unsigned)(inputKeyboard ? inputKeyboard->getHandle() : 0),
                (unsigned)(bootMouse ? bootMouse->getHandle() : 0));
#endif
}

void setup() {
#if DEBUG_SERIAL
  Serial.begin(115200);
  delay(1500);  // the CH340 UART needs a moment after reset
  Serial.println("\n=== hid_bridge_ble ===");
#endif

  startBleHid();

  esp_task_wdt_config_t wdt = {.timeout_ms = WATCHDOG_MS, .idle_core_mask = 0, .trigger_panic = true};
  esp_task_wdt_reconfigure(&wdt);
  esp_task_wdt_add(NULL);

  WiFi.setHostname("hid-bridge");
  WiFi.setSleep(false);  // modem sleep adds ~100 ms per command
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
#if DEBUG_SERIAL
  Serial.printf("[wifi] joining \"%s\" ...\n", WIFI_SSID);
#endif
}

void loop() {
  esp_task_wdt_reset();

  if (WiFi.status() != WL_CONNECTED) {
#if DEBUG_SERIAL
    static unsigned long last = 0;
    if (millis() - last > 5000) {
      last = millis();
      Serial.printf("[wifi] status=%d (not connected yet)\n", (int)WiFi.status());
    }
#endif
    delay(50);
    return;  // auto-reconnects
  }

#if DEBUG_SERIAL
  static bool ipReported = false;
  if (!ipReported) {
    ipReported = true;
    Serial.printf("[wifi] CONNECTED ip=%s gw=%s rssi=%d ch=%d\n", WiFi.localIP().toString().c_str(),
                  WiFi.gatewayIP().toString().c_str(), WiFi.RSSI(), WiFi.channel());
  }
  // Unconditional heartbeat: the link state matters most exactly when there is no phone,
  // because that is when the operator is trying to work out what went wrong.
  static unsigned long lastHidLog = 0;
  if (millis() - lastHidLog > 5000) {
    lastHidLog = millis();
    Serial.printf("[hid] %s\n", hidState().c_str());
  }
#endif

  if (!server.connected()) {
    mouseButtons = 0;
    keyboardRelease();
    if (!server.connect(SERVER_HOST, SERVER_PORT, 1000)) {
#if DEBUG_SERIAL
      static unsigned long lastFail = 0;
      if (millis() - lastFail > 3000) {
        lastFail = millis();
        Serial.printf("[tcp] connect %s:%d FAILED (ip=%s)\n", SERVER_HOST, SERVER_PORT,
                      WiFi.localIP().toString().c_str());
      }
#endif
      delay(200);
      return;
    }
    server.setNoDelay(true);
    server.printf("hello %s %lu\n", resetReason(), millis());
#if DEBUG_SERIAL
    Serial.printf("[tcp] connected to %s:%d as %s\n", SERVER_HOST, SERVER_PORT,
                  WiFi.localIP().toString().c_str());
#endif
  }

  if (server.available()) {
    String line = server.readStringUntil('\n');
    line.trim();
    if (!line.length()) return;
    unsigned long started = millis();
    String reply = run(line);
    server.print(reply + "\n");
#if DEBUG_SERIAL
    Serial.printf("%s -> %s (%lu ms)\n", line.c_str(), reply.c_str(), millis() - started);
#endif
  }
}
