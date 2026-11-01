#include <WiFi.h>
#include <WebServer.h>
#include <esp_wifi.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

// ===== LCD =====
#define LCD_SDA 21
#define LCD_SCL 22
#define LCD_ADDRESS 0x27   // If blank, try 0x3F
LiquidCrystal_I2C lcd(LCD_ADDRESS, 16, 2);
uint32_t lastLcdUpdate = 0;

void lcdLine(uint8_t row, const char* text) {
  lcd.setCursor(0, row);
  lcd.print(text);
  int len = strlen(text);
  while (len++ < 16) lcd.print(" ");
}

// ===== CONFIG =====
const char* AP_SSID = "DeauthGuard";
const char* AP_PASS = "guard1234";   // at least 8 characters
#define AP_CHANNEL      6            // 1-13. Sniffer watches this channel
#define AP_MAX_CLIENTS  4
#define ALERT_THRESHOLD 10           // deauth + disassoc frames per window
#define WINDOW_MS       2000
#define LOG_SIZE        10
#define BUZZER_PIN      -1           // set a GPIO (e.g. 13) if you have a buzzer
#define LED_PIN         -1           // set a GPIO if you have an LED

// ===== dashboard login =====
const char* WEB_USER = "admin";
const char* WEB_PASS = "vluhbluh";   // change this

WebServer server(80);

// ===== sniffer state (written from the Wi-Fi callback) =====
volatile uint32_t deauthTotal = 0;
volatile uint32_t disassocTotal = 0;
volatile uint8_t  lastSrc[6];
volatile uint8_t  lastBssid[6];
volatile uint32_t lastEventMs = 0;
volatile bool     hasEvent = false;
volatile int8_t   lastRssi = 0;
volatile uint8_t  lastChannel = AP_CHANNEL;
volatile uint16_t lastReason = 0;
volatile uint8_t  lastSubtype = 0;

void IRAM_ATTR snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  // Ignore truncated frames before reading their header/reason code.
  if (pkt->rx_ctrl.sig_len < 24) return;
  const uint8_t* f = pkt->payload;

  uint8_t ftype   = (f[0] >> 2) & 0x03;
  uint8_t subtype = (f[0] >> 4) & 0x0F;
  if (ftype != 0) return;              // management frames only

  if (subtype == 12)      deauthTotal++;
  else if (subtype == 10) disassocTotal++;
  else return;

  memcpy((void*)lastSrc,   f + 10, 6); // addr2 = transmitter
  memcpy((void*)lastBssid, f + 16, 6); // addr3 = BSSID
  lastRssi = pkt->rx_ctrl.rssi;
  lastChannel = pkt->rx_ctrl.channel;
  lastSubtype = subtype;
  lastReason = (pkt->rx_ctrl.sig_len >= 26)
      ? (uint16_t)f[24] | ((uint16_t)f[25] << 8)
      : 0;
  lastEventMs = millis();
  hasEvent = true;
}

// ===== alert log (updated from loop, not the callback) =====
struct Alert {
  uint32_t timeMs;
  uint32_t count;
  char src[18];
  char bssid[18];
  int8_t rssi;
  uint8_t channel;
  uint8_t subtype;
  uint16_t reason;
};
Alert alertLog[LOG_SIZE];
int alertCount = 0;
bool alertActive = false;
uint32_t alertUntil = 0;

uint32_t prevTotal = 0;
uint32_t windowCount = 0;
uint32_t windowStart = 0;

void formatMac(const volatile uint8_t* m, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// ===== login check =====
// Returns true if the request has the right username and password.
// Otherwise it sends a 401, which makes the browser show a login prompt.
bool checkAuth() {
  if (!server.authenticate(WEB_USER, WEB_PASS)) {
    server.requestAuthentication(BASIC_AUTH, "Deauth Detector");
    return false;
  }
  return true;
}

// ===== web page =====
const char PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deauth Detector</title>
<style>
  body{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;padding:16px}
  h1{font-size:20px;margin:0 0 12px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
  .card{background:#1d1d1d;border-radius:8px;padding:12px}
  .label{font-size:12px;color:#888;text-transform:uppercase}
  .val{font-size:20px;font-weight:bold;margin-top:4px;word-break:break-all}
  .banner{padding:14px;border-radius:8px;text-align:center;font-size:22px;font-weight:bold;margin-bottom:14px}
  .ok{background:#1b4d2b;color:#9ef0b5}
  .alert{background:#7a1f1f;color:#ffb3b3;animation:blink 1s steps(2) infinite}
  @keyframes blink{50%{opacity:.6}}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:6px;border-bottom:1px solid #333;text-align:left}
  th{color:#888}
  button{background:#333;color:#eee;border:0;padding:10px 14px;border-radius:6px;font-size:14px}
</style>
</head>
<body>
<h1>Deauth Detector</h1>
<div id="banner" class="banner ok">Monitoring</div>
<div class="grid">
  <div class="card"><div class="label">Channel</div><div class="val" id="ch">-</div></div>
  <div class="card"><div class="label">Clients</div><div class="val" id="clients">-</div></div>
  <div class="card"><div class="label">Uptime</div><div class="val" id="up">-</div></div>
  <div class="card"><div class="label">Free heap</div><div class="val" id="heap">-</div></div>
  <div class="card"><div class="label">Detector AP</div><div class="val" id="ssid">-</div></div>
  <div class="card"><div class="label">Dashboard IP</div><div class="val" id="ip">-</div></div>
  <div class="card"><div class="label">Alert threshold</div><div class="val" id="threshold">-</div></div>
  <div class="card"><div class="label">Deauth total</div><div class="val" id="deauth">0</div></div>
  <div class="card"><div class="label">Disassoc total</div><div class="val" id="disassoc">0</div></div>
  <div class="card"><div class="label">Last window</div><div class="val" id="win">0</div></div>
  <div class="card"><div class="label">Alerts</div><div class="val" id="alerts">0</div></div>
</div>
<div class="card" style="margin-bottom:14px">
  <div class="label">Last attacker</div>
  <div>Source: <span id="src">-</span></div>
  <div>BSSID: <span id="bssid">-</span></div>
  <div>Last seen: <span id="last">-</span></div>
  <div>Frame type: <span id="frameType">-</span></div>
  <div>Signal strength: <span id="rssi">-</span> dBm</div>
  <div>Observed channel: <span id="eventChannel">-</span></div>
  <div>Reason code: <span id="reason">-</span></div>
  <div class="label" style="margin-top:8px">Note: transmitter MACs can be spoofed; this is not proof of a person's identity.</div>
</div>
<div class="card" style="margin-bottom:14px">
  <div class="label">Alert history</div>
  <table><thead><tr><th>Time</th><th>Frames</th><th>Frame</th><th>Transmitter MAC</th><th>BSSID</th><th>RSSI</th><th>Channel</th><th>Reason</th></tr></thead>
  <tbody id="log"><tr><td colspan="8">None</td></tr></tbody></table>
</div>
<button onclick="fetch('/reset').then(()=>poll())">Reset counters</button>
<script>
function fmtUp(s){const h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;return h+"h "+m+"m "+x+"s";}
function fmtHeap(b){return (b/1024).toFixed(1)+" KB";}
async function poll(){
  try{
    const d = await (await fetch('/api/status')).json();
    document.getElementById('ch').textContent = d.channel;
    document.getElementById('clients').textContent = d.clients;
    document.getElementById('up').textContent = fmtUp(d.uptime);
    document.getElementById('heap').textContent = fmtHeap(d.heap);
    document.getElementById('ssid').textContent = d.ssid;
    document.getElementById('ip').textContent = d.ip;
    document.getElementById('threshold').textContent = d.threshold + " / " + (d.windowMs/1000) + " sec";
    document.getElementById('deauth').textContent = d.deauth;
    document.getElementById('disassoc').textContent = d.disassoc;
    document.getElementById('win').textContent = d.window;
    document.getElementById('alerts').textContent = d.alertCount;
    document.getElementById('src').textContent = d.src;
    document.getElementById('bssid').textContent = d.bssid;
    document.getElementById('last').textContent = d.lastSeen;
    document.getElementById('frameType').textContent = d.frameType;
    document.getElementById('rssi').textContent = d.rssi;
    document.getElementById('eventChannel').textContent = d.eventChannel;
    document.getElementById('reason').textContent = d.reason;
    const b = document.getElementById('banner');
    if(d.alert){b.className="banner alert";b.textContent="DEAUTH ATTACK DETECTED";}
    else{b.className="banner ok";b.textContent="Monitoring";}
    const tb = document.getElementById('log');
    if(d.log.length===0){tb.innerHTML='<tr><td colspan="8">None</td></tr>';}
    else{tb.innerHTML=d.log.map(a=>`<tr><td>${a.time}</td><td>${a.count}</td><td>${a.frameType}</td><td>${a.src}</td><td>${a.bssid}</td><td>${a.rssi} dBm</td><td>${a.channel}</td><td>${a.reason}</td></tr>`).reverse().join('');}
  }catch(e){}
  setTimeout(poll,1000);
}
poll();
</script>
</body>
</html>
)rawliteral";

// ===== helpers =====
String jsonEscape(const char* s) {
  String out = "\"";
  for (const char* p = s; *p; p++) {
    if (*p == '"' || *p == '\\') out += '\\';
    out += *p;
  }
  return out + "\"";
}

void handleStatus() {
  char src[18] = "-", bssid[18] = "-", lastSeen[24] = "never";
  uint8_t subtype = lastSubtype;
  if (hasEvent) {
    formatMac(lastSrc, src);
    formatMac(lastBssid, bssid);
    snprintf(lastSeen, sizeof(lastSeen), "%lu s ago", (millis() - lastEventMs) / 1000);
  }

  String j = "{";
  j += "\"channel\":" + String(AP_CHANNEL) + ",";
  j += "\"clients\":" + String(WiFi.softAPgetStationNum()) + ",";
  j += "\"uptime\":" + String(millis() / 1000) + ",";
  j += "\"heap\":" + String(ESP.getFreeHeap()) + ",";
  j += "\"deauth\":" + String(deauthTotal) + ",";
  j += "\"disassoc\":" + String(disassocTotal) + ",";
  j += "\"window\":" + String(windowCount) + ",";
  j += "\"alertCount\":" + String(alertCount) + ",";
  j += "\"alert\":" + String(alertActive ? "true" : "false") + ",";
  j += "\"src\":" + jsonEscape(src) + ",";
  j += "\"bssid\":" + jsonEscape(bssid) + ",";
  j += "\"lastSeen\":" + jsonEscape(lastSeen) + ",";
  j += "\"frameType\":" + jsonEscape(subtype == 12 ? "Deauthentication" : (subtype == 10 ? "Disassociation" : "None")) + ",";
  j += "\"rssi\":" + String((int)lastRssi) + ",";
  j += "\"eventChannel\":" + String((int)lastChannel) + ",";
  j += "\"reason\":" + String((unsigned int)lastReason) + ",";
  j += "\"ssid\":" + jsonEscape(AP_SSID) + ",";
  String ipText = WiFi.softAPIP().toString();
  j += "\"ip\":" + jsonEscape(ipText.c_str()) + ",";
  j += "\"threshold\":" + String(ALERT_THRESHOLD) + ",";
  j += "\"windowMs\":" + String(WINDOW_MS) + ",";
  j += "\"log\":[";
  int n = min(alertCount, LOG_SIZE);
  for (int i = 0; i < n; i++) {
    int idx = (alertCount - n + i) % LOG_SIZE;
    char t[16];
    snprintf(t, sizeof(t), "%lu s", alertLog[idx].timeMs / 1000);
    j += "{\"time\":" + jsonEscape(t) +
         ",\"count\":" + String(alertLog[idx].count) +
         ",\"src\":" + jsonEscape(alertLog[idx].src) +
         ",\"bssid\":" + jsonEscape(alertLog[idx].bssid) +
         ",\"frameType\":" + jsonEscape(alertLog[idx].subtype == 12 ? "Deauth" : "Disassoc") +
         ",\"rssi\":" + String((int)alertLog[idx].rssi) +
         ",\"channel\":" + String((int)alertLog[idx].channel) +
         ",\"reason\":" + String((unsigned int)alertLog[idx].reason) + "}";
    if (i < n - 1) j += ",";
  }
  j += "]}";
  server.send(200, "application/json", j);
}

// ===== setup =====
void setup() {
  Serial.begin(115200);

  // I2C LCD uses the ESP32's default SDA/SCL pins.
  Wire.begin(LCD_SDA, LCD_SCL);
  lcd.init();
  lcd.backlight();
  lcdLine(0, "DEAUTH GUARD");
  lcdLine(1, "Starting...");
  if (BUZZER_PIN >= 0) pinMode(BUZZER_PIN, OUTPUT);
  if (LED_PIN >= 0)    pinMode(LED_PIN, OUTPUT);

  // 1. Start the access point on a fixed channel
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, 0, AP_MAX_CLIENTS);
  Serial.print("AP started: ");
  Serial.println(AP_SSID);
  Serial.print("Dashboard: http://");
  Serial.println(WiFi.softAPIP());
  Serial.printf("Monitoring channel %d\n", AP_CHANNEL);

  // 2. Start the sniffer (stays on the AP's channel)
  wifi_promiscuous_filter_t filt = {};
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  esp_wifi_set_promiscuous(true);

  // 3. Web routes (every route requires the login)
  server.on("/", []() {
    if (!checkAuth()) return;
    server.send_P(200, "text/html", PAGE);
  });
  server.on("/api/status", []() {
    if (!checkAuth()) return;
    handleStatus();
  });
  server.on("/reset", []() {
    if (!checkAuth()) return;
    noInterrupts();
    deauthTotal = 0;
    disassocTotal = 0;
    interrupts();
    alertCount = 0;
    server.send(200, "text/plain", "ok");
  });
  server.begin();

  windowStart = millis();
}

// ===== loop =====
void loop() {
  server.handleClient();

  // Evaluate the window every WINDOW_MS
  if (millis() - windowStart >= WINDOW_MS) {
    windowStart = millis();
    uint32_t total = deauthTotal + disassocTotal;
    windowCount = total - prevTotal;
    prevTotal = total;

    if (windowCount >= ALERT_THRESHOLD) {
      alertActive = true;
      alertUntil = millis() + 5000;

      Alert& a = alertLog[alertCount % LOG_SIZE];
      a.timeMs = millis();
      a.count = windowCount;
      formatMac(lastSrc, a.src);
      formatMac(lastBssid, a.bssid);
      a.rssi = lastRssi;
      a.channel = lastChannel;
      a.subtype = lastSubtype;
      a.reason = lastReason;
      alertCount++;

      Serial.printf("ALERT: %lu frames, src %s, bssid %s\n",
                    (unsigned long)windowCount, a.src, a.bssid);
    }
  }

  if (alertActive && millis() > alertUntil) alertActive = false;

  // Refresh the LCD twice per second without clearing the whole screen.
  if (millis() - lastLcdUpdate >= 500) {
    lastLcdUpdate = millis();

    if (alertActive) {
      char line2[17];
      snprintf(line2, sizeof(line2), "Frames: %lu",
               (unsigned long)windowCount);
      lcdLine(0, "!! DEAUTH ALERT");
      lcdLine(1, line2);
    } else {
      char line2[17];
      snprintf(line2, sizeof(line2), "D:%lu S:%lu",
               (unsigned long)deauthTotal,
               (unsigned long)disassocTotal);
      lcdLine(0, "Monitoring CH 6");
      lcdLine(1, line2);
    }
  }

  if (LED_PIN >= 0)    digitalWrite(LED_PIN, alertActive);
  if (BUZZER_PIN >= 0) digitalWrite(BUZZER_PIN, alertActive);
}