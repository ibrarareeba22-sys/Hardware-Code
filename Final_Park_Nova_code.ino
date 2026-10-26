#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <ESP8266HTTPClient.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <Servo.h>
#include "secrets.h"   
// Firebase connection 
WiFiClientSecure fbClient;
HTTPClient fbHttp;
const bool FB_KEEP_ALIVE = true;
const uint16_t HTTP_FAST_TIMEOUT_MS = 4000;
#define TRIG1 D5
#define ECHO1 D6
#define TRIG2 D7
#define ECHO2 D0
#define TRIG3 D1
#define ECHO3 D2
#define LCD_SDA D3
#define LCD_SCL D4
LiquidCrystal_I2C lcd(0x27, 16, 2);
#define SERVO_PIN D8
Servo gateServo;
// Gate 
const int GATE_CLOSED_ANGLE = 150;
const int GATE_OPEN_ANGLE = 0;
const unsigned long GATE_OPEN_TIME_DEFAULT = 10000;   // 10 sec
unsigned long currentGateOpenMs = GATE_OPEN_TIME_DEFAULT;
bool gateIsOpen = false;
unsigned long gateOpenedAt = 0;
// Reservation cycle 
enum ReservationCycleState {
  CYCLE_IDLE,
  CYCLE_GATE_OPEN,
  CYCLE_POST_CLOSE_SENSOR
};
ReservationCycleState cycleState = CYCLE_IDLE;
unsigned long postCloseStartedAt = 0;
const unsigned long POST_GATE_SETTLE_MS = 2000;
// Parking settings 
const float ACTIVE_THRESHOLD_CM = 10.0;   
const char* FIREBASE_SLOT_1 = "slot1";
const char* FIREBASE_SLOT_2 = "slot2";
const char* FIREBASE_SLOT_3 = "slot3";

bool slot1EverPhysicallyOccupied = false;
bool slot2EverPhysicallyOccupied = false;
bool slot3EverPhysicallyOccupied = false;

unsigned long slot1HoldStartedAt = 0;
unsigned long slot2HoldStartedAt = 0;
unsigned long slot3HoldStartedAt = 0;

const unsigned long HOLD_TIMEOUT_MS = 5UL * 60UL * 1000UL;   // 5 min

const char* SLOT_LABELS[3] = {"A", "B", "C"};

String slotAStatus = "Free";
String slotBStatus = "Free";
String slotCStatus = "Free";

long slotADistance = -1;
long slotBDistance = -1;
long slotCDistance = -1;

// LCD rotation 
unsigned long lastLcdCycleMs = 0;
const unsigned long LCD_CYCLE_INTERVAL_MS = 3000;
int lcdCycleIndex = 0;
// Live sensor change detection 
bool lastSensorActive[3] = { false, false, false };
bool sensorBaselineReady = false;
const int SENSOR_CONFIRM_READS = 2;
int sensorChangeCounter[3] = { 0, 0, 0 };
bool pendingSlotWrite[3] = { false, false, false };
// Loop timing 
const unsigned long SENSOR_GAP_MS = 50;
const unsigned long LOOP_DELAY_MS = 20;
// Firebase auth 
String idToken = "";
unsigned long tokenObtainedAt = 0;
const unsigned long TOKEN_LIFETIME_MS = 55UL * 60UL * 1000UL;
// Background sync 
unsigned long lastSendMs = 0;
const unsigned long SEND_INTERVAL_MS = 2000;
int bgSyncSlotIndex = 0;   // 0 = A, 1 = B, 2 = C
// Gate polling 
unsigned long lastGateCheckMs = 0;
const unsigned long GATE_CHECK_INTERVAL_MS = 150;
String lastProcessedTimestamp = "";
unsigned long lastGateErrorPrintMs = 0;

void scanI2C() {
  byte count = 0;
  byte foundAddr = 0;
  for (byte addr = 1; addr < 127; addr++) {
    Wire.beginTransmission(addr);
    byte error = Wire.endTransmission();
    if (error == 0) {
      if (count == 0) foundAddr = addr;
      count++;
    }
  }
  if (count == 0) {
    Serial.println("[I2C] WARNING: No I2C device found! Check LCD wiring/power.");
  } else {
    Serial.print("[I2C] LCD found at 0x");
    Serial.println(foundAddr, HEX);
  }
}
// Ultrasonic sensor 
long readSensor(int trigPin, int echoPin) {
  digitalWrite(trigPin, LOW);
  delayMicroseconds(2);
  digitalWrite(trigPin, HIGH);
  delayMicroseconds(10);
  digitalWrite(trigPin, LOW);

  long duration = pulseIn(echoPin, HIGH, 30000);
  if (duration == 0) {
    return -1;
  }
  long distance = duration * 0.0343 / 2;
  return distance;
}
// WiFi 
bool connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 20000) {
    delay(400);
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf("[WIFI] FAILED (status=%d)\n", WiFi.status());
    return false;
  }
  return true;
}

void ensureWiFi() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WIFI] Dropped -> reconnecting...");
    fbClient.stop();
    if (connectWiFi()) {
      Serial.println("[WIFI] Reconnected.");
    }
  }
}
// Firebase auth 
bool firebaseSignIn() {
  fbClient.stop();

  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient https;
  https.useHTTP10(true);
  String url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=";
  url += FIREBASE_API_KEY;

  if (!https.begin(client, url)) {
    Serial.println("[ERROR][AUTH] HTTPS begin failed");
    return false;
  }

  https.addHeader("Content-Type", "application/json");

  StaticJsonDocument<256> reqDoc;
  reqDoc["email"] = FIREBASE_USER_EMAIL;
  reqDoc["password"] = FIREBASE_USER_PASSWORD;
  reqDoc["returnSecureToken"] = true;

  String reqBody;
  serializeJson(reqDoc, reqBody);

  int httpCode = https.POST(reqBody);
  if (httpCode <= 0) {
    Serial.printf("[ERROR][AUTH] Request failed: %d\n", httpCode);
    https.end();
    return false;
  }

  String payload = https.getString();
  https.end();

  if (httpCode == 200) {
    StaticJsonDocument<1024> resDoc;
    DeserializationError error = deserializeJson(resDoc, payload);
    if (error) {
      Serial.println("[ERROR][AUTH] JSON parse failed");
      return false;
    }
    idToken = resDoc["idToken"].as<String>();
    tokenObtainedAt = millis();
    return true;
  }

  Serial.printf("[ERROR][AUTH] FAILED HTTP=%d\n", httpCode);
  return false;
}

void ensureAuth() {
  if (idToken == "" || millis() - tokenObtainedAt > TOKEN_LIFETIME_MS) {
    if (!firebaseSignIn()) {
      Serial.println("[ERROR][AUTH] Re-authentication failed, will retry.");
    }
  }
}

int fbRequest(const char* method, const String &path, const String &body,
              String &response, uint16_t timeoutMs) {
  response = "";
  if (idToken == "") {
    return -100;
  }

  String url = String(FIREBASE_DB_URL) + path + "?auth=" + idToken;
  int code = -1;

  for (int attempt = 0; attempt < 2; attempt++) {
    fbHttp.setReuse(FB_KEEP_ALIVE);
    fbHttp.setTimeout(timeoutMs);

    if (!fbHttp.begin(fbClient, url)) {
      fbClient.stop();
      code = -1;
      continue;
    }

    if (body.length() > 0) {
      fbHttp.addHeader("Content-Type", "application/json");
    }

    if (strcmp(method, "PATCH") == 0) {
      code = fbHttp.PATCH(body);
    } else {
      code = fbHttp.GET();
    }

    if (code > 0) {
      response = fbHttp.getString();
      fbHttp.end();
      if (!FB_KEEP_ALIVE) {
        fbClient.stop();
      }
      return code;
    }

    fbHttp.end();
    fbClient.stop();
  }

  return code;
}

String firebaseGetSlotStatus(const char* slotName) {
  if (idToken == "") {
    return "";
  }

  String path = String("/parking/") + slotName + "/status.json";
  String payload;
  int httpCode = fbRequest("GET", path, "", payload, HTTP_FAST_TIMEOUT_MS);

  if (httpCode != 200) {
    Serial.printf("[ERROR][DB] %s status GET failed HTTP=%d\n", slotName, httpCode);
    return "";
  }

  payload.trim();

  if (payload.startsWith("\"") && payload.endsWith("\"") && payload.length() >= 2) {
    payload = payload.substring(1, payload.length() - 1);
  }
  payload.trim();

  if (payload == "" || payload == "null") {
    payload = "Free";
  }

  return payload;
}

bool firebaseWriteSlot(const char* slotName, const char* sensorValue, const String &status) {
  if (idToken == "") {
    return false;
  }

  StaticJsonDocument<256> doc;
  doc["sensors"] = sensorValue;
  doc["status"] = status;

  String body;
  serializeJson(doc, body);

  String path = String("/parking/") + slotName + ".json";
  String response;
  int httpCode = fbRequest("PATCH", path, body, response, HTTP_FAST_TIMEOUT_MS);

  if (httpCode != 200) {
    Serial.print("[ERROR][DB] ");
    Serial.print(slotName);
    Serial.print(" update FAILED | HTTP=");
    Serial.println(httpCode);
    return false;
  }

  return true;
}
bool firebaseUpdateSlotSensor(const char* slotName, const char* sensorValue, bool sensorActive,
                               String &outFinalStatus, bool &everPhysicallyOccupied,
                               unsigned long &holdStartedAt) {
  if (idToken == "") {
    outFinalStatus = sensorActive ? "Occupied" : "Free";
    return false;
  }

  String finalStatus;

  if (sensorActive) {
    finalStatus = "Occupied";
    everPhysicallyOccupied = true;
    holdStartedAt = 0;

  } else if (everPhysicallyOccupied) {
    finalStatus = "Free";
    everPhysicallyOccupied = false;
    holdStartedAt = 0;

  } else {
    String currentStatus = firebaseGetSlotStatus(slotName);
    currentStatus.trim();

    if (currentStatus == "") {
      outFinalStatus = "";
      return false;
    }

    bool isReservedMark = currentStatus.equalsIgnoreCase("Reserved") ||
                          currentStatus.equalsIgnoreCase("Booked");
    bool isOccupiedMark = currentStatus.equalsIgnoreCase("Occupied");

    if (isReservedMark || isOccupiedMark) {
      if (holdStartedAt == 0) {
        holdStartedAt = millis();
      }

      if (millis() - holdStartedAt >= HOLD_TIMEOUT_MS) {
        finalStatus = "Free";
        holdStartedAt = 0;
        Serial.print("[HOLD] ");
        Serial.print(slotName);
        Serial.println(" timeout -> Free");
      } else if (isOccupiedMark) {
        finalStatus = "Reserved";
      } else {
        finalStatus = currentStatus;
      }

    } else {
      finalStatus = "Free";
      holdStartedAt = 0;
    }
  }

  outFinalStatus = finalStatus;
  return firebaseWriteSlot(slotName, sensorValue, finalStatus);
}
// LCD 
void lcdMessage(String line2) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("PARK NOVA");
  lcd.setCursor(0, 1);
  lcd.print(line2);
}

void lcdShowSlotData(String line1, String line2) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(line1);
  lcd.setCursor(0, 1);
  lcd.print(line2);
}

void lcdShowSlot(int idx) {
  long distances[3]  = { slotADistance, slotBDistance, slotCDistance };
  String statuses[3] = { slotAStatus, slotBStatus, slotCStatus };

  String line1 = "Slot ";
  line1 += SLOT_LABELS[idx];
  line1 += ": ";
  if (distances[idx] >= 0) {
    line1 += String(distances[idx]);
    line1 += "cm";
  } else {
    line1 += "--";
  }

  String line2 = "Status: ";
  line2 += statuses[idx];

  lcdShowSlotData(line1, line2);
}

void updateLCDSlotCycle() {
  lcdShowSlot(lcdCycleIndex);
}
// Startup print
void printStartupSlotStatus() {
  Serial.println("[STARTUP] Current slot status:");

  String s1 = firebaseGetSlotStatus(FIREBASE_SLOT_1);
  String s2 = firebaseGetSlotStatus(FIREBASE_SLOT_2);
  String s3 = firebaseGetSlotStatus(FIREBASE_SLOT_3);

  if (s1 == "") s1 = "Unknown";
  if (s2 == "") s2 = "Unknown";
  if (s3 == "") s3 = "Unknown";

  slotAStatus = s1;
  slotBStatus = s2;
  slotCStatus = s3;

  Serial.print("  Slot A: ");
  Serial.println(slotAStatus);
  Serial.print("  Slot B: ");
  Serial.println(slotBStatus);
  Serial.print("  Slot C: ");
  Serial.println(slotCStatus);
}
// Gate 
bool updateGateFeedback(const char* gateState) {
  if (idToken == "") {
    return false;
  }

  StaticJsonDocument<256> doc;
  doc["gate"] = gateState;
  doc["status"] = gateState;

  String body;
  serializeJson(doc, body);

  String response;
  int httpCode = fbRequest("PATCH", "/hardware/entryGate.json", body, response, HTTP_FAST_TIMEOUT_MS);

  return (httpCode == 200);
}

void openGateNow() {
  gateServo.write(GATE_OPEN_ANGLE);
  gateIsOpen = true;
  gateOpenedAt = millis();

  lcdMessage("Gate Open");
  bool feedbackOk = updateGateFeedback("open");

  Serial.print("[GATE] OPEN");
  if (!gateServo.attached()) Serial.print(" | WARNING: servo NOT attached");
  if (!feedbackOk) Serial.print(" | WARNING: Firebase feedback failed");
  Serial.println();
}

void closeGateNow() {
  gateServo.write(GATE_CLOSED_ANGLE);
  gateIsOpen = false;

  lcdMessage("Gate Closed");
  bool feedbackOk = updateGateFeedback("closed");

  Serial.print("[GATE] CLOSED");
  if (!gateServo.attached()) Serial.print(" | WARNING: servo NOT attached");
  if (!feedbackOk) Serial.print(" | WARNING: Firebase feedback failed");
  Serial.println();
}

void handleGateTimer() {
  if (gateIsOpen && millis() - gateOpenedAt >= currentGateOpenMs) {
    closeGateNow();

    cycleState = CYCLE_POST_CLOSE_SENSOR;
    postCloseStartedAt = millis();
  }
}
// Serial print helper 
void printSlotShort(const char* label, long dist, const String &status) {
  Serial.print(label);
  Serial.print(": ");
  if (dist >= 0) {
    Serial.print(dist);
    Serial.print("cm");
  } else {
    Serial.print("--");
  }
  Serial.print(" ");
  Serial.print(status);
}
//Sensor + Firebase update 
void performSensorReadAndUpdate(long s1, long s2, long s3) {
  bool sensor1Active = (s1 >= 0 && s1 < ACTIVE_THRESHOLD_CM);
  bool sensor2Active = (s2 >= 0 && s2 < ACTIVE_THRESHOLD_CM);
  bool sensor3Active = (s3 >= 0 && s3 < ACTIVE_THRESHOLD_CM);

  const char* state1 = sensor1Active ? "active" : "inactive";
  const char* state2 = sensor2Active ? "active" : "inactive";
  const char* state3 = sensor3Active ? "active" : "inactive";

  String finalStatus1;
  String finalStatus2;
  String finalStatus3;

  if (idToken != "") {
    firebaseUpdateSlotSensor(FIREBASE_SLOT_1, state1, sensor1Active, finalStatus1, slot1EverPhysicallyOccupied, slot1HoldStartedAt);
    firebaseUpdateSlotSensor(FIREBASE_SLOT_2, state2, sensor2Active, finalStatus2, slot2EverPhysicallyOccupied, slot2HoldStartedAt);
    firebaseUpdateSlotSensor(FIREBASE_SLOT_3, state3, sensor3Active, finalStatus3, slot3EverPhysicallyOccupied, slot3HoldStartedAt);

    if (finalStatus1 == "") finalStatus1 = slotAStatus;
    if (finalStatus2 == "") finalStatus2 = slotBStatus;
    if (finalStatus3 == "") finalStatus3 = slotCStatus;
  } else {
    finalStatus1 = sensor1Active ? "Occupied" : "Free";
    finalStatus2 = sensor2Active ? "Occupied" : "Free";
    finalStatus3 = sensor3Active ? "Occupied" : "Free";
  }

  Serial.print("[CYCLE] After gate -> ");
  printSlotShort("A", s1, finalStatus1);
  Serial.print(" | ");
  printSlotShort("B", s2, finalStatus2);
  Serial.print(" | ");
  printSlotShort("C", s3, finalStatus3);
  Serial.println();

  slotAStatus = finalStatus1;
  slotBStatus = finalStatus2;
  slotCStatus = finalStatus3;
}
// Background sync
void performSingleSlotSync(int slotIndex, long s1, long s2, long s3) {
  const char* slotName;
  long distance;
  bool *everOccupied;
  unsigned long *holdStarted;
  String *statusVar;
  const char* label;

  if (slotIndex == 0) {
    slotName = FIREBASE_SLOT_1;
    distance = s1;
    everOccupied = &slot1EverPhysicallyOccupied;
    holdStarted = &slot1HoldStartedAt;
    statusVar = &slotAStatus;
    label = "Slot A";
  } else if (slotIndex == 1) {
    slotName = FIREBASE_SLOT_2;
    distance = s2;
    everOccupied = &slot2EverPhysicallyOccupied;
    holdStarted = &slot2HoldStartedAt;
    statusVar = &slotBStatus;
    label = "Slot B";
  } else {
    slotName = FIREBASE_SLOT_3;
    distance = s3;
    everOccupied = &slot3EverPhysicallyOccupied;
    holdStarted = &slot3HoldStartedAt;
    statusVar = &slotCStatus;
    label = "Slot C";
  }

  bool sensorActive = (distance >= 0 && distance < ACTIVE_THRESHOLD_CM);
  const char* sensorState = sensorActive ? "active" : "inactive";

  String previousStatus = *statusVar;
  String finalStatus;

  if (idToken != "") {
    firebaseUpdateSlotSensor(slotName, sensorState, sensorActive, finalStatus, *everOccupied, *holdStarted);
    if (finalStatus == "") {
      finalStatus = previousStatus;
    }
  } else {
    finalStatus = sensorActive ? "Occupied" : "Free";
  }

  if (finalStatus != previousStatus) {
    Serial.print("[SLOT] ");
    Serial.print(label);
    Serial.print(": ");
    Serial.print(previousStatus);
    Serial.print(" -> ");
    Serial.println(finalStatus);
  }

  *statusVar = finalStatus;
}

bool flushOnePendingSlotWrite() {
  const char* names[3] = { FIREBASE_SLOT_1, FIREBASE_SLOT_2, FIREBASE_SLOT_3 };
  String* statusVars[3] = { &slotAStatus, &slotBStatus, &slotCStatus };

  for (int i = 0; i < 3; i++) {
    if (pendingSlotWrite[i]) {
      pendingSlotWrite[i] = false;
      if (idToken != "") {
        firebaseWriteSlot(names[i], lastSensorActive[i] ? "active" : "inactive", *statusVars[i]);
      }
      return true;
    }
  }
  return false;
}
//  Live change detection 
void syncSensorBaseline(long s1, long s2, long s3) {
  long d[3] = { s1, s2, s3 };
  for (int i = 0; i < 3; i++) {
    lastSensorActive[i] = (d[i] >= 0 && d[i] < ACTIVE_THRESHOLD_CM);
    sensorChangeCounter[i] = 0;
  }
  sensorBaselineReady = true;
}

void handleSensorChangeDetection(long s1, long s2, long s3) {
  long d[3] = { s1, s2, s3 };

  bool* everOcc[3]            = { &slot1EverPhysicallyOccupied, &slot2EverPhysicallyOccupied, &slot3EverPhysicallyOccupied };
  unsigned long* holdStart[3] = { &slot1HoldStartedAt, &slot2HoldStartedAt, &slot3HoldStartedAt };
  String* statusVars[3]       = { &slotAStatus, &slotBStatus, &slotCStatus };

  if (!sensorBaselineReady) {
    syncSensorBaseline(s1, s2, s3);
    for (int i = 0; i < 3; i++) {
      if (lastSensorActive[i]) {
        *everOcc[i] = true;
      }
    }
    return;
  }

  for (int i = 0; i < 3; i++) {
    bool active = (d[i] >= 0 && d[i] < ACTIVE_THRESHOLD_CM);

    if (active == lastSensorActive[i]) {
      sensorChangeCounter[i] = 0;
      continue;
    }

    sensorChangeCounter[i]++;
    if (sensorChangeCounter[i] < SENSOR_CONFIRM_READS) {
      continue;
    }

    sensorChangeCounter[i] = 0;
    lastSensorActive[i] = active;

    String previousStatus = *statusVars[i];

    if (active) {
      *everOcc[i] = true;
      *holdStart[i] = 0;
      *statusVars[i] = "Occupied";
    } else if (*everOcc[i]) {
      *everOcc[i] = false;
      *holdStart[i] = 0;
      *statusVars[i] = "Free";
    }

    pendingSlotWrite[i] = true;

    Serial.print("[SENSOR] Slot ");
    Serial.print(SLOT_LABELS[i]);
    Serial.print(active ? ": CAR DETECTED (" : ": CAR LEFT (");
    if (d[i] >= 0) {
      Serial.print(d[i]);
      Serial.print("cm");
    } else {
      Serial.print("no echo");
    }
    Serial.print(") | ");
    if (previousStatus != *statusVars[i]) {
      Serial.print(previousStatus);
      Serial.print(" -> ");
    }
    Serial.println(*statusVars[i]);

    lcdShowSlot(i);
    lcdCycleIndex = (i + 1) % 3;
    lastLcdCycleMs = millis();
  }
}

void handlePostCloseSensorUpdate() {
  if (cycleState != CYCLE_POST_CLOSE_SENSOR) {
    return;
  }

  if (millis() - postCloseStartedAt < POST_GATE_SETTLE_MS) {
    return;
  }

  long s1 = readSensor(TRIG1, ECHO1);
  delay(SENSOR_GAP_MS);
  long s2 = readSensor(TRIG2, ECHO2);
  delay(SENSOR_GAP_MS);
  long s3 = readSensor(TRIG3, ECHO3);

  slotADistance = s1;
  slotBDistance = s2;
  slotCDistance = s3;

  performSensorReadAndUpdate(s1, s2, s3);

  syncSensorBaseline(s1, s2, s3);
  for (int i = 0; i < 3; i++) {
    pendingSlotWrite[i] = false;
  }

  updateLCDSlotCycle();

  cycleState = CYCLE_IDLE;
}
// Gate command (camera / app) 
void checkGateCommand() {
  if (idToken == "") {
    return;
  }

  String payload;
  int httpCode = fbRequest("GET", "/hardware/entryGate.json", "", payload, HTTP_FAST_TIMEOUT_MS);

  if (httpCode != 200) {
    if (millis() - lastGateErrorPrintMs > 5000) {
      lastGateErrorPrintMs = millis();
      Serial.printf("[ERROR][GATE] Status check failed HTTP=%d\n", httpCode);
    }
    return;
  }

  StaticJsonDocument<1024> doc;
  DeserializationError error = deserializeJson(doc, payload);
  if (error) {
    Serial.println("[ERROR][GATE] JSON parse failed");
    return;
  }

  String status = doc["status"] | "";
  String timestamp = doc["timestamp"] | "";
  long openSeconds = doc["openSeconds"] | (long)(GATE_OPEN_TIME_DEFAULT / 1000);

  bool isNewCommand = (status.equalsIgnoreCase("open") && timestamp != "" && timestamp != lastProcessedTimestamp);

  if (isNewCommand && cycleState == CYCLE_IDLE) {
    lastProcessedTimestamp = timestamp;

    if (openSeconds < 1) openSeconds = 1;
    if (openSeconds > 3600) openSeconds = 3600;
    currentGateOpenMs = (unsigned long)openSeconds * 1000UL;

    cycleState = CYCLE_GATE_OPEN;
    openGateNow();
  }
}

void serviceGate() {
  if (millis() - lastGateCheckMs > GATE_CHECK_INTERVAL_MS) {
    lastGateCheckMs = millis();
    checkGateCommand();
  }
  handleGateTimer();
}
// setup
void setup() {
  Serial.begin(115200);
  delay(1000);

  pinMode(TRIG1, OUTPUT);
  pinMode(ECHO1, INPUT);
  pinMode(TRIG2, OUTPUT);
  pinMode(ECHO2, INPUT);
  pinMode(TRIG3, OUTPUT);
  pinMode(ECHO3, INPUT);

  digitalWrite(TRIG1, LOW);
  digitalWrite(TRIG2, LOW);
  digitalWrite(TRIG3, LOW);

  fbClient.setInsecure();
  fbHttp.setReuse(FB_KEEP_ALIVE);
  // LCD
  Wire.begin(LCD_SDA, LCD_SCL);
  scanI2C();

  lcd.init();
  lcd.backlight();
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("PARK NOVA");
  lcd.setCursor(0, 1);
  lcd.print("Starting...");
  delay(1500);
  // Servo 
  gateServo.attach(SERVO_PIN, 500, 2400);
  gateServo.write(GATE_CLOSED_ANGLE);
  gateIsOpen = false;
  cycleState = CYCLE_IDLE;
  delay(500);
  // WiFi
  lcdMessage("WiFi Connecting");
  bool wifiOk = connectWiFi();
  if (!wifiOk) {
    lcdMessage("WiFi ERROR");
  }
  // Firebase
  bool firebaseOk = false;
  if (wifiOk) {
    lcdMessage("Firebase Login");
    firebaseOk = firebaseSignIn();
  }

  if (firebaseOk) {
    lcdMessage("System Ready");
  } else {
    lcdMessage("Firebase Error");
  }

  // Status summary
  Serial.println("----------------------------------");
  Serial.println("PARK NOVA - SYSTEM STATUS");
  Serial.print("WiFi      : ");
  Serial.println(wifiOk ? ("OK (" + WiFi.localIP().toString() + ")") : "FAILED - check SSID/password");
  Serial.print("Firebase  : ");
  Serial.println(firebaseOk ? "OK" : "FAILED - check credentials/internet");
  Serial.print("Servo     : ");
  Serial.println(gateServo.attached() ? "OK" : "FAILED - check wiring/power");
  Serial.println("================================");

  if (firebaseOk) {
    printStartupSlotStatus();
  }

  if (wifiOk && firebaseOk) {
    Serial.println("System READY. Waiting for reservations...");
  } else {
    Serial.println("System started with ERRORS above - fix before relying on it.");
  }
}
//  loop 
void loop() {
  ensureWiFi();
  ensureAuth();
// 1) Gate
  serviceGate();
  handlePostCloseSensorUpdate();
  // 2) Sensors 
  long s1 = readSensor(TRIG1, ECHO1);
  delay(SENSOR_GAP_MS);
  long s2 = readSensor(TRIG2, ECHO2);
  delay(SENSOR_GAP_MS);
  long s3 = readSensor(TRIG3, ECHO3);
  slotADistance = s1;
  slotBDistance = s2;
  slotCDistance = s3;
  serviceGate();
  handleSensorChangeDetection(s1, s2, s3);

  if (!flushOnePendingSlotWrite()) {
    if (cycleState == CYCLE_IDLE && millis() - lastSendMs > SEND_INTERVAL_MS) {
      lastSendMs = millis();
      performSingleSlotSync(bgSyncSlotIndex, s1, s2, s3);
      bgSyncSlotIndex = (bgSyncSlotIndex + 1) % 3;
    }
  }
  serviceGate();
  // LCD rotation
  if (millis() - lastLcdCycleMs > LCD_CYCLE_INTERVAL_MS) {
    lastLcdCycleMs = millis();
    updateLCDSlotCycle();
    lcdCycleIndex = (lcdCycleIndex + 1) % 3;
  }
  delay(LOOP_DELAY_MS);
}