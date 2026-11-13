/**
 * Cloud-Based Smart Parking Management System
 * ESP32 Edge Sensor Firmware for HC-SR04 Ultrasonic Parking Detection
 * Communicates with AWS IoT Core via MQTT over TLS (Port 8883)
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>

// ==========================================
// 1. Hardware Pin Definitions (ESP32)
// ==========================================
const int TRIG_PIN = 5;       // Ultrasonic Trigger Pin
const int ECHO_PIN = 18;      // Ultrasonic Echo Pin
const int LED_PIN  = 2;       // Onboard Diagnostic LED (GPIO 2)

// ==========================================
// 2. Parking Bay & Threshold Configuration
// ==========================================
const char* SLOT_ID           = "A03";               // Assigned bay identifier
const char* PARKING_AREA      = "Zone A - Ground Level";
const float OCCUPANCY_DIST_CM = 50.0;                // Obstacle threshold (< 50 cm = OCCUPIED)
const unsigned long SENSOR_INTERVAL_MS = 3000;       // Telemetry publish interval

// ==========================================
// 3. Network & AWS IoT Core Configuration
// ==========================================
const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

// AWS IoT Core Endpoint (find in AWS IoT Console > Settings)
const char* AWS_IOT_ENDPOINT = "a2xyz123example-ats.iot.us-east-1.amazonaws.com";
const int   AWS_IOT_PORT     = 8883;
const char* MQTT_PUB_TOPIC   = "parking/sensor/status";
const char* CLIENT_ID        = "ESP32-SmartParking-A03";

// ==========================================
// 4. AWS IoT Core X.509 Device Certificates
// ==========================================
// Root CA Certificate (Amazon Root CA 1)
static const char AWS_CERT_CA[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
... [PASTE AmazonRootCA1.pem HERE] ...
-----END CERTIFICATE-----
)EOF";

// Device Certificate
static const char AWS_CERT_CRT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIU...
... [PASTE <id>-certificate.pem.crt HERE] ...
-----END CERTIFICATE-----
)EOF";

// Device Private Key
static const char AWS_CERT_PRIVATE[] PROGMEM = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
... [PASTE <id>-private.pem.key HERE] ...
-----END RSA PRIVATE KEY-----
)EOF";

// ==========================================
// 5. Global Clients & Variables
// ==========================================
WiFiClientSecure netClient;
PubSubClient mqttClient(netClient);

String lastStatus = "UNKNOWN";
unsigned long lastPublishTime = 0;

// Read distance in centimeters using HC-SR04 ultrasonic echo timing
float measureDistanceCm() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  long duration = pulseIn(ECHO_PIN, HIGH, 30000); // 30ms timeout
  if (duration == 0) {
    return 999.0; // No obstacle or out of range
  }
  // Speed of sound = 343 m/s = 0.0343 cm/microsecond. Divide by 2 for round-trip.
  return (duration * 0.0343) / 2.0;
}

void connectWiFi() {
  Serial.print("[WiFi] Connecting to: ");
  Serial.println(WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n[WiFi] Connected successfully. IP: " + WiFi.localIP().toString());
}

void connectAWS() {
  netClient.setCACert(AWS_CERT_CA);
  netClient.setCertificate(AWS_CERT_CRT);
  netClient.setPrivateKey(AWS_CERT_PRIVATE);

  mqttClient.setServer(AWS_IOT_ENDPOINT, AWS_IOT_PORT);

  while (!mqttClient.connected()) {
    Serial.print("[MQTT] Connecting to AWS IoT Core...");
    if (mqttClient.connect(CLIENT_ID)) {
      Serial.println(" Connected!");
      digitalWrite(LED_PIN, HIGH);
    } else {
      Serial.print(" Failed! rc=");
      Serial.print(mqttClient.state());
      Serial.println(" Retrying in 4 seconds...");
      delay(4000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  Serial.println("\n--- ESP32 Smart Parking Sensor Node Initializing ---");
  connectWiFi();
  connectAWS();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }
  if (!mqttClient.connected()) {
    connectAWS();
  }
  mqttClient.loop();

  unsigned long now = millis();
  if (now - lastPublishTime >= SENSOR_INTERVAL_MS) {
    lastPublishTime = now;

    // Take 3 median measurements to filter electrical bounce
    float d1 = measureDistanceCm(); delay(20);
    float d2 = measureDistanceCm(); delay(20);
    float d3 = measureDistanceCm();
    float distance = (d1 + d2 + d3) / 3.0;

    String currentStatus = (distance < OCCUPANCY_DIST_CM) ? "OCCUPIED" : "FREE";
    float confidence = (distance < OCCUPANCY_DIST_CM) 
      ? min(1.0, 0.80 + (OCCUPANCY_DIST_CM - distance) / 100.0) 
      : 0.98;

    // Construct telemetry JSON payload
    String payload = "{";
    payload += "\"slotId\":\"" + String(SLOT_ID) + "\",";
    payload += "\"parkingArea\":\"" + String(PARKING_AREA) + "\",";
    payload += "\"status\":\"" + currentStatus + "\",";
    payload += "\"source\":\"IOT\",";
    payload += "\"distanceCm\":" + String(distance, 1) + ",";
    payload += "\"confidence\":" + String(confidence, 2) + ",";
    payload += "\"timestamp\":\"" + String(now) + "\"";
    payload += "}";

    // Publish to AWS IoT Core
    if (mqttClient.publish(MQTT_PUB_TOPIC, payload.c_str())) {
      Serial.println("[Telemetry Published] " + payload);
      // Blink LED to indicate transmit
      digitalWrite(LED_PIN, LOW); delay(50); digitalWrite(LED_PIN, HIGH);
    } else {
      Serial.println("[MQTT Error] Failed to publish sensor reading");
    }

    lastStatus = currentStatus;
  }
}
