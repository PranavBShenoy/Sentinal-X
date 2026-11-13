# IoT Edge Sensor Integration Module (ESP32)
## Cloud-Based Smart Parking Management System

### 1. Hardware Architecture Overview

The IoT sensor subsystem provides real-time bay occupancy telemetry via edge microcontrollers installed above or in front of individual parking bays.

```
       +---------------------------------------------+
       |             ESP-WROOM-32 MCU                |
       |                                             |
       |   GPIO 5 (TRIG) ------> TRIG (HC-SR04)      |
       |   GPIO 18 (ECHO) <----  ECHO (HC-SR04)      |
       |   GPIO 2  (LED)  -----> Status LED          |
       |   3V3 / 5V       -----> VCC                 |
       |   GND            -----> GND                 |
       +---------------------------------------------+
                              |
                     WiFi 802.11 b/g/n
                              |
                              v
                  [ AWS IoT Core Broker ]
                    (MQTT over TLS 8883)
                              |
                              v
                [ AWS DynamoDB / REST API ]
```

---

### 2. Hardware Bill of Materials (BOM)

| Component | Quantity | Specification / Role |
| :--- | :--- | :--- |
| ESP-WROOM-32 Development Board | 1 per bay | 32-bit dual-core MCU with built-in Wi-Fi & BLE |
| HC-SR04 Ultrasonic Distance Sensor | 1 per bay | Range: $2\text{ cm} - 400\text{ cm}$, Accuracy: $3\text{ mm}$ |
| Jumper Wires | 4-6 | Dupont male-to-female connectors |
| Breadboard / Sensor Mount | 1 | Mounts sensor at height of $40-60\text{ cm}$ |
| USB Power Supply | 1 | 5V / 1A Micro-USB adapter |

---

### 3. Pin Wiring Schematic

| Sensor Pin | ESP32 Pin | Function |
| :--- | :--- | :--- |
| **VCC** | `VIN` or `5V` | Sensor power supply |
| **TRIG** | `GPIO 5` | Ultrasound trigger pulse ($10\,\mu\text{s}$ HIGH) |
| **ECHO** | `GPIO 18` | Echo pulse return duration measurement |
| **GND** | `GND` | Ground reference |

---

### 4. Telemetry Payload Contract

The ESP32 publishes JSON messages to topic `parking/sensor/status`:
```json
{
  "slotId": "A03",
  "parkingArea": "Zone A - Ground Level",
  "status": "OCCUPIED",
  "source": "IOT",
  "distanceCm": 32.4,
  "confidence": 0.98,
  "timestamp": "1794590000"
}
```

---

### 5. Flashing Instructions (Arduino IDE)

1. **Install ESP32 Board Support:**
   - In Arduino IDE > Preferences > Additional Board Manager URLs, add:
     `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
   - In Board Manager, install **esp32 by Espressif Systems**.
2. **Install Required Libraries:**
   - `PubSubClient` by Nick O'Leary
   - `WiFiClientSecure` (built into ESP32 board package)
3. **Configure Sketch:**
   - Open `esp32-code/esp32_parking_sensor.ino`.
   - Update `WIFI_SSID` and `WIFI_PASSWORD`.
   - Set `AWS_IOT_ENDPOINT` to your AWS IoT Core endpoint.
   - Paste device certificates and private keys generated in [AWS IoT Core Setup](../../aws/iot-core-setup.md).
4. **Compile & Upload:** Select **ESP32 Dev Module**, choose correct COM port, and click **Upload**.

---

### 6. Hardware-Free Testing with Virtual IoT Sensor Cluster

To test and demonstrate the IoT data flow without physical microcontrollers:
```bash
# Run one cycle
node detection/sensor/virtual_sensor.js --once

# Run continuous simulation loop
node detection/sensor/virtual_sensor.js
```
The virtual sensor outputs real distance readings, transitions bays between `FREE` and `OCCUPIED`, and tags the detection source as `IOT`.
