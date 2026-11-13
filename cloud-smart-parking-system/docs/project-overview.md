# Project Overview
## Cloud-Based Smart Parking Management System

### 1. Executive Summary

Urban vehicle congestion and the quest for available parking spots contribute significantly to carbon emissions, time wastage, and driver fatigue in modern smart cities. The **Cloud-Based Smart Parking Management System** solves this problem by providing a multi-modal, cloud-native IoT and Computer Vision infrastructure deployed on Amazon Web Services (AWS).

The system unifies:
1. **IoT Sensor Telemetry:** ESP32 microcontrollers measuring ultrasonic clearance distance.
2. **CCTV Computer Vision:** Python OpenCV processing CCTV surveillance feeds using adaptive thresholding and bounding-box pixel density analysis.
3. **JSON Simulation Engine:** Periodic automated vehicle turnover generator for rapid evaluation.
4. **Cloud Database:** Amazon DynamoDB tables (`ParkingSlots`, `Bookings`, `DetectionHistory`) with conditional write protection against double-booking.
5. **Modern Web Applications:** Responsive driver dashboard, reservation portal, and administrative control center with Chart.js analytics.

---

### 2. Key Objectives & Deliverables

- **Real-Time Visibility:** Provide immediate graphical color-coded status (Green = FREE, Red = OCCUPIED, Yellow = RESERVED, Grey = UNKNOWN).
- **Concurrency & Transaction Safety:** Prevent simultaneous slot reservations using DynamoDB conditional transactions (`#status = 'FREE'`).
- **Detection Agnosticism:** Unified data model allowing IoT, CCTV, JSON simulation, and admin overrides to feed into the same backend pipeline seamlessly.
- **Security & Cloud Best Practices:** IAM role-based authentication on EC2 without hardcoding AWS access keys in code or configuration.
- **Academic & Industry Quality:** Production-ready code, comprehensive API documentation, and automated test suite.

---

### 3. High-Level Technology Stack

| Domain | Technology / Framework |
| :--- | :--- |
| **Frontend** | HTML5, CSS3 (Custom Dark Navy Design Tokens), Vanilla JavaScript (ES6+), Chart.js |
| **Backend** | Node.js (v22 LTS), Express.js, AWS SDK for JavaScript v3 |
| **Database** | Amazon DynamoDB (On-Demand billing, GSIs, conditional transactions) |
| **Cloud Hosting** | Amazon EC2 (Ubuntu 22.04 LTS), AWS IAM, Nginx Reverse Proxy, PM2 |
| **Computer Vision** | Python 3, OpenCV (cv2), NumPy |
| **IoT Hardware** | ESP32 Microcontroller, HC-SR04 Ultrasonic Sensor, MQTT over TLS 1.2, AWS IoT Core |
| **Testing** | Node.js Test Runner, HTTP Integration Tests |

---

### 4. Application Modules & User Journeys

```
                    +-----------------------------+
                    |        Landing Page         |
                    |        (index.html)         |
                    +--------------+--------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
+------------------+                               +--------------------+
| Driver Dashboard |                               |   Admin Console    |
| (dashboard.html) |                               |    (admin.html)    |
+--------+---------+                               +---------+----------+
         |                                                   |
         | Select Slot & Book                                | Manage Bays & Overrides
         v                                                   v
+------------------+                               +--------------------+
| Reservation Flow |                               | Cloud Analytics &  |
|  (booking.html)  |                               | Detection History  |
+------------------+                               +--------------------+
```
