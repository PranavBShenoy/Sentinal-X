# Project Report: Cloud-Based Smart Parking Management System
**Course:** Cloud Computing (Mini Project)  
**Architecture:** AWS EC2, Amazon DynamoDB, AWS IoT Core, Node.js, OpenCV, ESP32  
**Date:** November 2026  

---

## 1. ABSTRACT

With exponential urban population growth and private vehicle ownership, finding vacant parking bays has become a major driver of traffic congestion, fuel wastage, and carbon emissions. This project presents the design and implementation of a **Cloud-Based Smart Parking Management System** that automatically determines parking bay occupancy using a unified multi-modal edge detection pipeline comprising: (1) Ultrasonic IoT microcontrollers (ESP-WROOM-32), (2) CCTV Computer Vision (Python & OpenCV), and (3) Stochastic JSON simulation.

The architecture leverages Amazon Web Services (AWS) infrastructure, utilizing Amazon DynamoDB as a serverless NoSQL datastore, Amazon EC2 for hosting the Node.js/Express application, and AWS IoT Core for secure MQTT sensor ingestion. The web frontend provides drivers with a real-time, color-coded visual parking map, atomic slot booking protected against race conditions, and an administrative console featuring Chart.js analytics. Experimental validation confirms sub-second state synchronization, robust concurrency handling, and a modular architecture capable of toggling edge sources without modifying the cloud application.

---

## 2. PROBLEM STATEMENT & OBJECTIVES

### 2.1 Problem Statement
Traditional parking facilities suffer from:
- **Lack of Real-Time Information:** Drivers cruise parking lots blindly, causing up to 30% of downtown traffic congestion.
- **Hardware Lock-in:** Existing proprietary parking systems depend on closed hardware ecosystems, preventing facilities from utilizing existing surveillance camera feeds or low-cost IoT nodes simultaneously.
- **Race Conditions in Online Booking:** Naive web applications fail to handle simultaneous reservations, leading to double-booked parking bays.
- **Scalability Bottlenecks:** On-premises database servers fail during traffic spikes and incur high maintenance overhead.

### 2.2 Project Objectives
- Build an automated vehicle occupancy detection pipeline supporting IoT, Computer Vision, and Simulation feeds.
- Design a cloud-native backend on AWS EC2 and Amazon DynamoDB.
- Prevent duplicate reservations via atomic database transactions.
- Develop a modern, responsive web dashboard with live color-coded indicators (Green = FREE, Red = OCCUPIED, Yellow = RESERVED, Grey = UNKNOWN).
- Implement an administrator console with facility management, manual overrides, and Chart.js analytics.
- Enforce cloud security principles (IAM instance profiles, no hardcoded secrets, authenticated administrative endpoints).

---

## 3. SYSTEM ARCHITECTURE & AWS CLOUD INFRASTRUCTURE

The system follows a decoupled four-tier cloud architecture:

```mermaid
flowchart LR
    subgraph SENSORS ["Edge Sensing Layer"]
        ESP[ESP32 Ultrasonic]
        CCTV[OpenCV CCTV Node]
        SIM[JSON Simulator]
    end

    subgraph AWS ["Amazon Web Services"]
        IOT[AWS IoT Core]
        EC2[Amazon EC2 Instance<br/>Node.js / Express]
        DDB[(Amazon DynamoDB<br/>ParkingSlots, Bookings, History)]
        IAM[AWS IAM Instance Role]
    end

    subgraph CLIENTS ["Presentation Layer"]
        WEB[Driver Dashboard & Booking]
        ADMIN[Admin & Analytics Console]
    end

    ESP -->|MQTT TLS 8883| IOT
    IOT -->|Rule Routing| DDB
    CCTV -->|REST API POST| EC2
    SIM -->|REST API POST| EC2
    EC2 --- IAM
    IAM -->|Least-Privilege Policy| DDB
    EC2 <-->|State Queries| DDB
    WEB <-->|HTTP / REST| EC2
    ADMIN <-->|HTTP / REST + Auth| EC2
```

### 3.1 Cloud Services Utilized
1. **Amazon DynamoDB:** Serves as the primary datastore utilizing On-Demand billing, partition keys for $O(1)$ item lookup, and Global Secondary Indexes (GSIs) for relational access patterns.
2. **Amazon EC2:** Hosts the Node.js Express backend and serves static frontend assets via Nginx reverse proxy.
3. **AWS Identity & Access Management (IAM):** An EC2 instance profile (`SmartParkingEC2Role`) authorizes DynamoDB read/write access without storing credentials on disk.
4. **AWS IoT Core:** Manages MQTT connections from ESP32 microcontrollers with X.509 device certificates.

---

## 4. DATABASE DESIGN & CONCURRENCY MODEL

### 4.1 DynamoDB Table Schemas

#### Table 1: `ParkingSlots`
- **Partition Key:** `slotId` (String)
- **Attributes:** `parkingArea`, `status` (`FREE` | `OCCUPIED` | `RESERVED` | `UNKNOWN`), `source` (`JSON` | `IOT` | `CCTV` | `ADMIN`), `confidence` (Number), `lastUpdated` (String), `detectionTimestamp` (String).

#### Table 2: `Bookings`
- **Partition Key:** `bookingId` (String)
- **Attributes:** `userId`, `slotId`, `vehicleNumber`, `bookingTime`, `status` (`ACTIVE` | `CANCELLED`), `durationMinutes`.
- **GSIs:** `userId-index` (Partition Key: `userId`), `slotId-index` (Partition Key: `slotId`).

#### Table 3: `DetectionHistory`
- **Partition Key:** `eventId` (String)
- **Attributes:** `slotId`, `previousStatus`, `newStatus`, `source`, `confidence`, `timestamp`.
- **GSI:** `slotId-timestamp-index` (Partition Key: `slotId`, Sort Key: `timestamp`).

### 4.2 Concurrency & Atomic Slot Booking
To guarantee that two users clicking "Book Slot" at the same millisecond cannot book the same parking space, the backend executes a DynamoDB `TransactWriteCommand`:
```javascript
Update: {
  TableName: 'ParkingSlots',
  Key: { slotId: cleanSlotId },
  UpdateExpression: 'SET #s = :reserved, #lu = :now, #actBkg = :bkgId',
  ConditionExpression: '#s = :free',
  ExpressionAttributeNames: { '#s': 'status', '#lu': 'lastUpdated', '#actBkg': 'activeBookingId' },
  ExpressionAttributeValues: { ':reserved': 'RESERVED', ':free': 'FREE', ':now': now, ':bkgId': bookingId }
}
```
If the slot status has changed to anything other than `FREE`, the transaction aborts with a `ConditionalCheckFailedException`, safely denying the second request.

---

## 5. EDGE DETECTION SUBSYSTEMS

### 5.1 CCTV Computer Vision Pipeline (OpenCV)
The computer vision node processes camera frames using bounding polygon regions defined in `slot_config.json`:
1. **Grayscale & Smoothing:** Frame luminance is smoothed with a Gaussian kernel $(5 \times 5)$ to eliminate high-frequency sensor noise.
2. **Adaptive Thresholding:**
   $$\text{dst}(x,y) = \begin{cases} 255 & \text{if } \text{src}(x,y) > T(x,y) \\ 0 & \text{otherwise} \end{cases}$$
   where $T(x,y)$ is the weighted mean of a $19 \times 19$ neighborhood minus constant $C=3$.
3. **Pixel Density Ratio:**
   $$\rho = \frac{1}{W \times H} \sum_{i=0}^{W-1} \sum_{j=0}^{H-1} \mathbb{I}(\text{pixel}_{i,j} \neq 0)$$
4. **Classification:** If $\rho \ge 0.28$, bay is marked `OCCUPIED`; otherwise `FREE`.
5. **Confidence Score:** Derived from the distance of $\rho$ from the $0.28$ boundary ($70\% - 100\%$).

### 5.2 IoT Microcontroller Subsystem (ESP32)
The IoT node utilizes an ESP-WROOM-32 wired to an HC-SR04 ultrasonic sensor:
1. Trigger pulse: $10\,\mu\text{s}$ active HIGH on GPIO 5.
2. Return pulse timing on GPIO 18 converted to distance:
   $$\text{Distance (cm)} = \frac{\text{Echo Duration (}\mu\text{s)} \times 0.0343}{2}$$
3. Clearance logic: If $\text{Distance} < 50\text{ cm}$, bay is flagged `OCCUPIED`.
4. Communication: Publishes encrypted JSON packets over MQTT (Port 8883) to AWS IoT Core.

### 5.3 Multi-Source Conflict Resolution
The system maintains a strict separation between physical sensing and user reservations:
- If a slot is `RESERVED`, and a sensor reports `FREE`, the reservation is **preserved** because the vehicle has not yet arrived.
- If a slot is `RESERVED`, and a sensor reports `OCCUPIED`, the status updates to `OCCUPIED` (driver parked).

---

## 6. REST API SPECIFICATIONS

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service health, uptime & DB mode | Public |
| `GET` | `/api/parking/slots` | Retrieve all registered bays | Public |
| `GET` | `/api/parking/availability`| Facility summary & availability % | Public |
| `GET` | `/api/parking/slots/:id` | Get specific bay status | Public |
| `POST` | `/api/bookings` | Atomically reserve an available bay | User ID |
| `GET` | `/api/bookings` | Query active & historical bookings | User ID |
| `PUT` | `/api/bookings/:id/cancel`| Cancel booking and release bay | User ID |
| `GET` | `/api/admin/dashboard` | Admin analytics & telemetry summary| Admin Key |
| `POST` | `/api/admin/slots` | Register new parking bay | Admin Key |
| `DELETE`| `/api/admin/slots/:id` | Deregister parking bay | Admin Key |
| `PUT` | `/api/admin/slots/:id/status`| Manual status override (Source: ADMIN)| Admin Key |
| `POST` | `/api/detection/update` | Ingest detection reading (Batch/Single)| Ingestion Node |
| `GET` | `/api/detection/history`| Audit trail of bay state transitions | Public / Admin |

---

## 7. EXPERIMENTAL RESULTS & VALIDATION

### 7.1 Automated Test Suite Results
The test harness executed 15 unit and integration tests:
- `GET /api/health`: Returned HTTP 200 with uptime counter and database mode.
- `GET /api/parking/slots`: Successfully scanned 12 seeded bays across Zone A and Zone B.
- `POST /api/bookings`: Verified atomic reservation on free bay A01.
- Concurrency Check: Attempted duplicate reservation on reserved bay A01; correctly failed with HTTP 400.
- `PUT /api/bookings/:id/cancel`: Released bay back to `FREE`.
- Admin Security: Tested `/api/admin/dashboard` without key (HTTP 401 rejected), and with valid `x-admin-key` (HTTP 200 accepted).

### 7.2 CCTV & IoT Throughput
- **CCTV Node:** Evaluated over 120 synthetic video frames running at 78.4 FPS on CPU without hardware acceleration.
- **Latency:** Average REST update processing latency: $4\text{ ms} - 12\text{ ms}$.

---

## 8. CONCLUSION & FUTURE SCOPE

The **Cloud-Based Smart Parking Management System** successfully demonstrates a resilient, cloud-native IoT and Computer Vision solution meeting all requirements for an enterprise smart city parking platform. By decoupling edge detection from cloud ingestion, the system allows facilities to combine legacy CCTV cameras, modern ultrasonic IoT nodes, and simulation models under a single glass pane.

### Future Scope
1. **Automatic Number Plate Recognition (ANPR):** Integrating optical character recognition (OCR) with CCTV cameras to verify vehicle plates against reservation records.
2. **Dynamic Pricing Engine:** Adjusting hourly parking rates algorithmically based on real-time occupancy percentages.
3. **Mobile App Navigation:** Integrating OpenStreetMap / Google Maps turn-by-turn guidance directing drivers directly to their reserved bay coordinates.

---

## 9. REFERENCES
1. Amazon Web Services, *Amazon DynamoDB Developer Guide*, AWS Documentation, 2026.
2. OpenCV Team, *Image Processing in OpenCV - Adaptive Thresholding*, OpenCV 5.0 Documentation, 2026.
3. Espressif Systems, *ESP32 Technical Reference Manual*, Version 4.8, 2025.
4. O. Vermesan et al., *Internet of Things: Smart Cities and Intelligent Transportation Systems*, River Publishers, 2023.
