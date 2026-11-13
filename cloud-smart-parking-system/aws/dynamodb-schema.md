# Amazon DynamoDB Schema & Access Patterns
## Cloud-Based Smart Parking Management System

### 1. Overview
The database layer uses Amazon DynamoDB with On-Demand (Pay-Per-Request) billing. The schema is organized into three tables designed to support high write volume from telemetry streams and fast key-based lookups for the web dashboard.

---

### 2. Logical Tables Specification

#### Table 1: `ParkingSlots`
Stores the current physical occupancy and reservation state of each parking space.

- **Table Name:** `ParkingSlots`
- **Partition Key (HASH):** `slotId` (String, e.g., `"A01"`, `"B04"`)
- **Sort Key (RANGE):** None

| Attribute | DynamoDB Type | Description |
| :--- | :--- | :--- |
| `slotId` | `S` (String) | Unique bay identifier (e.g., `"A01"`) |
| `parkingArea` | `S` (String) | Zone or facility designation (e.g., `"Zone A - Ground Level"`) |
| `status` | `S` (String) | Current bay state: `FREE`, `OCCUPIED`, `RESERVED`, `UNKNOWN` |
| `source` | `S` (String) | Ingestion source: `JSON`, `IOT`, `CCTV`, `ADMIN` |
| `confidence` | `N` (Number) | Measurement certainty between `0.0` and `1.0` |
| `lastUpdated` | `S` (String) | ISO 8601 UTC timestamp of last state change |
| `detectionTimestamp`| `S` (String) | ISO 8601 UTC timestamp of edge sensor reading |
| `activeBookingId` | `S` (String, Optional) | Associated `bookingId` when status is `RESERVED` |
| `adminNote` | `S` (String, Optional) | Override note logged when modified by an administrator |

##### Example Item (JSON):
```json
{
  "slotId": "A01",
  "parkingArea": "Zone A - Ground Level",
  "status": "FREE",
  "source": "CCTV",
  "confidence": 0.96,
  "lastUpdated": "2026-11-13T22:30:00.000Z",
  "detectionTimestamp": "2026-11-13T22:29:58.000Z"
}
```

---

#### Table 2: `Bookings`
Tracks driver reservation requests, allocated slots, and status history.

- **Table Name:** `Bookings`
- **Partition Key (HASH):** `bookingId` (String, e.g., `"BKG-1794589979045-BE925E"`)
- **Sort Key (RANGE):** None

| Attribute | DynamoDB Type | Description |
| :--- | :--- | :--- |
| `bookingId` | `S` (String) | Unique alphanumeric booking identifier |
| `userId` | `S` (String) | Unique driver ID (e.g., `"driver-4029"`) |
| `slotId` | `S` (String) | Allocated parking slot |
| `vehicleNumber` | `S` (String) | Driver vehicle registration plate |
| `bookingTime` | `S` (String) | ISO 8601 UTC timestamp when booked |
| `status` | `S` (String) | Booking lifecycle status: `ACTIVE`, `COMPLETED`, `CANCELLED` |
| `durationMinutes` | `N` (Number) | Requested duration in minutes |
| `cancelledAt` | `S` (String, Optional) | Timestamp when booking was cancelled |

##### Global Secondary Indexes (GSIs):
1. **`userId-index`**
   - Partition Key: `userId` (S)
   - Projection: `ALL`
   - Purpose: Retrieve all active and historical bookings for a given driver.
2. **`slotId-index`**
   - Partition Key: `slotId` (S)
   - Projection: `ALL`
   - Purpose: Query past bookings associated with a specific bay.

---

#### Table 3: `DetectionHistory`
Audit log recording every status change detected by IoT sensors, CCTV, simulation, or admin actions.

- **Table Name:** `DetectionHistory`
- **Partition Key (HASH):** `eventId` (String, e.g., `"EVT-1794590008077-BE925E"`)
- **Sort Key (RANGE):** None

| Attribute | DynamoDB Type | Description |
| :--- | :--- | :--- |
| `eventId` | `S` (String) | Unique event identifier |
| `slotId` | `S` (String) | Parking bay identifier |
| `previousStatus`| `S` (String) | Prior status (`FREE`, `OCCUPIED`, `RESERVED`, `NEW`) |
| `newStatus` | `S` (String) | Updated status |
| `source` | `S` (String) | Originating source (`JSON`, `IOT`, `CCTV`, `ADMIN`) |
| `confidence` | `N` (Number) | Detection confidence score |
| `timestamp` | `S` (String) | ISO 8601 UTC timestamp |
| `action` | `S` (String, Optional) | Event context (e.g., `BOOKING_CREATED`, `BOOKING_CANCELLED`) |

##### Global Secondary Indexes (GSIs):
1. **`slotId-timestamp-index`**
   - Partition Key: `slotId` (S)
   - Sort Key: `timestamp` (S)
   - Projection: `ALL`
   - Purpose: Query time-series activity for a specific parking bay.

---

### 3. Key Access Patterns & DynamoDB Commands

#### Pattern 1: Get Current Facility Availability
```javascript
// Scan all slots for real-time aggregation
const result = await docClient.send(new ScanCommand({
  TableName: 'ParkingSlots'
}));
```

#### Pattern 2: Atomic Slot Reservation (Double-Booking Prevention)
Uses `TransactWriteCommand` to ensure the slot is updated only if it is currently `FREE`, while simultaneously writing the `Bookings` record.
```javascript
await docClient.send(new TransactWriteCommand({
  TransactItems: [
    {
      Update: {
        TableName: 'ParkingSlots',
        Key: { slotId: 'A01' },
        UpdateExpression: 'SET #s = :reserved, #lu = :now, #actBkg = :bkgId',
        ConditionExpression: '#s = :free',
        ExpressionAttributeNames: {
          '#s': 'status',
          '#lu': 'lastUpdated',
          '#actBkg': 'activeBookingId'
        },
        ExpressionAttributeValues: {
          ':reserved': 'RESERVED',
          ':free': 'FREE',
          ':now': new Date().toISOString(),
          ':bkgId': bookingId
        }
      }
    },
    {
      Put: {
        TableName: 'Bookings',
        Item: newBooking,
        ConditionExpression: 'attribute_not_exists(bookingId)'
      }
    }
  ]
}));
```

#### Pattern 3: Query Driver Bookings
```javascript
const result = await docClient.send(new QueryCommand({
  TableName: 'Bookings',
  IndexName: 'userId-index',
  KeyConditionExpression: 'userId = :uid',
  ExpressionAttributeValues: { ':uid': 'driver-4029' }
}));
```
