/**
 * Detection Service
 * Processes incoming vehicle detections from JSON Simulator, IoT ESP32, and CCTV OpenCV.
 * Maintains historical detection audit logs in DynamoDB.
 */
const crypto = require('crypto');
const db = require('../config/dynamodb');
const { STATUS, SOURCES, isValidStatus, isValidSource } = require('../models/parkingModel');
require('dotenv').config();

const TABLE_PARKING_SLOTS = process.env.DYNAMODB_TABLE_PARKING_SLOTS || 'ParkingSlots';
const TABLE_DETECTION_HISTORY = process.env.DYNAMODB_TABLE_DETECTION_HISTORY || 'DetectionHistory';

function generateId(prefix = 'EVT') {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

/**
 * Process a single slot detection update
 */
async function processSlotDetection({ slotId, status, source = SOURCES.JSON, confidence = 1.0, parkingArea, detectionTimestamp }) {
  if (!slotId) throw new Error('Slot ID is required');

  const cleanSlotId = slotId.trim().toUpperCase();
  const cleanStatus = isValidStatus(status) ? status : STATUS.UNKNOWN;
  const cleanSource = isValidSource(source) ? source : SOURCES.JSON;
  const cleanConfidence = typeof confidence === 'number' ? Math.max(0, Math.min(1, confidence)) : 1.0;
  const now = new Date().toISOString();
  const timestamp = detectionTimestamp || now;

  // 1. Fetch current slot record
  const slotRes = await db.getItem({
    TableName: TABLE_PARKING_SLOTS,
    Key: { slotId: cleanSlotId }
  });

  let currentSlot = slotRes.Item;

  // If slot doesn't exist yet, automatically register it
  if (!currentSlot) {
    currentSlot = {
      slotId: cleanSlotId,
      parkingArea: parkingArea || 'Main Parking Area',
      status: cleanStatus,
      source: cleanSource,
      confidence: cleanConfidence,
      lastUpdated: now,
      detectionTimestamp: timestamp
    };

    await db.putItem({
      TableName: TABLE_PARKING_SLOTS,
      Item: currentSlot
    });

    const eventId = generateId('EVT');
    await db.putItem({
      TableName: TABLE_DETECTION_HISTORY,
      Item: {
        eventId,
        slotId: cleanSlotId,
        previousStatus: 'NEW',
        newStatus: cleanStatus,
        source: cleanSource,
        confidence: cleanConfidence,
        timestamp: now
      }
    });

    return { slotId: cleanSlotId, previousStatus: 'NEW', currentStatus: cleanStatus, updated: true };
  }

  const previousStatus = currentSlot.status;
  let targetStatus = cleanStatus;

  // 2. Intelligent Conflict Resolution:
  // - If slot is currently RESERVED:
  //   - Detection of OCCUPIED means the booked vehicle has physically parked -> update to OCCUPIED.
  //   - Detection of FREE means slot is currently empty waiting for user -> DO NOT overwrite RESERVED to FREE!
  if (previousStatus === STATUS.RESERVED && cleanSource !== SOURCES.ADMIN) {
    if (cleanStatus === STATUS.FREE) {
      // Keep as RESERVED, but refresh sensor timestamp and confidence
      await db.updateItem({
        TableName: TABLE_PARKING_SLOTS,
        Key: { slotId: cleanSlotId },
        UpdateExpression: 'SET #lu = :now, #dt = :dt, #conf = :conf',
        ExpressionAttributeNames: {
          '#lu': 'lastUpdated',
          '#dt': 'detectionTimestamp',
          '#conf': 'confidence'
        },
        ExpressionAttributeValues: {
          ':now': now,
          ':dt': timestamp,
          ':conf': cleanConfidence
        }
      });

      return {
        slotId: cleanSlotId,
        previousStatus,
        currentStatus: STATUS.RESERVED,
        statusRetainedReason: 'Slot is currently RESERVED by user. Physical FREE detection preserved reservation.',
        updated: false
      };
    } else if (cleanStatus === STATUS.OCCUPIED) {
      targetStatus = STATUS.OCCUPIED;
    }
  }

  // 3. Update slot if status changed or source updated
  const statusChanged = previousStatus !== targetStatus;

  await db.updateItem({
    TableName: TABLE_PARKING_SLOTS,
    Key: { slotId: cleanSlotId },
    UpdateExpression: 'SET #s = :status, #src = :source, #conf = :conf, #lu = :now, #dt = :dt',
    ExpressionAttributeNames: {
      '#s': 'status',
      '#src': 'source',
      '#conf': 'confidence',
      '#lu': 'lastUpdated',
      '#dt': 'detectionTimestamp'
    },
    ExpressionAttributeValues: {
      ':status': targetStatus,
      ':source': cleanSource,
      ':conf': cleanConfidence,
      ':now': now,
      ':dt': timestamp
    }
  });

  // 4. Record event in history when status changes
  if (statusChanged) {
    const eventId = generateId('EVT');
    await db.putItem({
      TableName: TABLE_DETECTION_HISTORY,
      Item: {
        eventId,
        slotId: cleanSlotId,
        previousStatus,
        newStatus: targetStatus,
        source: cleanSource,
        confidence: cleanConfidence,
        timestamp: now
      }
    });
  }

  return {
    slotId: cleanSlotId,
    previousStatus,
    currentStatus: targetStatus,
    source: cleanSource,
    confidence: cleanConfidence,
    updated: true,
    statusChanged
  };
}

/**
 * Process batch detection (e.g. from JSON simulation or CCTV whole-lot frame)
 */
async function processBatchDetection({ parkingArea, source = SOURCES.JSON, slots = [] }) {
  if (!Array.isArray(slots) || slots.length === 0) {
    throw new Error('Slots array cannot be empty');
  }

  const results = [];
  for (const item of slots) {
    try {
      const res = await processSlotDetection({
        slotId: item.slotId,
        status: item.status,
        source: item.source || source,
        confidence: item.confidence,
        parkingArea: item.parkingArea || parkingArea,
        detectionTimestamp: item.detectionTimestamp || new Date().toISOString()
      });
      results.push(res);
    } catch (err) {
      results.push({ slotId: item.slotId, error: err.message, updated: false });
    }
  }

  return {
    source,
    parkingArea: parkingArea || 'Main Parking Area',
    processedCount: results.length,
    results
  };
}

/**
 * Get detection history audit log
 */
async function getDetectionHistory(limit = 50) {
  const result = await db.scan({ TableName: TABLE_DETECTION_HISTORY });
  const items = result.Items || [];

  // Sort newest first
  items.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));

  return items.slice(0, Number(limit) || 50);
}

module.exports = {
  processSlotDetection,
  processBatchDetection,
  getDetectionHistory
};
