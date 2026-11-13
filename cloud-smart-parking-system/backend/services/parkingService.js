/**
 * Parking Service
 * Core business logic for slot queries, availability calculations, and administrative operations.
 */
const db = require('../config/dynamodb');
const { STATUS, SOURCES, isValidStatus, isValidSource } = require('../models/parkingModel');
require('dotenv').config();

const TABLE_PARKING_SLOTS = process.env.DYNAMODB_TABLE_PARKING_SLOTS || 'ParkingSlots';

async function getAllSlots() {
  const result = await db.scan({ TableName: TABLE_PARKING_SLOTS });
  const slots = result.Items || [];
  // Sort slots alphabetically by slotId
  slots.sort((a, b) => (a.slotId || '').localeCompare(b.slotId || ''));
  return slots;
}

async function getSlotById(slotId) {
  if (!slotId) return null;
  const result = await db.getItem({
    TableName: TABLE_PARKING_SLOTS,
    Key: { slotId: slotId.trim().toUpperCase() }
  });
  return result.Item || null;
}

async function getAvailabilitySummary() {
  const slots = await getAllSlots();
  const total = slots.length;

  let free = 0;
  let occupied = 0;
  let reserved = 0;
  let unknown = 0;

  const sourceStats = {
    JSON: 0,
    IOT: 0,
    CCTV: 0,
    ADMIN: 0
  };

  let latestTimestamp = null;

  slots.forEach(slot => {
    switch (slot.status) {
      case STATUS.FREE:
        free++;
        break;
      case STATUS.OCCUPIED:
        occupied++;
        break;
      case STATUS.RESERVED:
        reserved++;
        break;
      default:
        unknown++;
        break;
    }

    if (slot.source && sourceStats[slot.source] !== undefined) {
      sourceStats[slot.source]++;
    }

    if (slot.lastUpdated) {
      if (!latestTimestamp || new Date(slot.lastUpdated) > new Date(latestTimestamp)) {
        latestTimestamp = slot.lastUpdated;
      }
    }
  });

  const availabilityPercentage = total > 0 ? Math.round((free / total) * 100 * 10) / 10 : 0;

  return {
    totalCapacity: total,
    availableSlots: free,
    occupiedSlots: occupied,
    reservedSlots: reserved,
    unknownSlots: unknown,
    availabilityPercentage,
    lastUpdated: latestTimestamp || new Date().toISOString(),
    detectionSourceStats: sourceStats,
    slots
  };
}

async function addSlot({ slotId, parkingArea, status = STATUS.FREE, source = SOURCES.ADMIN }) {
  const cleanId = String(slotId).trim().toUpperCase();
  const existing = await getSlotById(cleanId);
  if (existing) {
    throw new Error(`Slot ${cleanId} already exists`);
  }

  const newSlot = {
    slotId: cleanId,
    parkingArea: (parkingArea || 'Zone A').trim(),
    status: isValidStatus(status) ? status : STATUS.FREE,
    source: isValidSource(source) ? source : SOURCES.ADMIN,
    confidence: 1.0,
    lastUpdated: new Date().toISOString(),
    detectionTimestamp: new Date().toISOString()
  };

  await db.putItem({
    TableName: TABLE_PARKING_SLOTS,
    Item: newSlot,
    ConditionExpression: 'attribute_not_exists(slotId)'
  });

  return newSlot;
}

async function removeSlot(slotId) {
  const cleanId = String(slotId).trim().toUpperCase();
  const existing = await getSlotById(cleanId);
  if (!existing) {
    throw new Error(`Slot ${cleanId} does not exist`);
  }

  await db.deleteItem({
    TableName: TABLE_PARKING_SLOTS,
    Key: { slotId: cleanId }
  });

  return { slotId: cleanId, deleted: true };
}

async function updateSlotManualStatus(slotId, status, notes = '') {
  const cleanId = String(slotId).trim().toUpperCase();
  if (!isValidStatus(status)) {
    throw new Error(`Invalid status: ${status}. Must be FREE, OCCUPIED, RESERVED, or UNKNOWN.`);
  }

  const existing = await getSlotById(cleanId);
  if (!existing) {
    throw new Error(`Slot ${cleanId} not found`);
  }

  const now = new Date().toISOString();
  await db.updateItem({
    TableName: TABLE_PARKING_SLOTS,
    Key: { slotId: cleanId },
    UpdateExpression: 'SET #s = :status, #src = :source, #lu = :lastUpdated, #adminNote = :note',
    ExpressionAttributeNames: {
      '#s': 'status',
      '#src': 'source',
      '#lu': 'lastUpdated',
      '#adminNote': 'adminNote'
    },
    ExpressionAttributeValues: {
      ':status': status,
      ':source': SOURCES.ADMIN,
      ':lastUpdated': now,
      ':note': notes || 'Manual admin override'
    }
  });

  return await getSlotById(cleanId);
}

module.exports = {
  getAllSlots,
  getSlotById,
  getAvailabilitySummary,
  addSlot,
  removeSlot,
  updateSlotManualStatus
};
