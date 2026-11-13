/**
 * Booking Service
 * Handles parking reservations, concurrency safety, and booking lifecycle.
 */
const crypto = require('crypto');
const db = require('../config/dynamodb');
const { STATUS, SOURCES } = require('../models/parkingModel');
require('dotenv').config();

const TABLE_PARKING_SLOTS = process.env.DYNAMODB_TABLE_PARKING_SLOTS || 'ParkingSlots';
const TABLE_BOOKINGS = process.env.DYNAMODB_TABLE_BOOKINGS || 'Bookings';
const TABLE_DETECTION_HISTORY = process.env.DYNAMODB_TABLE_DETECTION_HISTORY || 'DetectionHistory';

function generateId(prefix = 'BKG') {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

async function createBooking({ slotId, userId, vehicleNumber, durationMinutes = 60 }) {
  if (!slotId) throw new Error('Slot ID is required');
  if (!userId) throw new Error('User ID is required');

  const cleanSlotId = slotId.trim().toUpperCase();

  // 1. Fetch current slot status
  const slot = await db.getItem({
    TableName: TABLE_PARKING_SLOTS,
    Key: { slotId: cleanSlotId }
  });

  if (!slot.Item) {
    throw new Error(`Slot ${cleanSlotId} does not exist`);
  }

  const currentSlot = slot.Item;

  // 2. Validate booking rules
  if (currentSlot.status === STATUS.OCCUPIED) {
    throw new Error(`Slot ${cleanSlotId} is currently OCCUPIED and cannot be booked`);
  }
  if (currentSlot.status === STATUS.RESERVED) {
    throw new Error(`Slot ${cleanSlotId} is already RESERVED`);
  }
  if (currentSlot.status === STATUS.UNKNOWN) {
    throw new Error(`Slot ${cleanSlotId} status is UNKNOWN (sensor unverified); booking disallowed`);
  }
  if (currentSlot.status !== STATUS.FREE) {
    throw new Error(`Slot ${cleanSlotId} is not available for booking (status: ${currentSlot.status})`);
  }

  const bookingId = generateId('BKG');
  const now = new Date().toISOString();
  const eventId = generateId('EVT');

  const newBooking = {
    bookingId,
    userId: String(userId).trim(),
    slotId: cleanSlotId,
    vehicleNumber: (vehicleNumber || 'NOT-SPECIFIED').toUpperCase().trim(),
    bookingTime: now,
    status: 'ACTIVE',
    durationMinutes: Number(durationMinutes) || 60,
    parkingArea: currentSlot.parkingArea
  };

  const historyEvent = {
    eventId,
    slotId: cleanSlotId,
    previousStatus: STATUS.FREE,
    newStatus: STATUS.RESERVED,
    source: SOURCES.ADMIN, // user booking action
    action: 'BOOKING_CREATED',
    bookingId,
    timestamp: now
  };

  // 3. Atomically update slot to RESERVED and insert booking
  // Conditional write ensures no race conditions: #s must be FREE
  try {
    await db.transactWrite({
      TransactItems: [
        {
          Update: {
            TableName: TABLE_PARKING_SLOTS,
            Key: { slotId: cleanSlotId },
            UpdateExpression: 'SET #s = :reserved, #lu = :now, #actBkg = :bkgId',
            ConditionExpression: '#s = :free',
            ExpressionAttributeNames: {
              '#s': 'status',
              '#lu': 'lastUpdated',
              '#actBkg': 'activeBookingId'
            },
            ExpressionAttributeValues: {
              ':reserved': STATUS.RESERVED,
              ':free': STATUS.FREE,
              ':now': now,
              ':bkgId': bookingId
            }
          }
        },
        {
          Put: {
            TableName: TABLE_BOOKINGS,
            Item: newBooking,
            ConditionExpression: 'attribute_not_exists(bookingId)'
          }
        },
        {
          Put: {
            TableName: TABLE_DETECTION_HISTORY,
            Item: historyEvent
          }
        }
      ]
    });
  } catch (err) {
    if (err.name === 'TransactionCanceledException' || err.name === 'ConditionalCheckFailedException') {
      throw new Error(`Slot ${cleanSlotId} was booked or modified by another request. Please choose another slot.`);
    }
    throw err;
  }

  return newBooking;
}

async function getAllBookings(userId = null) {
  const result = await db.scan({ TableName: TABLE_BOOKINGS });
  let items = result.Items || [];

  if (userId) {
    items = items.filter(b => b.userId === userId);
  }

  // Sort newest first
  items.sort((a, b) => new Date(b.bookingTime || 0) - new Date(a.bookingTime || 0));
  return items;
}

async function getBookingById(bookingId) {
  if (!bookingId) return null;
  const result = await db.getItem({
    TableName: TABLE_BOOKINGS,
    Key: { bookingId: bookingId.trim() }
  });
  return result.Item || null;
}

async function cancelBooking(bookingId) {
  const booking = await getBookingById(bookingId);
  if (!booking) {
    throw new Error(`Booking ${bookingId} not found`);
  }

  if (booking.status === 'CANCELLED') {
    throw new Error(`Booking ${bookingId} is already cancelled`);
  }

  const now = new Date().toISOString();
  const slotId = booking.slotId;
  const eventId = generateId('EVT');

  // Cancel booking record
  await db.updateItem({
    TableName: TABLE_BOOKINGS,
    Key: { bookingId: booking.bookingId },
    UpdateExpression: 'SET #st = :cancelled, #ct = :cancelledAt',
    ExpressionAttributeNames: {
      '#st': 'status',
      '#ct': 'cancelledAt'
    },
    ExpressionAttributeValues: {
      ':cancelled': 'CANCELLED',
      ':cancelledAt': now
    }
  });

  // Check current slot status: if it is still RESERVED, release it to FREE
  const slotRes = await db.getItem({
    TableName: TABLE_PARKING_SLOTS,
    Key: { slotId }
  });

  if (slotRes.Item && slotRes.Item.status === STATUS.RESERVED) {
    await db.updateItem({
      TableName: TABLE_PARKING_SLOTS,
      Key: { slotId },
      UpdateExpression: 'SET #s = :free, #lu = :now REMOVE activeBookingId',
      ExpressionAttributeNames: {
        '#s': 'status',
        '#lu': 'lastUpdated'
      },
      ExpressionAttributeValues: {
        ':free': STATUS.FREE,
        ':now': now
      }
    });

    // Record in history
    await db.putItem({
      TableName: TABLE_DETECTION_HISTORY,
      Item: {
        eventId,
        slotId,
        previousStatus: STATUS.RESERVED,
        newStatus: STATUS.FREE,
        source: SOURCES.ADMIN,
        action: 'BOOKING_CANCELLED',
        bookingId,
        timestamp: now
      }
    });
  }

  return {
    bookingId,
    slotId,
    status: 'CANCELLED',
    cancelledAt: now
  };
}

module.exports = {
  createBooking,
  getAllBookings,
  getBookingById,
  cancelBooking
};
