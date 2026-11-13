/**
 * Parking Data Model and Validation Rules
 */

const STATUS = {
  FREE: 'FREE',
  OCCUPIED: 'OCCUPIED',
  RESERVED: 'RESERVED',
  UNKNOWN: 'UNKNOWN'
};

const SOURCES = {
  JSON: 'JSON',
  IOT: 'IOT',
  CCTV: 'CCTV',
  ADMIN: 'ADMIN'
};

function isValidStatus(status) {
  return Object.values(STATUS).includes(status);
}

function isValidSource(source) {
  return Object.values(SOURCES).includes(source);
}

function formatSlotRecord({ slotId, parkingArea, status, source, confidence, detectionTimestamp }) {
  if (!slotId || typeof slotId !== 'string') {
    throw new Error('Valid slotId is required');
  }

  const validStatus = isValidStatus(status) ? status : STATUS.UNKNOWN;
  const validSource = isValidSource(source) ? source : SOURCES.JSON;

  return {
    slotId: slotId.trim().toUpperCase(),
    parkingArea: (parkingArea || 'Main Parking Area').trim(),
    status: validStatus,
    source: validSource,
    lastUpdated: new Date().toISOString(),
    confidence: typeof confidence === 'number' ? Math.max(0, Math.min(1, confidence)) : 1.0,
    detectionTimestamp: detectionTimestamp || new Date().toISOString()
  };
}

module.exports = {
  STATUS,
  SOURCES,
  isValidStatus,
  isValidSource,
  formatSlotRecord
};
