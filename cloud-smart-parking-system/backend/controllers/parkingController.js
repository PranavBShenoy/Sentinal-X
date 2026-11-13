/**
 * Parking Controller
 */
const parkingService = require('../services/parkingService');
const detectionService = require('../services/detectionService');

async function getSlots(req, res) {
  try {
    const slots = await parkingService.getAllSlots();
    res.json({ success: true, count: slots.length, data: slots });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

async function getAvailability(req, res) {
  try {
    const summary = await parkingService.getAvailabilitySummary();
    res.json({ success: true, data: summary });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

async function getSlotById(req, res) {
  try {
    const { slotId } = req.params;
    const slot = await parkingService.getSlotById(slotId);
    if (!slot) {
      return res.status(404).json({ success: false, error: `Slot ${slotId} not found` });
    }
    res.json({ success: true, data: slot });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

async function updateParkingStatus(req, res) {
  try {
    const { slotId, status, source, confidence, parkingArea, detectionTimestamp } = req.body;
    if (!slotId || !status) {
      return res.status(400).json({ success: false, error: 'slotId and status are required' });
    }

    const result = await detectionService.processSlotDetection({
      slotId,
      status,
      source: source || 'JSON',
      confidence,
      parkingArea,
      detectionTimestamp
    });

    res.json({ success: true, data: result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
}

module.exports = {
  getSlots,
  getAvailability,
  getSlotById,
  updateParkingStatus
};
