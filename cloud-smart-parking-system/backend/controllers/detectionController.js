/**
 * Detection Controller
 */
const detectionService = require('../services/detectionService');

async function handleDetectionUpdate(req, res) {
  try {
    const payload = req.body;

    // Check if batch payload (array or object containing slots array)
    if (Array.isArray(payload.slots) || Array.isArray(payload)) {
      const slots = Array.isArray(payload.slots) ? payload.slots : payload;
      const result = await detectionService.processBatchDetection({
        parkingArea: payload.parkingArea,
        source: payload.source || 'JSON',
        slots
      });
      return res.json({ success: true, message: 'Batch detection processed', data: result });
    }

    // Single slot payload
    const { slotId, status, source, confidence, parkingArea, detectionTimestamp } = payload;
    if (!slotId || !status) {
      return res.status(400).json({
        success: false,
        error: 'Invalid payload. slotId and status are required for single detection.'
      });
    }

    const result = await detectionService.processSlotDetection({
      slotId,
      status,
      source: source || 'JSON',
      confidence,
      parkingArea,
      detectionTimestamp
    });

    res.json({ success: true, message: 'Detection processed', data: result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
}

async function getHistory(req, res) {
  try {
    const { limit } = req.query;
    const history = await detectionService.getDetectionHistory(limit);
    res.json({ success: true, count: history.length, data: history });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

module.exports = {
  handleDetectionUpdate,
  getHistory
};
