/**
 * Admin Controller
 */
const parkingService = require('../services/parkingService');
const bookingService = require('../services/bookingService');
const detectionService = require('../services/detectionService');

async function getDashboardStats(req, res) {
  try {
    const summary = await parkingService.getAvailabilitySummary();
    const bookings = await bookingService.getAllBookings();
    const history = await detectionService.getDetectionHistory(25);

    // Active vs cancelled bookings count
    const activeBookings = bookings.filter(b => b.status === 'ACTIVE').length;
    const cancelledBookings = bookings.filter(b => b.status === 'CANCELLED').length;

    res.json({
      success: true,
      data: {
        summary,
        totalBookings: bookings.length,
        activeBookings,
        cancelledBookings,
        recentBookings: bookings.slice(0, 10),
        recentHistory: history,
        systemMode: require('../config/dynamodb').getMode()
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

async function addSlot(req, res) {
  try {
    const { slotId, parkingArea, status } = req.body;
    if (!slotId) {
      return res.status(400).json({ success: false, error: 'slotId is required' });
    }

    const slot = await parkingService.addSlot({ slotId, parkingArea, status });
    res.status(201).json({
      success: true,
      message: `Slot ${slot.slotId} added successfully`,
      data: slot
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
}

async function removeSlot(req, res) {
  try {
    const { slotId } = req.params;
    const result = await parkingService.removeSlot(slotId);
    res.json({
      success: true,
      message: `Slot ${slotId} removed successfully`,
      data: result
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
}

async function updateSlotStatusManual(req, res) {
  try {
    const { slotId } = req.params;
    const { status, note } = req.body;

    if (!status) {
      return res.status(400).json({ success: false, error: 'status is required (FREE, OCCUPIED, RESERVED, UNKNOWN)' });
    }

    const updated = await parkingService.updateSlotManualStatus(slotId, status, note);
    res.json({
      success: true,
      message: `Slot ${slotId} status updated to ${status} by admin`,
      data: updated
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
}

module.exports = {
  getDashboardStats,
  addSlot,
  removeSlot,
  updateSlotStatusManual
};
