/**
 * Booking Controller
 */
const bookingService = require('../services/bookingService');

async function createBooking(req, res) {
  try {
    const { slotId, userId, vehicleNumber, durationMinutes } = req.body;
    const effectiveUserId = userId || req.userId || 'guest-user';

    if (!slotId) {
      return res.status(400).json({ success: false, error: 'slotId is required' });
    }

    const booking = await bookingService.createBooking({
      slotId,
      userId: effectiveUserId,
      vehicleNumber,
      durationMinutes
    });

    res.status(201).json({
      success: true,
      message: `Slot ${booking.slotId} reserved successfully`,
      data: booking
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
}

async function getBookings(req, res) {
  try {
    const { userId } = req.query;
    const bookings = await bookingService.getAllBookings(userId);
    res.json({ success: true, count: bookings.length, data: bookings });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

async function getBookingById(req, res) {
  try {
    const { bookingId } = req.params;
    const booking = await bookingService.getBookingById(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, error: `Booking ${bookingId} not found` });
    }
    res.json({ success: true, data: booking });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

async function cancelBooking(req, res) {
  try {
    const { bookingId } = req.params;
    const result = await bookingService.cancelBooking(bookingId);
    res.json({
      success: true,
      message: `Booking ${bookingId} cancelled successfully`,
      data: result
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
}

module.exports = {
  createBooking,
  getBookings,
  getBookingById,
  cancelBooking
};
