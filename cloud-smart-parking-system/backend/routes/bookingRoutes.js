/**
 * Booking Routes
 */
const express = require('express');
const router = express.Router();
const bookingController = require('../controllers/bookingController');
const { extractUser } = require('../middleware/authMiddleware');

router.post('/', extractUser, bookingController.createBooking);
router.get('/', extractUser, bookingController.getBookings);
router.get('/:bookingId', bookingController.getBookingById);
router.put('/:bookingId/cancel', bookingController.cancelBooking);

module.exports = router;
