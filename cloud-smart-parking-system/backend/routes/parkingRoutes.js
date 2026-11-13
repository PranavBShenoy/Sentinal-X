/**
 * Parking Routes
 */
const express = require('express');
const router = express.Router();
const parkingController = require('../controllers/parkingController');

router.get('/slots', parkingController.getSlots);
router.get('/availability', parkingController.getAvailability);
router.get('/slots/:slotId', parkingController.getSlotById);
router.post('/update', parkingController.updateParkingStatus);

module.exports = router;
