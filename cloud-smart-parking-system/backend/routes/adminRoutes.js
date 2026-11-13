/**
 * Admin Routes
 */
const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { requireAdmin } = require('../middleware/authMiddleware');

router.use(requireAdmin);

router.get('/dashboard', adminController.getDashboardStats);
router.post('/slots', adminController.addSlot);
router.delete('/slots/:slotId', adminController.removeSlot);
router.put('/slots/:slotId/status', adminController.updateSlotStatusManual);

module.exports = router;
