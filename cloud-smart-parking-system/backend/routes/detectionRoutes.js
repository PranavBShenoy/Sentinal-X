/**
 * Detection Routes
 */
const express = require('express');
const router = express.Router();
const detectionController = require('../controllers/detectionController');

router.post('/update', detectionController.handleDetectionUpdate);
router.get('/history', detectionController.getHistory);

module.exports = router;
