/**
 * Cloud-Based Smart Parking Management System - Backend Server
 */
const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const db = require('./config/dynamodb');
const parkingRoutes = require('./routes/parkingRoutes');
const bookingRoutes = require('./routes/bookingRoutes');
const adminRoutes = require('./routes/adminRoutes');
const detectionRoutes = require('./routes/detectionRoutes');

const app = express();
const PORT = process.env.PORT || 5000;
const startTime = new Date();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files
const frontendPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(frontendPath));

// Request logger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ${res.statusCode} (${duration}ms)`);
    }
  });
  next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'HEALTHY',
    service: 'Cloud Smart Parking API',
    version: '1.0.0',
    uptimeSeconds: Math.floor((new Date() - startTime) / 1000),
    databaseMode: db.getMode(),
    timestamp: new Date().toISOString()
  });
});

// API Routes
app.use('/api/parking', parkingRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/detection', detectionRoutes);

// Catch-all for API 404
app.all('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: `Endpoint not found: ${req.method} ${req.originalUrl}`
  });
});

// Fallback route for single-page navigation to landing
app.get('/', (req, res) => {
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[Unhandled Error]', err.stack || err.message);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

// Start server if not imported by test suite
if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log('==================================================');
    console.log(`🚀 Smart Parking System Backend running on port ${PORT}`);
    console.log(`📡 Database Mode: [${db.getMode().toUpperCase()}]`);
    console.log(`🌐 Web UI: http://localhost:${PORT}`);
    console.log(`🩺 Health API: http://localhost:${PORT}/api/health`);
    console.log('==================================================');
  });

  process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => console.log('HTTP server closed'));
  });
}

module.exports = app;
