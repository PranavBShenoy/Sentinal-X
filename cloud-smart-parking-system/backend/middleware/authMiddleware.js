/**
 * Authentication & Authorization Middleware
 * Protects administrative routes and extracts user context.
 */
require('dotenv').config();

const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'admin-secret-key-smart-parking-2026';

function requireAdmin(req, res, next) {
  const headerKey = req.headers['x-admin-key'];
  const authHeader = req.headers['authorization'];
  let bearerToken = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    bearerToken = authHeader.substring(7).trim();
  }

  const token = headerKey || bearerToken;

  if (!token || token !== ADMIN_API_KEY) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized: Valid Admin API key required',
      hint: 'Include x-admin-key header or Authorization: Bearer <ADMIN_API_KEY>'
    });
  }

  req.isAdmin = true;
  next();
}

function extractUser(req, res, next) {
  const userId = req.headers['x-user-id'] || req.body.userId || req.query.userId || 'guest-user';
  req.userId = String(userId).trim();
  next();
}

module.exports = {
  requireAdmin,
  extractUser
};
