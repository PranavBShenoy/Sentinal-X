/**
 * Smart Parking Frontend - Unified API Client
 */

const API_BASE_URL = '/api';

// Admin Key Storage
function getAdminKey() {
  return localStorage.getItem('smart_parking_admin_key') || 'admin-secret-key-smart-parking-2026';
}

function setAdminKey(key) {
  localStorage.setItem('smart_parking_admin_key', key);
}

// Current User ID Storage
function getCurrentUser() {
  let userId = localStorage.getItem('smart_parking_user_id');
  if (!userId) {
    userId = 'driver-' + Math.floor(1000 + Math.random() * 9000);
    localStorage.setItem('smart_parking_user_id', userId);
  }
  return userId;
}

function setCurrentUser(userId) {
  if (userId) {
    localStorage.setItem('smart_parking_user_id', userId.trim());
  }
}

/**
 * Core Fetch Wrapper
 */
async function request(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'x-user-id': getCurrentUser(),
    ...options.headers
  };

  if (options.requireAdmin) {
    headers['x-admin-key'] = getAdminKey();
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers
    });

    const data = await response.json().catch(() => null);

    if (!response.ok) {
      const errorMsg = (data && data.error) ? data.error : `HTTP error: ${response.status} ${response.statusText}`;
      throw new Error(errorMsg);
    }

    return data;
  } catch (err) {
    console.error(`[API Error] ${options.method || 'GET'} ${endpoint}:`, err.message);
    throw err;
  }
}

/**
 * Toast Notification Utility
 */
function showToast(message, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : type === 'warning' ? '⚠' : 'ℹ';
  toast.innerHTML = `<span style="font-weight:bold">${icon}</span> <span>${message}</span>`;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

/**
 * Exported API Functions
 */
window.ParkingAPI = {
  getAdminKey,
  setAdminKey,
  getCurrentUser,
  setCurrentUser,
  showToast,

  // Health
  async getHealth() {
    return await request('/health');
  },

  // Parking Slots & Availability
  async getSlots() {
    return await request('/parking/slots');
  },

  async getAvailability() {
    return await request('/parking/availability');
  },

  async getSlot(slotId) {
    return await request(`/parking/slots/${encodeURIComponent(slotId)}`);
  },

  // Bookings
  async createBooking(bookingData) {
    return await request('/bookings', {
      method: 'POST',
      body: JSON.stringify(bookingData)
    });
  },

  async getBookings(userId = null) {
    const query = userId ? `?userId=${encodeURIComponent(userId)}` : '';
    return await request(`/bookings${query}`);
  },

  async getBooking(bookingId) {
    return await request(`/bookings/${encodeURIComponent(bookingId)}`);
  },

  async cancelBooking(bookingId) {
    return await request(`/bookings/${encodeURIComponent(bookingId)}/cancel`, {
      method: 'PUT'
    });
  },

  // Admin APIs
  async getAdminDashboard() {
    return await request('/admin/dashboard', { requireAdmin: true });
  },

  async addSlot(slotData) {
    return await request('/admin/slots', {
      method: 'POST',
      requireAdmin: true,
      body: JSON.stringify(slotData)
    });
  },

  async removeSlot(slotId) {
    return await request(`/admin/slots/${encodeURIComponent(slotId)}`, {
      method: 'DELETE',
      requireAdmin: true
    });
  },

  async updateSlotStatusManual(slotId, status, note = '') {
    return await request(`/admin/slots/${encodeURIComponent(slotId)}/status`, {
      method: 'PUT',
      requireAdmin: true,
      body: JSON.stringify({ status, note })
    });
  },

  // Detection APIs
  async sendDetection(data) {
    return await request('/detection/update', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async getDetectionHistory(limit = 25) {
    return await request(`/detection/history?limit=${limit}`);
  }
};
