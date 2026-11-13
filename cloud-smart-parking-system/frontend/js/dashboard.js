/**
 * Dashboard Controller
 * Manages live telemetry updates, parking zone rendering, and slot inspection.
 */

let currentSlots = [];
let activeFilter = 'ALL';
let autoRefreshTimer = null;
let countdownTimer = null;
let countdownSecs = 3;

// SVG Silhouette for Top-Down Car
const CAR_SVG = `
<svg class="car-icon-svg" viewBox="0 0 100 160" fill="none" xmlns="http://www.w3.org/2000/svg">
  <!-- Vehicle Body -->
  <rect x="18" y="10" width="64" height="140" rx="20" fill="currentColor" fill-opacity="0.85" stroke="rgba(255,255,255,0.4)" stroke-width="2"/>
  <!-- Front Windshield -->
  <path d="M 26 50 Q 50 42 74 50 L 70 65 Q 50 60 30 65 Z" fill="#0f172a" stroke="rgba(255,255,255,0.2)" stroke-width="1.5"/>
  <!-- Rear Windshield -->
  <path d="M 28 115 Q 50 120 72 115 L 70 128 Q 50 132 30 128 Z" fill="#0f172a" stroke="rgba(255,255,255,0.2)" stroke-width="1.5"/>
  <!-- Side Windows -->
  <rect x="23" y="68" width="6" height="42" rx="2" fill="#0f172a"/>
  <rect x="71" y="68" width="6" height="42" rx="2" fill="#0f172a"/>
  <!-- Headlights -->
  <circle cx="28" cy="18" r="4" fill="#fef08a"/>
  <circle cx="72" cy="18" r="4" fill="#fef08a"/>
  <!-- Taillights -->
  <rect x="24" y="145" width="10" height="4" rx="2" fill="#ef4444"/>
  <rect x="66" y="145" width="10" height="4" rx="2" fill="#ef4444"/>
</svg>
`;

async function fetchDashboardData() {
  try {
    const res = await ParkingAPI.getAvailability();
    if (!res || !res.success) throw new Error('Failed to fetch data');

    const data = res.data;
    currentSlots = data.slots || [];

    // Update KPIs
    document.getElementById('kpi-total').textContent = data.totalCapacity;
    document.getElementById('kpi-free').textContent = data.availableSlots;
    document.getElementById('kpi-occupied').textContent = data.occupiedSlots;
    document.getElementById('kpi-reserved').textContent = data.reservedSlots;
    document.getElementById('kpi-percentage').textContent = `${data.availabilityPercentage}%`;

    // Last updated
    const dt = new Date(data.lastUpdated);
    document.getElementById('last-updated-text').textContent = dt.toLocaleTimeString();

    renderParkingFacility();
  } catch (err) {
    console.error('Error fetching dashboard:', err);
    ParkingAPI.showToast('Failed to connect to parking telemetry', 'error');
  }
}

function renderParkingFacility() {
  const container = document.getElementById('parking-zones-container');
  if (!container) return;

  // Filter slots
  const filtered = currentSlots.filter(s => {
    if (activeFilter === 'ALL') return true;
    return s.status === activeFilter;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="card" style="text-align: center; padding: 3rem;">
        <p style="color: var(--text-dim); font-size: 1rem;">No parking slots match filter "${activeFilter}".</p>
      </div>
    `;
    return;
  }

  // Group by Parking Area / Zone
  const zones = {};
  filtered.forEach(slot => {
    const zoneName = slot.parkingArea || 'General Parking';
    if (!zones[zoneName]) zones[zoneName] = [];
    zones[zoneName].push(slot);
  });

  let html = '';

  Object.entries(zones).forEach(([zoneName, slots]) => {
    const freeCount = slots.filter(s => s.status === 'FREE').length;

    html += `
      <div class="parking-lot-section">
        <div class="zone-header">
          <div class="zone-title">
            <span>📍 ${zoneName}</span>
            <span class="badge badge-source">${slots.length} Bays</span>
          </div>
          <span style="font-size: 0.85rem; color: var(--status-free); font-weight: 600;">
            ${freeCount} Free Available
          </span>
        </div>

        <div class="zone-grid">
          ${slots.map(slot => renderSlotCard(slot)).join('')}
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

function renderSlotCard(slot) {
  const statusClass = `slot-${slot.status.toLowerCase()}`;
  let badgeClass = 'badge-unknown';
  let carColor = '#64748b';

  if (slot.status === 'FREE') {
    badgeClass = 'badge-free';
    carColor = '#10b981';
  } else if (slot.status === 'OCCUPIED') {
    badgeClass = 'badge-occupied';
    carColor = '#ef4444';
  } else if (slot.status === 'RESERVED') {
    badgeClass = 'badge-reserved';
    carColor = '#f59e0b';
  }

  const confidence = slot.confidence !== undefined ? `${Math.round(slot.confidence * 100)}%` : '100%';

  return `
    <div class="parking-slot-card ${statusClass}" onclick="openSlotModal('${slot.slotId}')" title="Click to view ${slot.slotId} details">
      <div class="slot-header">
        <span class="slot-id">${slot.slotId}</span>
        <span class="badge ${badgeClass}">${slot.status}</span>
      </div>

      <div class="slot-visual" style="color: ${carColor};">
        ${CAR_SVG}
      </div>

      <div class="slot-footer">
        <span class="source-tag">${slot.source || 'SYS'}</span>
        <span>${confidence}</span>
      </div>
    </div>
  `;
}

function openSlotModal(slotId) {
  const slot = currentSlots.find(s => s.slotId === slotId);
  if (!slot) return;

  const modal = document.getElementById('slot-modal');
  document.getElementById('modal-slot-id').textContent = `Slot ${slot.slotId}`;

  const badge = document.getElementById('modal-slot-badge');
  badge.textContent = slot.status;
  badge.className = `badge badge-${slot.status.toLowerCase()}`;

  document.getElementById('modal-slot-area').textContent = slot.parkingArea || 'Zone A';
  document.getElementById('modal-slot-source').textContent = slot.source || 'JSON';
  document.getElementById('modal-slot-confidence').textContent = `${Math.round((slot.confidence || 1) * 100)}% Verified`;

  const dt = slot.lastUpdated ? new Date(slot.lastUpdated).toLocaleString() : 'Just now';
  document.getElementById('modal-slot-updated').textContent = dt;

  const actionContainer = document.getElementById('modal-action-container');

  if (slot.status === 'FREE') {
    actionContainer.innerHTML = `
      <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; text-align: center;">
        <span style="color: var(--status-free); font-weight: 600;">✅ This slot is completely free!</span>
      </div>
      <a href="booking.html?slotId=${encodeURIComponent(slot.slotId)}" class="btn btn-primary" style="width: 100%;">
        🎟️ Reserve Slot ${slot.slotId} Now
      </a>
    `;
  } else if (slot.status === 'RESERVED') {
    actionContainer.innerHTML = `
      <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 8px; padding: 1rem; text-align: center;">
        <span style="color: var(--status-reserved); font-weight: 600;">🟡 This slot is reserved by another driver.</span>
        <p style="font-size: 0.82rem; color: var(--text-muted); margin-top: 0.3rem;">Simultaneous bookings are locked by AWS DynamoDB transactions.</p>
      </div>
    `;
  } else if (slot.status === 'OCCUPIED') {
    actionContainer.innerHTML = `
      <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 1rem; text-align: center;">
        <span style="color: var(--status-occupied); font-weight: 600;">🔴 A vehicle is currently parked in this space.</span>
      </div>
    `;
  } else {
    actionContainer.innerHTML = `
      <div style="background: rgba(107, 114, 128, 0.1); border: 1px solid rgba(107, 114, 128, 0.3); border-radius: 8px; padding: 1rem; text-align: center;">
        <span style="color: var(--status-unknown); font-weight: 600;">⚪ Slot status is UNKNOWN (Awaiting sensor verification)</span>
      </div>
    `;
  }

  modal.classList.add('active');
}

function closeSlotModal() {
  const modal = document.getElementById('slot-modal');
  if (modal) modal.classList.remove('active');
}

// Setup Filters
function setupFilters() {
  const buttons = document.querySelectorAll('.filter-btn');
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      buttons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilter = btn.dataset.filter;
      renderParkingFacility();
    });
  });
}

// Setup Auto Sync
function setupAutoSync() {
  const toggle = document.getElementById('auto-refresh-toggle');
  const countdownEl = document.getElementById('sync-countdown');
  const refreshBtn = document.getElementById('manual-refresh-btn');

  refreshBtn.addEventListener('click', () => {
    fetchDashboardData();
    countdownSecs = 3;
  });

  countdownTimer = setInterval(() => {
    if (toggle && toggle.checked) {
      countdownSecs--;
      if (countdownSecs <= 0) {
        countdownSecs = 3;
        fetchDashboardData();
      }
      if (countdownEl) countdownEl.textContent = `(${countdownSecs})`;
    } else {
      if (countdownEl) countdownEl.textContent = '(Paused)';
    }
  }, 1000);
}

// Modal Backdrop Click
window.addEventListener('click', (e) => {
  const modal = document.getElementById('slot-modal');
  if (e.target === modal) {
    closeSlotModal();
  }
});

document.addEventListener('DOMContentLoaded', () => {
  setupFilters();
  setupAutoSync();
  fetchDashboardData();
});
