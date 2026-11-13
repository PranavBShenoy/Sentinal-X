/**
 * Admin Console Controller
 * Manages slot configuration, status overrides, and Chart.js analytics.
 */

let occupancyChartInstance = null;
let sourceChartInstance = null;

function configureAdminKey() {
  const currentKey = ParkingAPI.getAdminKey();
  const newKey = prompt('Enter Admin API Key:', currentKey);
  if (newKey && newKey.trim()) {
    ParkingAPI.setAdminKey(newKey.trim());
    ParkingAPI.showToast('Admin API key updated', 'success');
    loadAdminDashboard();
  }
}

async function loadAdminDashboard() {
  try {
    const res = await ParkingAPI.getAdminDashboard();
    if (!res || !res.success) throw new Error('Failed to load admin telemetry');

    const data = res.data;
    const summary = data.summary;

    // Update KPIs
    document.getElementById('admin-total-slots').textContent = summary.totalCapacity;
    document.getElementById('admin-free-slots').textContent = summary.availableSlots;
    document.getElementById('admin-occupied-slots').textContent = summary.occupiedSlots;
    document.getElementById('admin-total-bookings').textContent = data.totalBookings;
    document.getElementById('admin-active-bookings-subtext').textContent = `${data.activeBookings} Active, ${data.cancelledBookings} Cancelled`;

    // Render Charts
    renderOccupancyChart(summary);
    renderSourceChart(summary.detectionSourceStats);

    // Render Tables
    renderSlotsTable(summary.slots);
    renderBookingsTable(data.recentBookings);
    renderHistoryTable(data.recentHistory);
  } catch (err) {
    console.error('Admin loading error:', err);
    ParkingAPI.showToast(`Admin error: ${err.message}`, 'error');
    if (err.message.includes('401') || err.message.includes('Unauthorized')) {
      document.getElementById('admin-auth-status').textContent = 'Key Unauthorized';
      document.getElementById('admin-auth-status').parentElement.style.borderColor = 'rgba(239, 68, 68, 0.4)';
    }
  }
}

function renderOccupancyChart(summary) {
  const ctx = document.getElementById('occupancyChart');
  if (!ctx) return;

  if (occupancyChartInstance) {
    occupancyChartInstance.destroy();
  }

  occupancyChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Free', 'Occupied', 'Reserved', 'Unknown'],
      datasets: [{
        data: [
          summary.availableSlots,
          summary.occupiedSlots,
          summary.reservedSlots,
          summary.unknownSlots
        ],
        backgroundColor: [
          '#10b981', // Free - Green
          '#ef4444', // Occupied - Red
          '#f59e0b', // Reserved - Yellow
          '#6b7280'  // Unknown - Grey
        ],
        borderWidth: 2,
        borderColor: '#0f172a'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 } }
        }
      },
      cutout: '65%'
    }
  });
}

function renderSourceChart(stats = {}) {
  const ctx = document.getElementById('sourceChart');
  if (!ctx) return;

  if (sourceChartInstance) {
    sourceChartInstance.destroy();
  }

  sourceChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['JSON Simulator', 'IoT ESP32', 'CCTV OpenCV', 'Admin Override'],
      datasets: [{
        label: 'Active Bay Sources',
        data: [
          stats.JSON || 0,
          stats.IOT || 0,
          stats.CCTV || 0,
          stats.ADMIN || 0
        ],
        backgroundColor: [
          'rgba(56, 189, 248, 0.75)',
          'rgba(16, 185, 129, 0.75)',
          'rgba(168, 85, 247, 0.75)',
          'rgba(245, 158, 11, 0.75)'
        ],
        borderColor: [
          '#38bdf8',
          '#10b981',
          '#a855f7',
          '#f59e0b'
        ],
        borderWidth: 1,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#94a3b8', font: { family: 'Inter', size: 11 } },
          grid: { display: false }
        },
        y: {
          ticks: { color: '#94a3b8', precision: 0 },
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          beginAtZero: true
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderSlotsTable(slots = []) {
  const tbody = document.getElementById('admin-slots-table-body');
  if (!tbody) return;

  if (slots.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="padding: 2rem; text-align: center; color: var(--text-dim);">No parking slots found.</td></tr>';
    return;
  }

  let html = '';
  slots.forEach(slot => {
    let badgeClass = 'badge-unknown';
    if (slot.status === 'FREE') badgeClass = 'badge-free';
    else if (slot.status === 'OCCUPIED') badgeClass = 'badge-occupied';
    else if (slot.status === 'RESERVED') badgeClass = 'badge-reserved';

    const confidence = slot.confidence !== undefined ? `${Math.round(slot.confidence * 100)}%` : '100%';
    const updated = slot.lastUpdated ? new Date(slot.lastUpdated).toLocaleTimeString() : '--';

    html += `
      <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.05);">
        <td style="padding: 0.75rem;"><strong style="color: #fff;">${slot.slotId}</strong></td>
        <td style="padding: 0.75rem; color: var(--text-muted);">${slot.parkingArea || 'Zone A'}</td>
        <td style="padding: 0.75rem;"><span class="badge ${badgeClass}">${slot.status}</span></td>
        <td style="padding: 0.75rem;"><span class="badge badge-source">${slot.source || 'SYS'}</span></td>
        <td style="padding: 0.75rem; color: var(--accent-cyan); font-weight: 600;">${confidence}</td>
        <td style="padding: 0.75rem; color: var(--text-dim); font-size: 0.8rem;">${updated}</td>
        <td style="padding: 0.75rem; text-align: right;">
          <button class="btn btn-secondary btn-sm" onclick="openOverrideModal('${slot.slotId}', '${slot.status}')" style="margin-right: 0.35rem;">Override</button>
          <button class="btn btn-danger btn-sm" onclick="handleDeleteSlot('${slot.slotId}')">Delete</button>
        </td>
      </tr>
    `;
  });

  tbody.innerHTML = html;
}

function renderBookingsTable(bookings = []) {
  const tbody = document.getElementById('admin-bookings-table-body');
  if (!tbody) return;

  if (bookings.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="padding: 1.5rem; text-align: center; color: var(--text-dim);">No bookings recorded.</td></tr>';
    return;
  }

  let html = '';
  bookings.forEach(b => {
    const isActive = b.status === 'ACTIVE';
    html += `
      <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.04);">
        <td style="padding: 0.5rem;"><strong style="color: #fff;">${b.slotId}</strong></td>
        <td style="padding: 0.5rem; color: var(--text-muted);">${b.userId}</td>
        <td style="padding: 0.5rem; color: var(--accent-blue);">${b.vehicleNumber || 'N/A'}</td>
        <td style="padding: 0.5rem;">
          <span class="badge ${isActive ? 'badge-free' : 'badge-unknown'}" style="font-size: 0.65rem;">
            ${b.status}
          </span>
        </td>
      </tr>
    `;
  });
  tbody.innerHTML = html;
}

function renderHistoryTable(events = []) {
  const tbody = document.getElementById('admin-history-table-body');
  if (!tbody) return;

  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="padding: 1.5rem; text-align: center; color: var(--text-dim);">No detection events logged.</td></tr>';
    return;
  }

  let html = '';
  events.forEach(e => {
    const time = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '--';
    html += `
      <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.04);">
        <td style="padding: 0.5rem;"><strong style="color: #fff;">${e.slotId}</strong></td>
        <td style="padding: 0.5rem; font-size: 0.75rem;">
          <span style="color: var(--text-dim);">${e.previousStatus || 'N/A'}</span> → <strong style="color: #fff;">${e.newStatus}</strong>
        </td>
        <td style="padding: 0.5rem;"><span class="badge badge-source" style="font-size: 0.65rem;">${e.source}</span></td>
        <td style="padding: 0.5rem; color: var(--text-dim); font-size: 0.75rem;">${time}</td>
      </tr>
    `;
  });
  tbody.innerHTML = html;
}

// Modal Handlers
function openAddSlotModal() {
  document.getElementById('add-slot-modal').classList.add('active');
}

function closeAddSlotModal() {
  document.getElementById('add-slot-modal').classList.remove('active');
}

function openOverrideModal(slotId, currentStatus) {
  document.getElementById('override-slot-id').value = slotId;
  document.getElementById('override-slot-label').textContent = `Slot ${slotId} (Current: ${currentStatus})`;
  document.getElementById('override-status-select').value = currentStatus;
  document.getElementById('override-modal').classList.add('active');
}

function closeOverrideModal() {
  document.getElementById('override-modal').classList.remove('active');
}

async function handleAddSlotSubmit(e) {
  e.preventDefault();
  const slotId = document.getElementById('new-slot-id').value.trim().toUpperCase();
  const parkingArea = document.getElementById('new-slot-area').value.trim();
  const status = document.getElementById('new-slot-status').value;

  try {
    const res = await ParkingAPI.addSlot({ slotId, parkingArea, status });
    if (res && res.success) {
      ParkingAPI.showToast(`Slot ${slotId} added successfully!`, 'success');
      closeAddSlotModal();
      document.getElementById('add-slot-form').reset();
      loadAdminDashboard();
    }
  } catch (err) {
    ParkingAPI.showToast(`Failed to add slot: ${err.message}`, 'error');
  }
}

async function handleOverrideSubmit(e) {
  e.preventDefault();
  const slotId = document.getElementById('override-slot-id').value;
  const status = document.getElementById('override-status-select').value;
  const note = document.getElementById('override-note').value;

  try {
    const res = await ParkingAPI.updateSlotStatusManual(slotId, status, note);
    if (res && res.success) {
      ParkingAPI.showToast(`Slot ${slotId} overridden to ${status} (Source: ADMIN)`, 'success');
      closeOverrideModal();
      loadAdminDashboard();
    }
  } catch (err) {
    ParkingAPI.showToast(`Override failed: ${err.message}`, 'error');
  }
}

async function handleDeleteSlot(slotId) {
  if (!confirm(`Are you sure you want to delete Slot ${slotId}? This will remove it from the cloud database.`)) {
    return;
  }

  try {
    const res = await ParkingAPI.removeSlot(slotId);
    if (res && res.success) {
      ParkingAPI.showToast(`Slot ${slotId} deleted`, 'info');
      loadAdminDashboard();
    }
  } catch (err) {
    ParkingAPI.showToast(`Failed to delete slot: ${err.message}`, 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadAdminDashboard();

  const addForm = document.getElementById('add-slot-form');
  if (addForm) addForm.addEventListener('submit', handleAddSlotSubmit);

  const overrideForm = document.getElementById('override-form');
  if (overrideForm) overrideForm.addEventListener('submit', handleOverrideSubmit);
});
