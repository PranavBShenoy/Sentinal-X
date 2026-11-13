/**
 * Booking Controller
 * Manages slot reservations, active booking tracking, and cancellation flow.
 */

let availableSlots = [];

function getUrlParameter(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name);
}

function updateDisplayUser() {
  const user = ParkingAPI.getCurrentUser();
  const el = document.getElementById('display-user-id');
  if (el) el.textContent = user;
}

function changeUserId() {
  const current = ParkingAPI.getCurrentUser();
  const newId = prompt('Enter Driver / User ID:', current);
  if (newId && newId.trim()) {
    ParkingAPI.setCurrentUser(newId.trim());
    updateDisplayUser();
    loadAvailableSlots();
    loadUserBookings();
    ParkingAPI.showToast(`Switched user to ${newId.trim()}`, 'info');
  }
}

async function loadAvailableSlots() {
  const select = document.getElementById('slot-select');
  if (!select) return;

  try {
    const res = await ParkingAPI.getAvailability();
    if (!res || !res.success) throw new Error('Failed to retrieve slots');

    const slots = res.data.slots || [];
    availableSlots = slots.filter(s => s.status === 'FREE');

    if (availableSlots.length === 0) {
      select.innerHTML = '<option value="">No FREE slots currently available (All occupied/reserved)</option>';
      select.disabled = true;
      const submitBtn = document.getElementById('submit-booking-btn');
      if (submitBtn) submitBtn.disabled = true;
      return;
    }

    select.disabled = false;
    const submitBtn = document.getElementById('submit-booking-btn');
    if (submitBtn) submitBtn.disabled = false;

    const requestedSlot = getUrlParameter('slotId');

    let options = '<option value="">-- Choose a Parking Bay --</option>';
    availableSlots.forEach(slot => {
      const isSelected = requestedSlot && requestedSlot.toUpperCase() === slot.slotId ? 'selected' : '';
      options += `<option value="${slot.slotId}" ${isSelected}>Slot ${slot.slotId} - ${slot.parkingArea || 'General'}</option>`;
    });

    select.innerHTML = options;
  } catch (err) {
    console.error('Error loading slots:', err);
    select.innerHTML = '<option value="">Error connecting to AWS cloud</option>';
  }
}

async function loadUserBookings() {
  const container = document.getElementById('user-bookings-container');
  if (!container) return;

  const userId = ParkingAPI.getCurrentUser();

  try {
    const res = await ParkingAPI.getBookings(userId);
    if (!res || !res.success) throw new Error('Failed to fetch bookings');

    const bookings = res.data || [];

    if (bookings.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 2rem; color: var(--text-dim);">
          <div style="font-size: 2rem; margin-bottom: 0.5rem;">🅿️</div>
          <p>No active or historical bookings found for <strong>${userId}</strong>.</p>
        </div>
      `;
      return;
    }

    let html = '<div style="display: flex; flex-direction: column; gap: 0.85rem;">';

    bookings.forEach(b => {
      const isActive = b.status === 'ACTIVE';
      const statusBadge = isActive
        ? '<span class="badge badge-free">ACTIVE</span>'
        : '<span class="badge badge-unknown">CANCELLED</span>';

      const timeStr = b.bookingTime ? new Date(b.bookingTime).toLocaleString() : '--';

      html += `
        <div class="card" style="padding: 1rem; background: rgba(15, 23, 42, 0.6); border: 1px solid ${isActive ? 'rgba(56, 189, 248, 0.3)' : 'rgba(255,255,255,0.06)'};">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <div style="display: flex; align-items: center; gap: 0.5rem;">
              <strong style="font-size: 1.15rem; color: #fff;">Slot ${b.slotId}</strong>
              ${statusBadge}
            </div>
            <span style="font-size: 0.72rem; color: var(--text-dim); font-family: monospace;">${b.bookingId}</span>
          </div>

          <div style="display: flex; justify-content: space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: ${isActive ? '0.75rem' : '0'};">
            <div>🚗 Vehicle: <strong style="color: #fff;">${b.vehicleNumber || 'N/A'}</strong></div>
            <div>⏱️ ${b.durationMinutes || 60} mins</div>
            <div>📅 ${timeStr}</div>
          </div>

          ${isActive ? `
            <div style="display: flex; justify-content: flex-end; border-top: 1px solid rgba(255, 255, 255, 0.05); padding-top: 0.6rem;">
              <button class="btn btn-danger btn-sm" onclick="cancelUserBooking('${b.bookingId}', '${b.slotId}')">
                Cancel Reservation
              </button>
            </div>
          ` : ''}
        </div>
      `;
    });

    html += '</div>';
    container.innerHTML = html;
  } catch (err) {
    console.error('Error loading bookings:', err);
    container.innerHTML = `<p style="color: var(--status-occupied);">Failed to load bookings: ${err.message}</p>`;
  }
}

async function handleBookingSubmit(e) {
  e.preventDefault();

  const slotId = document.getElementById('slot-select').value;
  const vehicleNumber = document.getElementById('vehicle-input').value.trim();
  const durationMinutes = document.getElementById('duration-select').value;
  const userId = ParkingAPI.getCurrentUser();

  if (!slotId) {
    ParkingAPI.showToast('Please select an available parking slot', 'warning');
    return;
  }

  const submitBtn = document.getElementById('submit-booking-btn');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Processing DynamoDB Transaction...';

  try {
    const res = await ParkingAPI.createBooking({
      slotId,
      userId,
      vehicleNumber,
      durationMinutes
    });

    if (res && res.success) {
      ParkingAPI.showToast(`Slot ${slotId} reserved successfully!`, 'success');

      // Populate confirmation card
      const confCard = document.getElementById('confirmation-card');
      document.getElementById('conf-id').textContent = res.data.bookingId;
      document.getElementById('conf-slot').textContent = res.data.slotId;
      document.getElementById('conf-vehicle').textContent = res.data.vehicleNumber;
      document.getElementById('conf-duration').textContent = `${res.data.durationMinutes} Mins`;
      confCard.style.display = 'block';

      // Reset form
      document.getElementById('booking-form').reset();

      // Refresh list and slots
      loadAvailableSlots();
      loadUserBookings();
    }
  } catch (err) {
    ParkingAPI.showToast(`Booking failed: ${err.message}`, 'error');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Confirm & Reserve Slot';
  }
}

async function cancelUserBooking(bookingId, slotId) {
  if (!confirm(`Are you sure you want to cancel your reservation for Slot ${slotId}?`)) {
    return;
  }

  try {
    const res = await ParkingAPI.cancelBooking(bookingId);
    if (res && res.success) {
      ParkingAPI.showToast(`Reservation for Slot ${slotId} cancelled`, 'info');
      // Hide confirmation card if it matches
      const confCard = document.getElementById('confirmation-card');
      const confId = document.getElementById('conf-id').textContent;
      if (confId === bookingId) {
        confCard.style.display = 'none';
      }
      loadAvailableSlots();
      loadUserBookings();
    }
  } catch (err) {
    ParkingAPI.showToast(`Cancellation failed: ${err.message}`, 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  updateDisplayUser();
  loadAvailableSlots();
  loadUserBookings();

  const form = document.getElementById('booking-form');
  if (form) form.addEventListener('submit', handleBookingSubmit);
});
