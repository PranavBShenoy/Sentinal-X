/**
 * Backend API Verification Test
 * Tests health endpoint, parking routes, detection routes, booking flow, and admin access.
 */
const http = require('http');
const app = require('../server');

let server;
const PORT = 5099;

function request(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request({ ...options, port: PORT, host: '127.0.0.1' }, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const json = body ? JSON.parse(body) : null;
          resolve({ status: res.statusCode, headers: res.headers, body: json, rawBody: body });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body, rawBody: body });
        }
      });
    });
    req.on('error', reject);
    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

async function runTests() {
  console.log('🧪 Starting API Verification Tests...');
  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${message}`);
      failed++;
    }
  }

  server = app.listen(PORT);

  try {
    // 1. Health Endpoint Test
    const healthRes = await request({ path: '/api/health', method: 'GET' });
    assert(healthRes.status === 200, 'GET /api/health returns 200');
    assert(healthRes.body && healthRes.body.status === 'HEALTHY', 'Status is HEALTHY');
    assert(healthRes.body && healthRes.body.databaseMode === 'local', 'Database mode is local for development');

    // 2. Parking Slots Retrieval Test
    const slotsRes = await request({ path: '/api/parking/slots', method: 'GET' });
    assert(slotsRes.status === 200, 'GET /api/parking/slots returns 200');
    assert(Array.isArray(slotsRes.body.data) && slotsRes.body.data.length > 0, 'Initial seeded slots exist');

    // 3. Availability Summary Test
    const availRes = await request({ path: '/api/parking/availability', method: 'GET' });
    assert(availRes.status === 200, 'GET /api/parking/availability returns 200');
    assert(availRes.body.data.totalCapacity > 0, 'Availability totalCapacity > 0');
    assert(typeof availRes.body.data.availableSlots === 'number', 'availableSlots is a number');

    // 4. Booking Creation Test
    const freeSlot = availRes.body.data.slots.find(s => s.status === 'FREE');
    if (freeSlot) {
      const bookRes = await request(
        {
          path: '/api/bookings',
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        },
        { slotId: freeSlot.slotId, userId: 'test-driver-1', vehicleNumber: 'KA-01-AB-1234' }
      );
      assert(bookRes.status === 201, `POST /api/bookings reserved slot ${freeSlot.slotId}`);
      assert(bookRes.body.data && bookRes.body.data.status === 'ACTIVE', 'Booking status is ACTIVE');

      // Attempt double-booking same slot (should fail)
      const doubleBookRes = await request(
        {
          path: '/api/bookings',
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        },
        { slotId: freeSlot.slotId, userId: 'test-driver-2' }
      );
      assert(doubleBookRes.status === 400, 'Prevent duplicate booking of already reserved slot');

      // Cancel booking
      const cancelRes = await request(
        {
          path: `/api/bookings/${bookRes.body.data.bookingId}/cancel`,
          method: 'PUT'
        }
      );
      assert(cancelRes.status === 200, 'PUT /api/bookings/:id/cancel releases slot');
    }

    // 5. Admin Security Test
    const adminNoKey = await request({ path: '/api/admin/dashboard', method: 'GET' });
    assert(adminNoKey.status === 401, 'GET /api/admin/dashboard without key rejects with 401');

    const adminWithKey = await request({
      path: '/api/admin/dashboard',
      method: 'GET',
      headers: { 'x-admin-key': 'admin-secret-key-smart-parking-2026' }
    });
    assert(adminWithKey.status === 200, 'GET /api/admin/dashboard with key returns 200');

    // 6. Detection Update Test
    const detectRes = await request(
      {
        path: '/api/detection/update',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      },
      { slotId: 'A03', status: 'OCCUPIED', source: 'JSON', confidence: 0.98 }
    );
    assert(detectRes.status === 200, 'POST /api/detection/update updates slot status');

    console.log(`\n🏁 Test Results: ${passed} passed, ${failed} failed`);
  } catch (err) {
    console.error('Test execution error:', err);
    failed++;
  } finally {
    server.close();
    process.exit(failed > 0 ? 1 : 0);
  }
}

if (require.main === module) {
  runTests();
}
