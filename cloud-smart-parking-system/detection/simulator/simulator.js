/**
 * JSON Parking Detection Simulator
 * Reads initial slot data, simulates stochastic vehicle arrival/departure,
 * updates sample-data/parking-data.json, and pushes updates to the cloud API.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

const SAMPLE_DATA_PATH = path.join(__dirname, '..', 'sample-data', 'parking-data.json');
const API_HOST = process.env.API_HOST || '127.0.0.1';
const API_PORT = process.env.API_PORT || 5000;
const INTERVAL_MS = parseInt(process.env.SIMULATION_INTERVAL_MS || '4000', 10);

// Parse CLI flags
const args = process.argv.slice(2);
const runOnce = args.includes('--once');
const cyclesArg = args.find(a => a.startsWith('--cycles='));
const maxCycles = cyclesArg ? parseInt(cyclesArg.split('=')[1], 10) : (runOnce ? 1 : Infinity);

function readSampleData() {
  try {
    if (fs.existsSync(SAMPLE_DATA_PATH)) {
      return JSON.parse(fs.readFileSync(SAMPLE_DATA_PATH, 'utf-8'));
    }
  } catch (err) {
    console.error('[Simulator] Error reading sample data:', err.message);
  }

  // Fallback defaults if file missing
  return {
    parkingArea: 'Main Parking',
    slots: [
      { slotId: 'A01', status: 'FREE', source: 'JSON' },
      { slotId: 'A02', status: 'OCCUPIED', source: 'JSON' },
      { slotId: 'A03', status: 'FREE', source: 'JSON' },
      { slotId: 'B01', status: 'FREE', source: 'JSON' },
      { slotId: 'B02', status: 'OCCUPIED', source: 'JSON' }
    ]
  };
}

function sendDetectionUpdate(payload) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const options = {
      hostname: API_HOST,
      port: API_PORT,
      path: '/api/detection/update',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = http.request(options, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(body));
          } catch {
            resolve(body);
          }
        } else {
          reject(new Error(`API responded with ${res.statusCode}: ${body}`));
        }
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/**
 * Perform one simulation tick
 */
async function simulateCycle(cycleNum) {
  const currentData = readSampleData();
  const slots = currentData.slots || [];
  const now = new Date().toISOString();

  // Pick 1 to 2 slots to simulate physical change
  const numToChange = Math.floor(Math.random() * 2) + 1;
  const changedSlots = [];

  for (let i = 0; i < numToChange; i++) {
    const randIndex = Math.floor(Math.random() * slots.length);
    const slot = slots[randIndex];

    let newStatus = slot.status;

    if (slot.status === 'FREE') {
      // 70% chance to become occupied
      if (Math.random() < 0.7) {
        newStatus = 'OCCUPIED';
      }
    } else if (slot.status === 'OCCUPIED') {
      // 60% chance to depart
      if (Math.random() < 0.6) {
        newStatus = 'FREE';
      }
    } else if (slot.status === 'RESERVED') {
      // Reserved slot: 40% chance driver arrives (OCCUPIED)
      if (Math.random() < 0.4) {
        newStatus = 'OCCUPIED';
      }
      // Note: We never change RESERVED to FREE directly in sensor sim
    } else if (slot.status === 'UNKNOWN') {
      newStatus = 'FREE';
    }

    if (newStatus !== slot.status) {
      slot.previousStatus = slot.status;
      slot.status = newStatus;
      slot.source = 'JSON';
      slot.lastUpdated = now;
      slot.confidence = 1.0;
      changedSlots.push(slot);
    }
  }

  // Update sample data file
  currentData.lastSimulated = now;
  try {
    fs.writeFileSync(SAMPLE_DATA_PATH, JSON.stringify(currentData, null, 2), 'utf-8');
  } catch (err) {
    console.error('[Simulator] Failed to save updated sample JSON:', err.message);
  }

  // Send updates to cloud API
  if (changedSlots.length > 0) {
    console.log(`[Simulator Cycle ${cycleNum}] Simulating events for: ${changedSlots.map(s => `${s.slotId} (${s.previousStatus} -> ${s.status})`).join(', ')}`);
    try {
      await sendDetectionUpdate({
        parkingArea: currentData.parkingArea || 'Main Parking',
        source: 'JSON',
        slots: changedSlots
      });
      console.log(`[Simulator Cycle ${cycleNum}] Synchronized with Cloud API successfully.`);
    } catch (err) {
      console.warn(`[Simulator Cycle ${cycleNum}] Cloud API sync skipped (${err.message}). Is the backend running on port ${API_PORT}?`);
    }
  } else {
    console.log(`[Simulator Cycle ${cycleNum}] No slot status changes in this cycle.`);
  }
}

async function start() {
  console.log('==================================================');
  console.log('🚗 Smart Parking JSON Detection Simulator Started');
  console.log(`📁 Source File: ${SAMPLE_DATA_PATH}`);
  console.log(`🌐 Target Cloud API: http://${API_HOST}:${API_PORT}/api/detection/update`);
  console.log(`⏱️ Interval: ${INTERVAL_MS}ms | Max Cycles: ${maxCycles === Infinity ? 'Infinite' : maxCycles}`);
  console.log('==================================================');

  let cycle = 0;

  async function step() {
    cycle++;
    await simulateCycle(cycle);

    if (cycle >= maxCycles) {
      console.log(`[Simulator] Reached max cycles (${maxCycles}). Stopping simulator.`);
      process.exit(0);
    } else {
      setTimeout(step, INTERVAL_MS);
    }
  }

  await step();
}

if (require.main === module) {
  start();
}

module.exports = { simulateCycle, readSampleData };
