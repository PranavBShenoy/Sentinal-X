/**
 * Virtual ESP32 IoT Sensor Simulator
 * Emulates physical ultrasonic sensor hardware readings and pushes telemetry
 * to the Smart Parking Cloud REST API with source: "IOT".
 */

const http = require('http');

const API_HOST = process.env.API_HOST || '127.0.0.1';
const API_PORT = process.env.API_PORT || 5000;
const INTERVAL_MS = parseInt(process.env.IOT_INTERVAL_MS || '3500', 10);

// Simulated IoT Nodes
const SENSOR_NODES = [
  { slotId: 'A03', parkingArea: 'Zone A - Ground Level', lastDistance: 175.0 },
  { slotId: 'B01', parkingArea: 'Zone B - Level 1', lastDistance: 190.0 }
];

function sendIoTUpdate(reading) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(reading);
    const req = http.request({
      hostname: API_HOST,
      port: API_PORT,
      path: '/api/detection/update',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    }, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(body)); } catch { resolve(body); }
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

async function runCycle(cycleNum) {
  for (const node of SENSOR_NODES) {
    // 35% chance to toggle distance across the 50cm boundary
    if (Math.random() < 0.35) {
      if (node.lastDistance < 50.0) {
        // Vehicle leaving: distance jumps to clearance (> 120cm)
        node.lastDistance = 140.0 + Math.random() * 80.0;
      } else {
        // Vehicle arriving: distance drops (< 40cm)
        node.lastDistance = 15.0 + Math.random() * 25.0;
      }
    } else {
      // Small sensor jitter +/- 2 cm
      node.lastDistance += (Math.random() * 4 - 2);
    }

    const isOccupied = node.lastDistance < 50.0;
    const status = isOccupied ? 'OCCUPIED' : 'FREE';
    const confidence = isOccupied ? 0.97 : 0.99;

    const payload = {
      slotId: node.slotId,
      parkingArea: node.parkingArea,
      status,
      source: 'IOT',
      confidence,
      distanceCm: Math.round(node.lastDistance * 10) / 10,
      detectionTimestamp: new Date().toISOString()
    };

    try {
      await sendIoTUpdate(payload);
      console.log(`[IoT Cycle ${cycleNum}] Sensor Node ${node.slotId}: ${node.lastDistance.toFixed(1)} cm -> ${status} (Conf: ${confidence})`);
    } catch (err) {
      console.warn(`[IoT Cycle ${cycleNum}] Sensor Node ${node.slotId} sync error:`, err.message);
    }
  }
}

async function start() {
  console.log('==================================================');
  console.log('📡 Virtual ESP32 Ultrasonic Sensor Cluster Active');
  console.log(`🏢 Nodes: ${SENSOR_NODES.map(n => n.slotId).join(', ')}`);
  console.log(`⏱️ Interval: ${INTERVAL_MS}ms | Endpoint: http://${API_HOST}:${API_PORT}/api/detection/update`);
  console.log('==================================================');

  const args = process.argv.slice(2);
  const runOnce = args.includes('--once');

  let cycle = 0;
  async function step() {
    cycle++;
    await runCycle(cycle);
    if (runOnce) {
      console.log('[Virtual Sensor] Completed single cycle.');
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

module.exports = { runCycle, SENSOR_NODES };
