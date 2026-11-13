/**
 * Seed Script
 * Resets and populates initial parking slots in local or DynamoDB database.
 */
const fs = require('fs');
const path = require('path');
const db = require('../config/dynamodb');
require('dotenv').config();

const TABLE_PARKING_SLOTS = process.env.DYNAMODB_TABLE_PARKING_SLOTS || 'ParkingSlots';

async function seed() {
  console.log('--- Seeding Parking Slots into Database ---');
  console.log(`Target Mode: [${db.getMode().toUpperCase()}]`);

  const samplePath = path.join(__dirname, '..', '..', 'detection', 'sample-data', 'parking-data.json');
  if (!fs.existsSync(samplePath)) {
    console.error('Sample data file not found at:', samplePath);
    process.exit(1);
  }

  const sample = JSON.parse(fs.readFileSync(samplePath, 'utf-8'));
  const slots = sample.slots || [];
  const now = new Date().toISOString();

  let count = 0;
  for (const slot of slots) {
    const item = {
      slotId: slot.slotId,
      parkingArea: slot.parkingArea || sample.parkingArea || 'Zone A',
      status: slot.status || 'FREE',
      source: slot.source || 'JSON',
      confidence: slot.confidence !== undefined ? slot.confidence : 1.0,
      lastUpdated: now,
      detectionTimestamp: now
    };

    await db.putItem({
      TableName: TABLE_PARKING_SLOTS,
      Item: item
    });
    count++;
    console.log(`  Seeded slot: ${slot.slotId} (${item.status}) in ${item.parkingArea}`);
  }

  console.log(`\n✅ Successfully seeded ${count} parking slots.`);
}

if (require.main === module) {
  seed().then(() => process.exit(0)).catch(err => {
    console.error('Seeding error:', err);
    process.exit(1);
  });
}

module.exports = { seed };
