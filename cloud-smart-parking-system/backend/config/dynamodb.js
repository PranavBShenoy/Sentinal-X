/**
 * Database Abstraction Layer
 * Interfaces with AWS DynamoDB or Local Persistence Store.
 * Conforms to AWS DocumentClient commands.
 */
const fs = require('fs');
const path = require('path');
const {
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  ScanCommand,
  QueryCommand,
  TransactWriteCommand
} = require('@aws-sdk/lib-dynamodb');
const { docClient } = require('./aws');
require('dotenv').config();

const DB_MODE = process.env.DB_MODE || 'local';
const LOCAL_STORE_FILE = path.join(__dirname, '..', 'data', 'local_dynamodb_store.json');

// In-Memory store for local development mode
let localTables = {
  ParkingSlots: {},
  Bookings: {},
  DetectionHistory: {}
};

// Ensure data directory exists
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Load existing local store if available, or seed from detection/sample-data/parking-data.json
function initLocalStore() {
  try {
    if (fs.existsSync(LOCAL_STORE_FILE)) {
      const data = JSON.parse(fs.readFileSync(LOCAL_STORE_FILE, 'utf-8'));
      localTables = {
        ParkingSlots: data.ParkingSlots || {},
        Bookings: data.Bookings || {},
        DetectionHistory: data.DetectionHistory || {}
      };
    } else {
      // Seed initial slots from sample json
      const samplePath = path.join(__dirname, '..', '..', 'detection', 'sample-data', 'parking-data.json');
      if (fs.existsSync(samplePath)) {
        const sample = JSON.parse(fs.readFileSync(samplePath, 'utf-8'));
        if (Array.isArray(sample.slots)) {
          sample.slots.forEach(slot => {
            localTables.ParkingSlots[slot.slotId] = {
              ...slot,
              parkingArea: slot.parkingArea || sample.parkingArea || 'Main Parking',
              lastUpdated: slot.lastUpdated || new Date().toISOString(),
              confidence: slot.confidence !== undefined ? slot.confidence : 1.0
            };
          });
        }
      }
      saveLocalStore();
    }
  } catch (err) {
    console.error('[DB] Error initializing local store:', err.message);
  }
}

function saveLocalStore() {
  if (DB_MODE === 'local') {
    try {
      fs.writeFileSync(LOCAL_STORE_FILE, JSON.stringify(localTables, null, 2), 'utf-8');
    } catch (err) {
      console.error('[DB] Failed to persist local store:', err.message);
    }
  }
}

if (DB_MODE === 'local') {
  initLocalStore();
}

/**
 * DynamoDB Adapter Object
 */
const db = {
  getMode() {
    return DB_MODE;
  },

  async getItem({ TableName, Key }) {
    if (DB_MODE === 'aws' || DB_MODE === 'dynamodb-local') {
      const command = new GetCommand({ TableName, Key });
      const result = await docClient.send(command);
      return { Item: result.Item || null };
    }

    // Local Mode
    const table = localTables[TableName] || {};
    const pk = Object.values(Key)[0];
    const item = table[pk] ? JSON.parse(JSON.stringify(table[pk])) : null;
    return { Item: item };
  },

  async putItem({ TableName, Item, ConditionExpression }) {
    if (DB_MODE === 'aws' || DB_MODE === 'dynamodb-local') {
      const command = new PutCommand({ TableName, Item, ConditionExpression });
      return await docClient.send(command);
    }

    // Local Mode
    const table = localTables[TableName] = localTables[TableName] || {};
    const pk = Item.slotId || Item.bookingId || Item.eventId;

    // Evaluate simple attribute_not_exists condition
    if (ConditionExpression && ConditionExpression.includes('attribute_not_exists')) {
      if (table[pk]) {
        const err = new Error('The conditional request failed: Item already exists');
        err.name = 'ConditionalCheckFailedException';
        throw err;
      }
    }

    table[pk] = JSON.parse(JSON.stringify(Item));
    saveLocalStore();
    return { Attributes: table[pk] };
  },

  async updateItem({ TableName, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames, ConditionExpression }) {
    if (DB_MODE === 'aws' || DB_MODE === 'dynamodb-local') {
      const command = new UpdateCommand({
        TableName,
        Key,
        UpdateExpression,
        ExpressionAttributeValues,
        ExpressionAttributeNames,
        ConditionExpression,
        ReturnValues: 'ALL_NEW'
      });
      return await docClient.send(command);
    }

    // Local Mode
    const table = localTables[TableName] = localTables[TableName] || {};
    const pk = Object.values(Key)[0];
    const existing = table[pk];

    if (!existing) {
      const err = new Error(`Item ${pk} not found in ${TableName}`);
      err.name = 'ResourceNotFoundException';
      throw err;
    }

    // Evaluate conditional expressions for atomic checks
    if (ConditionExpression) {
      if (ConditionExpression.includes('#s = :free') || ConditionExpression.includes('status = :free')) {
        const expectedStatus = ExpressionAttributeValues[':free'];
        if (existing.status !== expectedStatus) {
          const err = new Error(`ConditionalCheckFailedException: Status is ${existing.status}, expected ${expectedStatus}`);
          err.name = 'ConditionalCheckFailedException';
          throw err;
        }
      }
    }

    // Apply updates based on UpdateExpression and ExpressionAttributeNames
    if (UpdateExpression) {
      const parts = UpdateExpression.split(' ');
      if (UpdateExpression.includes('SET ')) {
        const setPart = UpdateExpression.split('SET ')[1].split('REMOVE')[0].trim();
        const assignments = setPart.split(',').map(s => s.trim());
        assignments.forEach(assign => {
          const [rawField, rawVal] = assign.split('=').map(s => s.trim());
          const fieldName = (ExpressionAttributeNames && ExpressionAttributeNames[rawField])
            ? ExpressionAttributeNames[rawField]
            : rawField.replace('#', '');
          const val = (ExpressionAttributeValues && ExpressionAttributeValues[rawVal] !== undefined)
            ? ExpressionAttributeValues[rawVal]
            : rawVal;
          existing[fieldName] = val;
        });
      }
      if (UpdateExpression.includes('REMOVE ')) {
        const removePart = UpdateExpression.split('REMOVE ')[1].trim();
        const removeFields = removePart.split(',').map(s => s.trim());
        removeFields.forEach(f => {
          const fieldName = (ExpressionAttributeNames && ExpressionAttributeNames[f])
            ? ExpressionAttributeNames[f]
            : f.replace('#', '');
          delete existing[fieldName];
        });
      }
    } else if (ExpressionAttributeValues) {
      Object.keys(ExpressionAttributeValues).forEach(k => {
        const fieldName = k.replace(':', '');
        existing[fieldName] = ExpressionAttributeValues[k];
      });
    }

    table[pk] = existing;
    saveLocalStore();
    return { Attributes: JSON.parse(JSON.stringify(existing)) };
  },

  async deleteItem({ TableName, Key }) {
    if (DB_MODE === 'aws' || DB_MODE === 'dynamodb-local') {
      const command = new DeleteCommand({ TableName, Key });
      return await docClient.send(command);
    }

    // Local Mode
    const table = localTables[TableName] || {};
    const pk = Object.values(Key)[0];
    delete table[pk];
    saveLocalStore();
    return {};
  },

  async scan({ TableName }) {
    if (DB_MODE === 'aws' || DB_MODE === 'dynamodb-local') {
      const command = new ScanCommand({ TableName });
      const result = await docClient.send(command);
      return { Items: result.Items || [] };
    }

    // Local Mode
    const table = localTables[TableName] || {};
    const items = Object.values(table).map(i => JSON.parse(JSON.stringify(i)));
    return { Items: items };
  },

  async query({ TableName, IndexName, KeyConditionExpression, ExpressionAttributeValues }) {
    if (DB_MODE === 'aws' || DB_MODE === 'dynamodb-local') {
      const command = new QueryCommand({
        TableName,
        IndexName,
        KeyConditionExpression,
        ExpressionAttributeValues
      });
      const result = await docClient.send(command);
      return { Items: result.Items || [] };
    }

    // Local Mode fallback query
    const table = localTables[TableName] || {};
    let items = Object.values(table);

    if (ExpressionAttributeValues) {
      Object.entries(ExpressionAttributeValues).forEach(([k, val]) => {
        const attr = k.replace(':', '');
        items = items.filter(item => item[attr] === val);
      });
    }

    return { Items: items.map(i => JSON.parse(JSON.stringify(i))) };
  },

  async transactWrite({ TransactItems }) {
    if (DB_MODE === 'aws' || DB_MODE === 'dynamodb-local') {
      const command = new TransactWriteCommand({ TransactItems });
      return await docClient.send(command);
    }

    // Local Mode Transaction: atomic validation & commit
    // First pass: validation
    for (const item of TransactItems) {
      if (item.Update) {
        const { TableName, Key, ConditionExpression, ExpressionAttributeValues } = item.Update;
        const pk = Object.values(Key)[0];
        const record = (localTables[TableName] || {})[pk];
        if (!record) {
          const err = new Error(`Transaction failed: ${pk} not found`);
          err.name = 'TransactionCanceledException';
          throw err;
        }
        if (ConditionExpression && (ConditionExpression.includes('#s = :free') || ConditionExpression.includes('status = :free'))) {
          if (record.status !== ExpressionAttributeValues[':free']) {
            const err = new Error(`Transaction failed: Slot ${pk} is not FREE (currently ${record.status})`);
            err.name = 'TransactionCanceledException';
            throw err;
          }
        }
      }
      if (item.Put) {
        const { TableName, Item, ConditionExpression } = item.Put;
        const pk = Item.bookingId || Item.eventId || Item.slotId;
        if (ConditionExpression && ConditionExpression.includes('attribute_not_exists')) {
          if ((localTables[TableName] || {})[pk]) {
            const err = new Error(`Transaction failed: Duplicate key ${pk}`);
            err.name = 'TransactionCanceledException';
            throw err;
          }
        }
      }
    }

    // Second pass: apply updates
    for (const item of TransactItems) {
      if (item.Update) {
        const { TableName, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues } = item.Update;
        const pk = Object.values(Key)[0];
        const record = localTables[TableName][pk];

        // Parse SET statements e.g. "SET #s = :reserved, #lu = :now, #actBkg = :bkgId"
        if (UpdateExpression && UpdateExpression.startsWith('SET ')) {
          const setClause = UpdateExpression.replace('SET ', '');
          const assignments = setClause.split(',').map(s => s.trim());

          assignments.forEach(assign => {
            const [rawField, rawVal] = assign.split('=').map(s => s.trim());
            const fieldName = (ExpressionAttributeNames && ExpressionAttributeNames[rawField])
              ? ExpressionAttributeNames[rawField]
              : rawField.replace('#', '');
            const val = (ExpressionAttributeValues && ExpressionAttributeValues[rawVal] !== undefined)
              ? ExpressionAttributeValues[rawVal]
              : rawVal;
            record[fieldName] = val;
          });
        }
      }
      if (item.Put) {
        const { TableName, Item } = item.Put;
        const pk = Item.bookingId || Item.eventId || Item.slotId;
        localTables[TableName] = localTables[TableName] || {};
        localTables[TableName][pk] = JSON.parse(JSON.stringify(Item));
      }
    }

    saveLocalStore();
    return { success: true };
  },

  // Reset or reseed local store (useful for automated testing)
  resetLocalStore() {
    localTables = { ParkingSlots: {}, Bookings: {}, DetectionHistory: {} };
    initLocalStore();
  }
};

module.exports = db;
