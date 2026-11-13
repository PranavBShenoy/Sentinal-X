/**
 * DynamoDB Table Creation and Initializer Script
 * Creates tables in AWS DynamoDB or DynamoDB Local according to PRD specs.
 */
const {
  CreateTableCommand,
  DescribeTableCommand,
  ListTablesCommand
} = require('@aws-sdk/client-dynamodb');
const { dynamoClient } = require('../config/aws');
require('dotenv').config();

const TABLES = [
  {
    TableName: process.env.DYNAMODB_TABLE_PARKING_SLOTS || 'ParkingSlots',
    KeySchema: [{ AttributeName: 'slotId', KeyType: 'HASH' }],
    AttributeDefinitions: [{ AttributeName: 'slotId', AttributeType: 'S' }],
    BillingMode: 'PAY_PER_REQUEST'
  },
  {
    TableName: process.env.DYNAMODB_TABLE_BOOKINGS || 'Bookings',
    KeySchema: [{ AttributeName: 'bookingId', KeyType: 'HASH' }],
    AttributeDefinitions: [
      { AttributeName: 'bookingId', AttributeType: 'S' },
      { AttributeName: 'userId', AttributeType: 'S' },
      { AttributeName: 'slotId', AttributeType: 'S' }
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'userId-index',
        KeySchema: [{ AttributeName: 'userId', KeyType: 'HASH' }],
        Projection: { ProjectionType: 'ALL' }
      },
      {
        IndexName: 'slotId-index',
        KeySchema: [{ AttributeName: 'slotId', KeyType: 'HASH' }],
        Projection: { ProjectionType: 'ALL' }
      }
    ],
    BillingMode: 'PAY_PER_REQUEST'
  },
  {
    TableName: process.env.DYNAMODB_TABLE_DETECTION_HISTORY || 'DetectionHistory',
    KeySchema: [{ AttributeName: 'eventId', KeyType: 'HASH' }],
    AttributeDefinitions: [
      { AttributeName: 'eventId', AttributeType: 'S' },
      { AttributeName: 'slotId', AttributeType: 'S' },
      { AttributeName: 'timestamp', AttributeType: 'S' }
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'slotId-timestamp-index',
        KeySchema: [
          { AttributeName: 'slotId', KeyType: 'HASH' },
          { AttributeName: 'timestamp', KeyType: 'RANGE' }
        ],
        Projection: { ProjectionType: 'ALL' }
      }
    ],
    BillingMode: 'PAY_PER_REQUEST'
  }
];

async function setupTables() {
  console.log('--- Initializing DynamoDB Tables Setup ---');
  if (!dynamoClient) {
    console.log('[Setup] No active AWS DynamoDB client configured. If running locally with DB_MODE=local, file-based persistence is active.');
    return;
  }

  try {
    const listResult = await dynamoClient.send(new ListTablesCommand({}));
    const existingTables = listResult.TableNames || [];
    console.log('[Setup] Existing tables:', existingTables);

    for (const tableConfig of TABLES) {
      if (existingTables.includes(tableConfig.TableName)) {
        console.log(`[Setup] Table already exists: ${tableConfig.TableName}`);
      } else {
        console.log(`[Setup] Creating table: ${tableConfig.TableName}...`);
        await dynamoClient.send(new CreateTableCommand(tableConfig));
        console.log(`[Setup] Created table: ${tableConfig.TableName} successfully.`);
      }
    }
    console.log('[Setup] All DynamoDB tables ready.');
  } catch (err) {
    console.error('[Setup] Error creating DynamoDB tables:', err.message);
  }
}

if (require.main === module) {
  setupTables();
}

module.exports = { setupTables, TABLES };
