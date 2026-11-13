/**
 * AWS SDK Configuration
 * Supports AWS EC2 IAM Roles, explicit credentials, or DynamoDB Local endpoint.
 */
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient } = require('@aws-sdk/lib-dynamodb');
require('dotenv').config();

const region = process.env.AWS_REGION || 'us-east-1';
const clientConfig = { region };

// If using DynamoDB Local
if (process.env.DB_MODE === 'dynamodb-local' || process.env.DYNAMODB_ENDPOINT) {
  if (process.env.DB_MODE === 'dynamodb-local') {
    clientConfig.endpoint = process.env.DYNAMODB_ENDPOINT || 'http://localhost:8000';
    clientConfig.credentials = {
      accessKeyId: 'fakeMyKeyId',
      secretAccessKey: 'fakeSecretAccessKey'
    };
  }
}

// If explicit AWS credentials provided in .env (for local dev with real AWS)
if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
  clientConfig.credentials = {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  };
}

let dynamoClient = null;
let docClient = null;

try {
  dynamoClient = new DynamoDBClient(clientConfig);
  docClient = DynamoDBDocumentClient.from(dynamoClient, {
    marshallOptions: {
      removeUndefinedValues: true,
      convertEmptyValues: false
    }
  });
} catch (err) {
  console.warn('[AWS] DynamoDB Client initialization note:', err.message);
}

module.exports = {
  region,
  dynamoClient,
  docClient
};
