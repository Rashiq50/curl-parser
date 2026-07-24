// AWS S3 integration — OUTDATED fixture
// Uses the monolithic aws-sdk v2 (maintenance mode / EOL).
// Should migrate to modular @aws-sdk/client-s3 v3.

import AWS from "aws-sdk"; // deprecated: v2 monolith

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});

const s3 = new AWS.S3();

// v2 .promise() pattern — replaced by command objects in v3.
export async function uploadObject(bucket, key, body) {
  return s3.putObject({ Bucket: bucket, Key: key, Body: body }).promise();
}

export async function getObject(bucket, key) {
  return s3.getObject({ Bucket: bucket, Key: key }).promise();
}
