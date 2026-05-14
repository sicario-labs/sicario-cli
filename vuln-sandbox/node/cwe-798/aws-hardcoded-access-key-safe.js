// SAFE: aws-hardcoded-access-key — credentials loaded from environment variables, not hardcoded
// Rule: AwsHardcodedAccessKey | CWE-798 | Expected: TrueNegative

const { S3Client, ListBucketsCommand } = require('@aws-sdk/client-s3');

// SAFE: credentials loaded from environment variables or IAM role, never hardcoded
const client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  // No credentials specified — SDK uses environment variables or instance profile automatically
});

async function listBuckets() {
  const command = new ListBucketsCommand({});
  const response = await client.send(command);
  return response.Buckets;
}

listBuckets().then(console.log).catch(console.error);
