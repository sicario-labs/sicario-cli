// SAFE: aws-s3-public-read-acl — S3 object uploaded without public-read ACL
// Rule: AwsS3PublicReadAcl | CWE-732 | Expected: TrueNegative

const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const client = new S3Client({ region: process.env.AWS_REGION });

async function uploadPrivateFile(bucket, key, body) {
  // SAFE: no ACL specified; bucket default (private) applies
  const command = new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: body,
    ServerSideEncryption: 'AES256',
  });
  return client.send(command);
}

uploadPrivateFile('my-private-bucket', 'reports/2024-q1.pdf', Buffer.from('report data'))
  .then(() => console.log('Uploaded privately'))
  .catch(console.error);
