# SAFE: aws-s3-public-read-acl — S3 object uploaded without public-read ACL
# Rule: AwsS3PublicReadAcl | CWE-732 | Expected: TrueNegative

import boto3

s3 = boto3.client('s3')


def upload_private_file(bucket: str, key: str, data: bytes) -> None:
    """Upload a file to S3 with private access (no public ACL)."""
    # SAFE: no ACL parameter; bucket default (private) applies
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ServerSideEncryption='AES256',
    )


if __name__ == '__main__':
    upload_private_file('my-private-bucket', 'reports/2024-q1.pdf', b'report data')
    print('Uploaded with private access')
