# SAFE: aws-hardcoded-access-key — credentials loaded from environment or IAM role
# Rule: AwsHardcodedAccessKey | CWE-798 | Expected: TrueNegative

import boto3

# SAFE: no credentials passed explicitly; boto3 uses environment variables,
# ~/.aws/credentials, or the EC2/ECS instance profile automatically
s3 = boto3.client('s3')

def list_buckets():
    response = s3.list_buckets()
    return [b['Name'] for b in response.get('Buckets', [])]

if __name__ == '__main__':
    print(list_buckets())
