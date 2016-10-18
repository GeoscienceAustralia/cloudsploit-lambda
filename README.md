Cloudsploit Lambda
=================

## Outline
Cloudsploit Lambda provides an automated way to view security risks in your AWS account. It will create Lambda functions to scan your account (using Cloudsploit Scans) and generate a static website with the output.

## Getting Started
1. Set your AWS credentials in ~/.aws/credentials or in the environment variables $AWS_ACCESS_KEY_ID and $AWS_SECRET_KEY_ID.
2. Add your IP address range to generate_cloudsploit.py.
3. Run `python3 generate_cloudsploit.py`. This will create the S3 bucket, download the Lambda function code zips, and upload them to the newly-created bucket. It will also generate a Cloudformation template.
4. Run `cloudsploit-cf/stack-create.sh`. This will create a Cloudformation stack that creates the Lambda functions and schedule.
