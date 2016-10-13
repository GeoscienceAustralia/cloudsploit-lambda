#!/usr/bin/env python3

from troposphere import Template, GetAtt
from troposphere.s3 import Bucket, BucketPolicy, WebsiteConfiguration
from troposphere.awslambda import Function, Code, Permission
from troposphere.events import Rule, Target
from troposphere.iam import Role, Policy
from awacs.aws import Allow, Statement, Principal
from awacs.aws import Policy as AWACSPolicy
from awacs.sts import AssumeRole
import boto3
import urllib.request
import shutil
import botocore
import logging

def download_file(url, filename):
    print('Downloading from {0}...'.format(url))
    with urllib.request.urlopen(url) as response, open(filename, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)

def upload_to_s3(bucketname, filename):
    print('Uploading {0} to S3 bucket {1}...'.format(filename, bucketname))
    s3 = boto3.resource('s3')
    s3.Object(bucketname, filename).put(Body=open(filename, 'rb'))

def create_bucket(bucketname):

    s3 = boto3.resource('s3')
    s3client = boto3.client('s3')

    print('Creating bucket {0}...'.format(bucketname))

    try:
        s3.create_bucket(Bucket=bucketname, CreateBucketConfiguration={
            'LocationConstraint' : 'ap-southeast-2'
        })
    except botocore.exceptions.ClientError as e:
        logging.warning('An error occurred when creating bucket {0}: {1}'.format(bucketname, e))
    bucket = s3.Bucket(bucketname)
    try:
        bucket.Acl().put(ACL='public-read')
    except botocore.exceptions.ClientError as e:
        logging.warning('Unable to set ACL on bucket: {0}'.format(e))
    try:
        s3client.put_bucket_website(
            Bucket=bucketname,
            WebsiteConfiguration={
                'IndexDocument': {
                    'Suffix': 'index.html'
                },
                'ErrorDocument': {
                    'Key': 'index.html'
                }
            }
        )
    except botocore.exceptions.ClientError as e:
        logging.warning('Unable to set website on bucket: {0}'.format(e))

def create_lambda(title, bucketname, filename, handlername, role_arn, environment):
    print('Adding lambda {0} to template...'.format(title))
    trop_lambda = Function(
                  title,
                  Code=Code(S3Bucket=bucketname, S3Key=filename),
                  Description='Cloudsploit',
                  FunctionName=title,
                  Handler=handlername,
                  MemorySize=128,
                  Role=role_arn,
                  Runtime=environment,
                  Timeout=300)

    return trop_lambda

def create_lambda_schedule(template, awslambda, schedule):
    trop_cw_rule = template.add_resource(
        Rule(
            'CloudsploitRule',
            Name='CloudsploitReporter',
            ScheduleExpression=schedule,
            State='ENABLED',
            Targets=[Target(
                Arn=GetAtt(awslambda, 'Arn'),
                Id='CloudsploitRule'
            )]
        )
    )

    trop_cw_permission = template.add_resource(
        Permission(
            'CloudsploitRulePermission',
            Action='lambda:InvokeFunction',
            FunctionName=GetAtt(awslambda, 'Arn'),
            Principal='events.amazonaws.com',
            SourceArn=GetAtt(trop_cw_rule, 'Arn')
        )
    )

reporter_role = Role(
    'CloudsploitReporterRole',
    AssumeRolePolicyDocument=AWACSPolicy(
        Statement=[
            Statement(
                Effect=Allow,
                Action=[AssumeRole],
                Principal=Principal("Service", ["lambda.amazonaws.com"])
            )
        ]
    ),
    Policies=[Policy(
        PolicyName='CloudsploitReporterS3FullAccess',
        PolicyDocument=
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "*"
                    }
                ]
            }
        ),
    Policy(
        PolicyName='CloudsploitLambdaInvoke',
        PolicyDocument=
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Resource": [
                            "*"
                        ],
                        "Action": [
                            "lambda:InvokeFunction",
                            "iam:ListAccountAliases"
                        ]
                    }
                ]
            }
        )
    ],
    RoleName='CloudsploitReporterRole'
)

scanner_role = Role(
    'CloudsploitScannerRole',
    AssumeRolePolicyDocument=AWACSPolicy(
        Statement=[
            Statement(
                Effect=Allow,
                Action=[AssumeRole],
                Principal=Principal("Service", ["lambda.amazonaws.com"])
            )
        ]
    ),
    Policies=[Policy(
        PolicyName='CloudsploitScannerS3FullAccess',
        PolicyDocument=
            {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": "s3:*",
                  "Resource": "*"
                }
              ]
            }
        ),
        Policy(
            PolicyName='CloudsploitAWSFullReadAccess',
            PolicyDocument=
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "cloudformation:getStackPolicy",
                            "cloudwatchlogs:describeLogGroups",
                            "cloudwatchlogs:describeMetricFilters",
                            "autoscaling:Describe*",
                            "cloudformation:DescribeStack*",
                            "cloudformation:GetTemplate",
                            "cloudformation:ListStack*",
                            "cloudfront:Get*",
                            "cloudfront:List*",
                            "cloudtrail:DescribeTrails",
                            "cloudtrail:GetTrailStatus",
                            "cloudtrail:ListTags",
                            "cloudwatch:Describe*",
                            "codecommit:BatchGetRepositories",
                            "codecommit:GetBranch",
                            "codecommit:GetObjectIdentifier",
                            "codecommit:GetRepository",
                            "codecommit:List*",
                            "codedeploy:Batch*",
                            "codedeploy:Get*",
                            "codedeploy:List*",
                            "config:Deliver*",
                            "config:Describe*",
                            "config:Get*",
                            "datapipeline:DescribeObjects",
                            "datapipeline:DescribePipelines",
                            "datapipeline:EvaluateExpression",
                            "datapipeline:GetPipelineDefinition",
                            "datapipeline:ListPipelines",
                            "datapipeline:QueryObjects",
                            "datapipeline:ValidatePipelineDefinition",
                            "directconnect:Describe*",
                            "dynamodb:ListTables",
                            "ec2:Describe*",
                            "ecs:Describe*",
                            "ecs:List*",
                            "elasticache:Describe*",
                            "elasticbeanstalk:Describe*",
                            "elasticloadbalancing:Describe*",
                            "elasticmapreduce:DescribeJobFlows",
                            "elasticmapreduce:ListClusters",
                            "firehose:Describe*",
                            "firehose:List*",
                            "glacier:ListVaults",
                            "iam:GenerateCredentialReport",
                            "iam:Get*",
                            "iam:List*",
                            "kms:Describe*",
                            "kms:Get*",
                            "kms:List*",
                            "lambda:GetPolicy",
                            "lambda:ListFunctions",
                            "rds:Describe*",
                            "rds:DownloadDBLogFilePortion",
                            "rds:ListTagsForResource",
                            "redshift:Describe*",
                            "route53:GetChange",
                            "route53:GetCheckerIpRanges",
                            "route53:GetGeoLocations",
                            "route53:GetHealthCheck",
                            "route53:GetHealthCheckCount",
                            "route53:GetHealthCheckLastFailureReason",
                            "route53:GetHostedZone",
                            "route53:GetHostedZoneCount",
                            "route53:GetReusableDelegationSet",
                            "route53:ListGeoLocations",
                            "route53:ListHealthChecks",
                            "route53:ListHostedZones",
                            "route53:ListHostedZonesByName",
                            "route53:ListResourceRecordSets",
                            "route53:ListReusableDelegationSets",
                            "route53:ListTagsForResource",
                            "route53:ListTagsForResources",
                            "route53domains:GetDomainDetail",
                            "route53domains:GetOperationDetail",
                            "route53domains:ListDomains",
                            "route53domains:ListOperations",
                            "route53domains:ListTagsForDomain",
                            "s3:GetBucket*",
                            "s3:GetLifecycleConfiguration",
                            "s3:GetObjectAcl",
                            "s3:GetObjectVersionAcl",
                            "s3:ListAllMyBuckets",
                            "sdb:DomainMetadata",
                            "sdb:ListDomains",
                            "ses:GetIdentityDkimAttributes",
                            "ses:ListIdentities",
                            "sns:GetTopicAttributes",
                            "sns:ListTopics",
                            "sqs:GetQueueAttributes",
                            "sqs:ListQueues",
                            "tag:GetResources",
                            "tag:GetTagKeys"
                        ],
                        "Effect": "Allow",
                        "Resource": "*"
                    }
                ]
            }
        ),
        Policy(
            PolicyName='CloudsploitLoggingAccess',
            PolicyDocument=
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:CreateLogGroup",
                        "Resource": "arn:aws:logs:ap-southeast-2:658691668407:*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": [
                            "arn:aws:logs:ap-southeast-2:658691668407:log-group:/aws/lambda/test:*"
                        ]
                    }
                ]
            }
        )
    ],
    RoleName='CloudsploitScannerRole'
)


def main():
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()['Account']
    bucketname = 'cloudsploitwww' + account_id

    template_file_path = 'cloudsploit-stack.json'
    template = Template()

    create_bucket(bucketname)

    download_file('https://s3-ap-southeast-2.amazonaws.com/cloudsploit/cloudsploit-report.zip', 'cloudsploit-report.zip')
    download_file('https://s3-ap-southeast-2.amazonaws.com/cloudsploit/cloudsploit-scans.zip', 'cloudsploit-scans.zip')

    upload_to_s3(bucketname, 'cloudsploit-report.zip')
    upload_to_s3(bucketname, 'cloudsploit-scans.zip')

    trop_scanner_role = template.add_resource(scanner_role)
    trop_reporter_role = template.add_resource(reporter_role)
    scanner_role_arn = GetAtt(trop_scanner_role, 'Arn')
    reporter_role_arn = GetAtt(trop_reporter_role, 'Arn')

    scanner_lambda = template.add_resource(create_lambda('cloudsploitscanner', bucketname,
                'cloudsploit-scans.zip', 'lambda.handler', scanner_role_arn, 'nodejs4.3'))
    reporter_lambda = template.add_resource(create_lambda('cloudsploitreporter', bucketname,
                'cloudsploit-report.zip', 'cloudsploit_report.handler', reporter_role_arn, 'python2.7'))
    create_lambda_schedule(template, reporter_lambda, 'rate(1 day)')

    # Write template to file
    template_data = template.to_json(indent=2, separators=(',', ': '))
    with open(template_file_path, 'w') as template_file:
        template_file.write(template_data)
        template_file.close()
        print("Template created: {0}".format(template_file_path))

if __name__ == '__main__':
    main()
