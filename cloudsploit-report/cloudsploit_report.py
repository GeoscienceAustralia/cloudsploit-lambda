#!/usr/bin/env python3

import json
import datetime
import boto3

categories = ['CloudFront', 'CloudTrail', 'ConfigService', 'EC2', 'IAM', 'KMS', 'RDS', 'Route53', 'S3', 'VPC']

plugins = ['publicS3Origin', 'cloudtrailBucketAccessLogging', 'cloudtrailBucketDelete', 'cloudtrailEnabled',
            'cloudtrailEncryption', 'cloudtrailFileValidation', 'cloudtrailToCloudwatch', 'cloudtrailBucketPrivate',
            'configServiceEnabled', 'elasticIpLimit', 'excessiveSecurityGroups', 'insecureCiphers', 'instanceLimit',
            'openCIFS', 'openDNS', 'openFTP', 'openMySQL', 'openNetBIOS', 'openPostgreSQL', 'openRDP', 'openRPC',
            'openSMBoTCP', 'openSMTP', 'openSQLServer', 'openSSH', 'openTelnet', 'openVNCClient', 'openVNCServer',
            'vpcElasticIpLimit', 'defaultSecurityGroup', 'accessKeysExtra', 'accessKeysLastUsed', 'accessKeysRotated',
            'certificateExpiry', 'emptyGroups', 'maxPasswordAge', 'minPasswordLength', 'noUserIamPolicies',
            'passwordExpiration', 'passwordRequiresLowercase', 'passwordRequiresNumbers', 'passwordRequiresSymbols',
            'passwordRequiresUppercase', 'passwordReusePrevention', 'rootAccessKeys', 'rootAccountInUse',
            'rootMfaEnabled', 'sshKeysRotated', 'usersMfaEnabled', 'kmsKeyRotation', 'rdsAutomatedBackups',
            'rdsEncryptionEnabled', 'rdsPubliclyAccessible', 'rdsRestorable', 'domainAutoRenew', 'domainExpiry',
            'domainTransferLock', 'bucketAllUsersPolicy', 'classicInstances', 'flowLogsEnabled']

sts = boto3.client("sts")
account_id = sts.get_caller_identity()["Account"]
wwwbucket = 'secgadevsga'


def retrieve_json():

  payload = {}
  payload['plugins'] = plugins
  json_payload = json.dumps(payload)

  client = boto3.client('lambda')
  resp = client.invoke(
      FunctionName='cloudsploit_scans',
      InvocationType='RequestResponse',
      Payload=json_payload
  )

  data = json.loads(resp['Payload'].read().decode('utf-8'))
  return data

def generate_html(filename, content):
    filename = account_id + '/' + filename + '.html'
    s3client = boto3.resource('s3')

    bucket = s3client.Bucket(wwwbucket)
    obj = bucket.put_object(Key=filename, Body=content, ContentType='text/html', ACL='public-read')

def add_header(title):
    time = datetime.datetime.now()
    content = '<!DOCTYPE html>\n'
    content += '<html>\n'
    content += '<head><link rel="stylesheet" ' \
               'href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" ' \
               'integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" ' \
               'crossorigin="anonymous">\n'
    content += '</head>\n'
    content += '<body>\n'
    content += '<div class="jumbotron text-center">\n'
    content += '<h2>{0}</h2>\n'.format(title)
    content += '<h3>{0}</h3>\n'.format(time)
    content += '</div>'

    return content

def generate_index(count):
    client = boto3.client('iam')
    response = client.list_account_aliases()
    try:
      response = client.list_account_aliases()
      account_alias = response['AccountAliases'][0]
    except Exception as e:
      print('No alias for this account, using account ID: ' + e.args[-1])
      account_alias = account_id

 
    content = add_header(account_alias)
    category_count = 0
    content += '<div class ="container"><div class="row"><div class="col-sm-6">'

    for category in categories:
        if count[category] == 0:
            content += '<li class="list-group-item list-group-item-success">'
        else:
            content += '<li class="list-group-item list-group-item-danger">'
        content += '<a href=' + category + '.html>'
        content += category
        content += '</a></li><br>\n'

        category_count += 1

        if category_count % 5 == 0:
            content += '</div><div class="col-sm-6">'

    content += '</div></div></div>'

    generate_html('index', content)

def handler(event, context):
    count = {}
    category_content = {}
    for category in categories:
      count[category] = 0
      category_content[category] = add_header(category)

    data = retrieve_json()

    for datapoint in data['data']:
      category = datapoint['category']
      datapoint_safe = True

      datapoint_name = datapoint['title'].replace(' ', '_')
      datapoint_content = add_header(datapoint['title'])
      datapoint_content += '<h4>' + datapoint['description'] + '</h4>\n'
      datapoint_content += '<p>More info: ' + datapoint['more_info'] + '</p>\n'
      datapoint_content += '<p>Recommended action: ' + datapoint['recommended_action'] + '</p>\n'
      datapoint_content += '<p><a href=' + datapoint['link'] + '>' + datapoint['link'] + '</a></p>\n'

      for result in datapoint['results']:
        if result['status'] == 0:
          datapoint_content += '<li class="list-group-item list-group-item-success">'
        else:
          datapoint_content += '<li class="list-group-item list-group-item-danger">'
          count[category] += 1
          datapoint_safe = False

        datapoint_content += result['region'] + '\n'
        datapoint_content += result['message'] + '\n'
        datapoint_content += '</li>'

      if datapoint_safe:
        category_content[category] += '<li class="list-group-item list-group-item-success">'
      else:
        category_content[category] += '<li class="list-group-item list-group-item-danger">'

      category_content[category] += '<a href=' + datapoint_name + '.html>'
      category_content[category] += datapoint['title']
      category_content[category] += '</a></li><br>\n'

      generate_html(datapoint_name, datapoint_content)

    for category in categories:
      generate_html(category, category_content[category])

    generate_index(count)



