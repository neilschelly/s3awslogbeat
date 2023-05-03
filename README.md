# S3 AWS Log Beat

Current status: **beta release**

## Overview

This is a beat for the AWS services that can export logs to S3, like [Amazon Web Services (AWS) CloudTrail](https://aws.amazon.com/cloudtrail/) service.  S3AWSLogBeat relies on a combination of SNS, SQS and S3 to create a processing 'pipeline' to process new log events quickly and efficiently.  The beat polls the SQS queue for notification of when a new log file is available for download in S3.  Each log file is then downloaded, processed and sent to the configured receiver (logstash, elasticsearch, etc).  You are then able to query the data using Kibana (or any other tool) to analyse events involving API calls and IAM authentications.

## Getting Started
### Requirements

* [Golang](https://golang.org/dl/) 1.18

### Building

These steps assume you already have a working [Go environment](https://golang.org/doc/install).

```bash
git clone https://github.com/neilschelly/s3awslogbeat.git
cd s3awslogbeat
docker build . -t s3awslogbeat:latest
```

### AWS Configuration
#### Pipeline configuration for CloudTrail

Confguring CloudTrail is relatively straight forward and can be done quite easily through the AWS web console.  The [official documentation](http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html) outlines the steps required to configure everything, just ensure you complete the optional step 3.

If you would prefer to use CloudFormation to configure your environment, you can use the [provided template](conf/cloudtrail_cf.template) which will configure all of the neccessary services (CloudTrail, S3, SQS).   

Once configured, you can confirm everything is working by inspecting the configured S3 bucket as well as the SQS queue.

#### Access control configuration

S3AWSLogBeat supports usage of both IAM roles and API keys, but as per AWS best practices, if S3AWSLogBeat is being run from an EC2 you should be using IAM roles.  The following IAM Policy provides the minimal access required to process new S3AWSLogBeat events and initiate backfilling.  Make sure you replace the S3 and SQS ARN's with the values appropriate to your configuration.

```JSON
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowS3BucketAccess",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::<bucket name here>"
            ]
        },
        {
            "Sid": "AllowObjectRetrieval",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::<bucket name here>/*"
            ]
        },
        {
            "Sid": "AllowSQS",
            "Effect": "Allow",
            "Action": [
                "sqs:DeleteMessage",
                "sqs:ReceiveMessage",
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:aws:sqs:<sqs arn here>"
            ]
        }
    ]
}
```

### Running S3AWSLogBeat

1. Build S3AWSLogBeat using the steps list above
2. Modify the included *s3awslogbeat.yml* file as required
  1. Change the *sqs_url* field under the *input* section with the appropriate SQS url
  2. Configure the *output* section to send the events to your logstash/elasticsearch instance.  More information on Beat output configuration can be found in the [official documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-configuration-details.html). 
3. If you are not using IAM Roles to grant access to the SQS and S3 buckets, you will also need to configure *~/.aws/credentials* with the an appropriate key and secret.  The [AWS docs](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files) give a thorough explanation on setting up the required credentials files. 
4. Run S3AWSLogBeat in debug mode: `s3awslogbeat -c /path/to/s3awslogbeat.yml -d "*"`

You should now see a bunch of events scrolling through your terminal and in your output source.

If you are happy with the output, you will need to edit the configuration file to set `no_purge` to `false` (or delete the line).

#### Backfilling

If you would like to backfill events that have been cleared from the SQS or expired, you can run S3AWSLogBeat with the `-b` flag the name of the bucket that contains the AWS logs.  Example:

`s3awslogbeat -c /path/to/s3awslogbeat.yml -d "*" -b example-bucket`

If you would like to backfill only a subset of a bucket, you can also include the flag `-p` with the desired bucket prefix.  Example: 

`s3awslogbeat -c /path/to/s3awslogbeat.yml -d "*" -b example-bucket -f AWSLogs/xxxxx/CloudTrail/ap-northeast-1/2016/05`

## Thanks

This beat is based originally on a fork of [taxibeat/CloudTrailBeat](https://github.com/taxibeat/cloudtrailbeat). That beat is heavily inspired by [AppliedTrust/traildash](https://github.com/AppliedTrust/traildash) with some updates and additional functionality.

## Todo

- Configurable "type" of retrieved logs (CloudTrail, VPC Flow Logs, GuardDuty, etc)
