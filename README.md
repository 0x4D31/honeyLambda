<img align="left" src="https://github.com/0x4D31/honeyLambda/blob/master/docs/honeyLambda-sm.png" width="250px">

Serverless trap

[![serverless](http://public.serverless.com/badges/v3.svg)](http://www.serverless.com)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

honeyλ - a simple serverless application designed to create and monitor URL [{honey}tokens](https://www.symantec.com/connect/articles/honeytokens-other-honeypot), on top of AWS Lambda and Amazon API Gateway
* Slack notifications
* Email and SMS alerts
* Load config from local file or Amazon S3
* Customize the HTTP response for each token
* Threat Intelligence report (Source IP lookup)
  * Using Cymon API v2
* Based on Serverless framework
  * pay-what-you-use
  * provider agnostic

## Description
honeyλ allows you to create and monitor fake HTTP endpoints automatically. You can then place these URL honeytokens in e.g. your inbox, documents, browser history, or embed them as {hidden} links in your web pages (Note: [honeybits](https://github.com/0x4D31/honeybits) can be used for spreading breadcrumbs across your systems to lure the attackers toward your traps). Depending on how and where you implement honeytokens, you may detect human attackers, malicious insiders, content scrapers, or bad bots.

This application is based on [Serverless framework](https://serverless.com) and can be deployed in different cloud providers such as Amazon Web Services (AWS), Microsoft Azure, IBM OpenWhisk or Google Cloud (Only tested on AWS; the main function may need small changes to support other providers). If your cloud provider is AWS, it automatically creates HTTP endpoints using Amazon API Gateway and then starts monitoring the HTTP endpoints using honeyλ Lambda function.

## Setup
* Install Serverless framework:
  * ```npm install -g serverless```
* Install honeyλ:
  * ```serverless install --url https://github.com/0x4d31/honeyLambda```
* Edit `serverless.yml` and set HTTP endpoint path (default: /v1/get-pass)
* Edit `config.json` and fill in your Slack Webhook URL. Change the trap/token configs as you need
* You can customize the HTTP response for each token
  * For example you can return a 1x1px beacon image in response and embed the token in your decoy documents or email (tracking pixel!)

## Deploy
* Set up your [AWS Credentials](https://serverless.com/framework/docs/providers/aws/guide/credentials/)
* In order to deploy honeyλ, simply run:
  * ```serverless deploy```

Output:

```
Serverless: Packaging service...
Serverless: Creating Stack...
Serverless: Checking Stack create progress...
.....
Serverless: Stack create finished...
Serverless: Uploading CloudFormation file to S3...
Serverless: Uploading artifacts...
Serverless: Uploading service .zip file to S3 (116.22 KB)...
Serverless: Validating template...
Serverless: Updating Stack...
Serverless: Checking Stack update progress...
.................................
Serverless: Stack update finished...
Service Information
service: honeyLambda
stage: dev
region: ap-southeast-2
api keys:
  None
endpoints:
  GET - https://rz1bEXAMPLE.execute-api.ap-southeast-2.amazonaws.com/dev/v1/get-pass
functions:
  honeylambda: honeyLambda-dev-honeylambda
```

* __Note:__ If you want to return binary in HTTP response (e.g. Content-Type: image/png), you have to manually configure Binary Support using the Amazon API Gateway console (it's not yet possible to set binary media types automatically using serverless):

Open the Amazon API Gateway console, add the binary media type __\*/\*__, and save.

<img src="https://github.com/0x4D31/honeyLambda/blob/master/docs/aws-apigw-binarysupport.png" width="800">

Once done, you have to re-deploy the API to the dev stage

<img src="https://github.com/0x4D31/honeyLambda/blob/master/docs/aws-api-redeploy.png" width="450">

## Usage
Open the generated URL/endpoint in your browser to test if it works:

![honeyLambdaURL](https://github.com/0x4D31/honeyLambda/blob/master/docs/http-response.png)

## Slack Alert
![threatintel](https://github.com/0x4D31/honeyLambda/blob/master/docs/slack-alert_threatintel.png)

## TODO
- [x] Remote config: load config from Amazon S3
- [x] Beacon image / return image as HTTP response 
- [x] Customize the HTTP response for each token
- [x] Check the source IP address against Threat Intelligence feeds (e.g. Cymon API)
- [x] Email alert
- [x] SMS alert ([Twilio](https://twilio.com))
- [ ] HTTP Client Fingerprinting
