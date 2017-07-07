<img align="left" src="https://github.com/0x4D31/honeyLambda/blob/master/docs/honeyLambda-sm.png" width="240px">

Serverless trap

[![serverless](http://public.serverless.com/badges/v3.svg)](http://www.serverless.com)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)]()

honeyλ - a simple serverless application designed to create and monitor URL [{honey}tokens](https://www.symantec.com/connect/articles/honeytokens-other-honeypot), on top of AWS Lambda and Amazon API Gateway
* Slack notifications
* Load config from local file or Amazon S3
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
* Edit `serverless.yml` and set HTTP endpoint path (default: v1/get-pass)
* Edit `config.json` and fill in your Slack Webhook URL. Change the trap/token configs as you need
* You can change the template (or the main function if it's needed) and customize the HTTP response
  * For example you can send image in response and embed the token in decoy documents; Or you can inject BeEF hook.js into the page

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

## Usage
Open the generated URL/endpoint in your browser to test if it works:

![honeyLambdaURL](https://github.com/0x4D31/honeyLambda/blob/master/docs/http-response.png)

## Slack Alert
![honeyLambda](https://github.com/0x4D31/honeyLambda/blob/master/docs/slack-alert.png)

## TODO
- [ ] Load config from Amazon S3
- [ ] Insert BeEF hook.js into the response
- [ ] Check the source IP address against Threat Intelligence feeds (e.g. Cymon API)
- [ ] Ability to send a different HTTP response for each endpoint

