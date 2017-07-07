#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import time
import urllib2
import logging
import boto3
import os

__author__ = 'Adel "0x4d31" Ka'
__version__ = '0.1'

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def honeylambda(event, context):
    # Load config file
    config = load_config()

    # Preparing alert message
    alertMessage = alert_msg(event, config)
    # Slack alert
    if config['alert']['type'] == "slack":
        webhookURL = config['alert']['webhookurl']
        slack_alerter(alertMessage, webhookURL)

    # Preparing HTTP response
    contentType, body = generate_http_response(config)
    # Send HTTP response
    response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": contentType
        },
        "body": body
    }

    return response


def load_config():
    # Check the environment variable for config type (local/s3)
    CONFIGFILE = os.environ['configFile']
    # Load config from S3
    if CONFIGFILE == "s3":
        BUCKET = os.environ['s3Bucket']
        KEY = os.environ['s3Key']
        s3 = boto3.client('s3')
        try:
            response = s3.get_object(Bucket=BUCKET, Key=KEY)
            data = response['Body'].read()
            conf = json.loads(data)
            logger.info("Config file loaded from S3")
        except Exception as err:
            logger.error(err)
            raise
    else:
        # Load config from local file
        with open('config.json') as config_file:
            conf = json.load(config_file)
            logger.info("Local config file loaded")

    return conf


def generate_http_response(conf):
    # TODO: needs some changes to support image as response
    ctype = conf['http-response']['content-type']
    bpath = conf['http-response']['body']
    with open(bpath) as bfile:
        data = bfile.read()

    return ctype, data


def alert_msg(e, conf):
    # message fields
    trap = e['resource']
    fullPath = e['requestContext']['path']
    host = e['headers']['Host']
    querystringDict = e['queryStringParameters']
    body = e['body']
    httpMethod = e['httpMethod']
    sourceIp = e['requestContext']['identity']['sourceIp']
    userAgent = e['headers']['User-Agent']
    viewerCountry = e['headers']['CloudFront-Viewer-Country']
    deviceDict = {
        "Tablet": e['headers']['CloudFront-Is-Tablet-Viewer'],
        "Mobile": e['headers']['CloudFront-Is-Mobile-Viewer'],
        "Desktop": e['headers']['CloudFront-Is-Desktop-Viewer'],
        "SmartTV": e['headers']['CloudFront-Is-SmartTV-Viewer']
    }
    viewerDevice = [dev for dev in deviceDict if deviceDict[dev] == "true"]
    # Search the config for the token note
    note = ""
    querystring = ""
    if querystringDict:
        # TODO: clean the following code!!!
        for path in conf['traps']:
            if path in trap:
                for token in conf['traps'][path]:
                    qs = conf['traps'][path][token]['qstring']
                    param = conf['traps'][path][token]['param']
                    if qs in querystringDict and param == querystringDict[qs]:
                        note = conf['traps'][path][token]['note']
                        querystring = "{}={}".format(qs, param)
                    else:
                        qs2 = (querystringDict.keys())[0]
                        param2 = (querystringDict.values())[0]
                        querystring = "{}={}".format(qs2, param2)
    # message dictionary
    msg = {
        "token-note": note,
        "token-path": fullPath,
        "host": host,
        "http-method": httpMethod,
        "querystring": querystring,
        "body": body,
        "source-ip": sourceIp,
        "user-agent": userAgent,
        "viewer-country": viewerCountry,
        "viewer-device": viewerDevice[0]
    }

    return msg


def slack_alerter(msg, hookurl):
    now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())
    # Preparing Slack message
    slack_message = {
        "text": "*Honeytoken triggered!*\nA honeytoken has been triggered by {}".format(msg['source-ip']),
        "username": "honeyλ",
        "icon_emoji": ":ghost:",
        "attachments": [
            {
                "color": "danger",
                # "title": "Alert details",
                "text": "Alert details:",
                "footer": "honeyλ",
                "footer_icon": "https://avatars2.githubusercontent.com/u/18599493",
                "fields": [
                    {
                        "title": "Time",
                        "value": now,
                        "short": "true"
                    },
                    {
                        "title": "Source IP Address",
                        "value": msg['source-ip'],
                        "short": "true"
                    },
                    {
                        "title": "User-Agent",
                        "value": msg['user-agent']
                    },
                    {
                        "title": "Token Note",
                        "value": msg['token-note'] if msg['token-note'] else "None",
                        "short": "true"
                    },
                    {
                        "title": "Token",
                        "value": msg['token-path'],
                        "short": "true"
                    },
                    {
                        "title": "Viewer Country & Device Type",
                        "value": "{}, {}".format(msg['viewer-country'], msg['viewer-device']),
                        "short": "true"
                    },
                    {
                        "title": "HTTP Method",
                        "value": msg['http-method'],
                        "short": "true"
                    },
                    {
                        "title": "QueryString",
                        "value": msg['querystring'] if msg['querystring'] else "None",
                        "short": "true"
                    },
                    {
                        "title": "Body",
                        "value": msg['body'] if msg['body'] else "None",
                        "short": "true"
                    },
                    {
                        "title": "Host",
                        "value": msg['host']
                    }
                ]
            }
        ]
    }

    # Sending Slack message
    req = urllib2.Request(hookurl, json.dumps(slack_message))

    try:
        resp = urllib2.urlopen(req)
        resp.read()
        logger.info("Message posted to Slack")
    except urllib2.HTTPError as err:
        logger.error("Request failed: {} {}".format(err.code, err.reason))
    except urllib2.URLError as err:
        logger.error("Connection failed: {}".format(err.reason))

    return
