#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import time
import urllib2
import logging
import boto3
import os
import base64

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

    # Prepare and send HTTP response
    response = generate_http_response(event, config)
    logger.info("HTTP response sent")

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


def generate_http_response(e, conf):
    req_path = e['resource']
    if e['queryStringParameters']:
        q, p = e['queryStringParameters'].items()[0]
        req_token = "{}={}".format(q, p)
    else:
        req_token = ""
    con_type = conf['default-http-response']['content-type']
    body_path = conf['default-http-response']['body']

    # Check if the token exists and has a custom http-response
    if req_token in conf['traps'][req_path]:
        if 'http-response' in conf['traps'][req_path][req_token]:
            con_type = (conf['traps'][req_path][req_token]
                        ['http-response']['content-type'])
            body_path = (conf['traps'][req_path][req_token]
                         ['http-response']['body'])

    with open(body_path) as body_file:
        data = body_file.read()

    if "image/" in con_type:
        res = {
            "statusCode": 200,
            "headers": {
                "Content-Type": con_type
            },
            "body": base64.b64encode(data),
            "isBase64Encoded": True
        }
    elif "text/" in con_type:
        res = {
            "statusCode": 200,
            "headers": {
                "Content-Type": con_type
            },
            "body": data,
        }
    else:
        logger.error("{} Content-Type is not supported".format(con_type))
        res = {
            "statusCode": 200,
            "body": ":-(",
        }

    return res


def alert_msg(e, conf):
    # message fields
    path = e['resource']
    full_path = e['requestContext']['path']
    host = e['headers']['Host']
    body = e['body']
    http_method = e['httpMethod']
    source_ip = e['requestContext']['identity']['sourceIp']
    user_agent = e['headers']['User-Agent']
    viewer_country = e['headers']['CloudFront-Viewer-Country']
    device_dict = {
        "Tablet": e['headers']['CloudFront-Is-Tablet-Viewer'],
        "Mobile": e['headers']['CloudFront-Is-Mobile-Viewer'],
        "Desktop": e['headers']['CloudFront-Is-Desktop-Viewer'],
        "SmartTV": e['headers']['CloudFront-Is-SmartTV-Viewer']
    }
    viewer_device = [dev for dev in device_dict if device_dict[dev] == "true"]
    if e['queryStringParameters']:
        q, p = e['queryStringParameters'].items()[0]
        req_token = "{}={}".format(q, p)
    else:
        req_token = ""
    # Search the config for the token note
    note = ""
    if req_token in conf['traps'][path]:
        if 'note' in conf['traps'][path][req_token]:
            note = conf['traps'][path][req_token]['note']

    # message dictionary
    msg = {
        "token-note": note,
        "path": full_path,
        "host": host,
        "http-method": http_method,
        "token": req_token,
        "body": body,
        "source-ip": source_ip,
        "user-agent": user_agent,
        "viewer-country": viewer_country,
        "viewer-device": viewer_device[0]
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
                        "value": msg['token'] if msg['token'] else "None",
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
                        "title": "Path",
                        "value": msg['path'],
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
