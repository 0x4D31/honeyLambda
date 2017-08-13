#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017  Adel "0x4D31" Karimi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import time
import urllib2
import urllib
import logging
import boto3
import os
import base64
import smtplib

__author__ = 'Adel "0x4d31" Ka'
__version__ = '0.1'

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def honeylambda(event, context):
    """ Main function """

    # Load config file
    config = load_config()

    # Preparing alert message
    alertMessage = alert_msg(event, config)

    # Slack alert
    if config['alert']['slack']['enabled'] == "true":
        WEBHOOK_URL = config['alert']['slack']['webhook-url']
        slack_alerter(alertMessage, WEBHOOK_URL)
    # Email alert
    if config['alert']['email']['enabled'] == "true":
        email_alerter(alertMessage, config)
    # SMS alert
    if config['alert']['sms']['enabled'] == "true":
        sms_alerter(alertMessage, config)

    # Prepare and send HTTP response
    response = generate_http_response(event, config)
    logger.info("HTTP response sent")

    return response


def load_config():
    """ Load the configuration from local file or Amazon S3 """

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


def threat_intel_lookup(ip, cred):
    """ Threat Intel lookup (source IP address) using Cymon v2 API """

    CYMON_LOGIN_API = "https://api.cymon.io/v2/auth/login"
    CYMON_SEARCHIP_API = "https://api.cymon.io/v2/ioc/search/ip/"
    CYMON_URL = "https://app.cymon.io/search/ip/"
    resp_dict = {}
    # Anonymous IP lookup request (rate-limited)
    lookup_req = urllib2.Request(
        CYMON_SEARCHIP_API + ip,
        headers={'Content-Type': 'application/json'}
    )
    # Authenticate if Cymon credential is provided
    if cred:
        auth_req = urllib2.Request(
            CYMON_LOGIN_API,
            data=json.dumps(cred),
            headers={'Content-Type': 'application/json'}
        )
        try:
            auth_resp = (urllib2.urlopen(auth_req)).read()
            auth_token = (json.loads(auth_resp))['jwt']
            lookup_req.add_header("Authorization", "Bearer {}".format(auth_token))
            logger.info("Cymon JWT token received")
        except urllib2.HTTPError as err:
            logger.error("Cymon Auth request failed: {} {}".format(
                err.code,
                err.reason)
            )
        except urllib2.URLError as err:
            logger.error("Cymon Auth connection failed: {}".format(err.reason))

    # Send IP lookup request
    try:
        lookup_resp = (urllib2.urlopen(lookup_req)).read()
        resp_dict = json.loads(lookup_resp)
        logger.info("Cymon results received")
    except urllib2.HTTPError as err:
        logger.error("Cymon lookup request failed: {} {}".format(
            err.code,
            err.reason)
        )
    except urllib2.URLError as err:
        logger.error("Cymon lookup connection failed: {}".format(err.reason))

    # Prepare the result
    if resp_dict:
        if resp_dict['total'] != 0:
            resp = ["- {} (tags: {})".format(h['title'], ', '.join(h['tags']))
                    for h in resp_dict['hits']]
            resp.append("+ More info: {}{}".format(CYMON_URL, ip))
            return resp

    return None


def generate_http_response(e, conf):
    """ Generate HTTP response """

    req_path = e['resource']
    if e['queryStringParameters']:
        q, p = e['queryStringParameters'].items()[0]
        req_token = "{}={}".format(q, p)
    else:
        req_token = ""
    # Load the default HTTP response
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
    """ Prepare alert message dictionary """

    # Message fields
    path = e['resource']
    full_path = e['requestContext']['path']
    host = e['headers']['Host']
    body = e['body']
    http_method = e['httpMethod']
    source_ip = e['requestContext']['identity']['sourceIp']
    user_agent = e['headers']['User-Agent']
    if "CloudFront-Viewer-Country" in e['headers']:
        viewer_country = e['headers']['CloudFront-Viewer-Country']
    else:
        viewer_country = "None"
    device_dict = {
        "Tablet": e['headers']['CloudFront-Is-Tablet-Viewer'],
        "Mobile": e['headers']['CloudFront-Is-Mobile-Viewer'],
        "Desktop": e['headers']['CloudFront-Is-Desktop-Viewer'],
        "SmartTV": e['headers']['CloudFront-Is-SmartTV-Viewer']
    }
    viewer_device = [dev for dev in device_dict if device_dict[dev] == "true"]
    viewer_details = "Country: {}, Device: {}".format(
        viewer_country,
        viewer_device[0])
    if e['queryStringParameters']:
        q, p = e['queryStringParameters'].items()[0]
        req_token = "{}={}".format(q, p)
    else:
        req_token = "None"

    # Search the config for the token note
    note = "None"
    if req_token in conf['traps'][path]:
        if 'note' in conf['traps'][path][req_token]:
            note = conf['traps'][path][req_token]['note']

    # Threat Intel Lookup (Cymon v2)
    threat_intel = "None"
    if conf['threat-intel-lookup']['enabled'] == "true":
        username = conf['threat-intel-lookup']['cymon2-user']
        password = conf['threat-intel-lookup']['cymon2-pass']
        if username and password:
            credential = {
                "username": username,
                "password": password
            }
        else:
            credential = None
        lookup_result = threat_intel_lookup(source_ip, credential)
        if lookup_result:
            threat_intel = "\n".join(lookup_result)

    # Message dictionary
    msg = {
        "token-note": note,
        "path": full_path,
        "host": host,
        "http-method": http_method,
        "token": req_token,
        "body": body,
        "source-ip": source_ip,
        "user-agent": user_agent,
        "viewer-details": viewer_details,
        "threat-intel": threat_intel
    }

    return msg


def email_alerter(msg, conf):
    """ Send Email alert """

    smtp_server = conf['alert']['email']['smtp_server']
    smtp_port = conf['alert']['email']['smtp_port']
    smtp_user = conf['alert']['email']['smtp_user']
    smtp_password = conf['alert']['email']['smtp_password']
    to_email = conf['alert']['email']['to_email']
    subject = 'honeyLambda Alert'
    now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())
    body = ("Honeytoken triggered!\n\n"
            "Time: {}\n"
            "Source IP: {}\n"
            "Threat Intel Report: {}\n"
            "User-Agent: {}\n"
            "Viewer Details: {}\n"
            "Token Note: {}\n"
            "Token: {}\n"
            "Path: {}\n"
            "Host: {}").format(
        now,
        msg['source-ip'],
        msg['threat-intel'] if msg['threat-intel'] else "None",
        msg['user-agent'],
        msg['viewer-details'],
        msg['token-note'],
        msg['token'],
        msg['path'],
        msg['host'])
    email_text = "From: {}\nTo: {}\nSubject: {}\n\n{}".format(
        smtp_user,
        ", ".join(to_email),
        subject,
        body)

    try:
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        server.ehlo()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, to_email, email_text)
        server.close()
        logger.info("Email Sent")
    except smtplib.SMTPException as err:
        logger.error("Error sending email: {}".format(err))


def sms_alerter(msg, conf):
    """ Send SMS alert """

    TWILIO_SMS_URL = "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json"
    to_number = conf['alert']['sms']['to_number']
    from_number = conf['alert']['sms']['from_number']
    twilio_account_sid = conf['alert']['sms']['twilio_account_sid']
    twilio_auth_token = conf['alert']['sms']['twilio_auth_token']

    body = (u"Honeytoken triggered by {}! \U0001F631\n"
            "'{}'\n"
            "Token Note: '{}'").format(
        msg['source-ip'],
        msg['viewer-details'],
        msg['token-note']
    )

    populated_url = TWILIO_SMS_URL.format(twilio_account_sid)
    post_params = {"To": to_number, "From": from_number, "Body": body}
    data = urllib.urlencode(post_params)
    req = urllib2.Request(populated_url)

    authentication = "{}:{}".format(twilio_account_sid, twilio_auth_token)
    base64string = base64.b64encode(authentication.encode('utf-8'))
    req.add_header("Authorization", "Basic %s" % base64string.decode('ascii'))

    try:
        urllib2.urlopen(req, data)
        logger.info("SMS Sent")
    except Exception as err:
        logger.error("Error sending SMS: {}".format(err))

    return


def slack_alerter(msg, webhook_url):
    """ Send Slack alert """

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
                "footer_icon": "https://raw.githubusercontent.com/0x4D31/honeyLambda/master/docs/slack-footer.png",
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
                        "title": "Threat Intel Report",
                        "value": msg['threat-intel'] if msg['threat-intel'] else "None",
                    },
                    {
                        "title": "User-Agent",
                        "value": msg['user-agent']
                    },
                    {
                        "title": "Token Note",
                        "value": msg['token-note'],
                        "short": "true"
                    },
                    {
                        "title": "Token",
                        "value": msg['token'],
                        "short": "true"
                    },
                    {
                        "title": "Viewer Details",
                        "value": msg['viewer-details'],
                        "short": "true"
                    },
                    {
                        "title": "Path",
                        "value": msg['path'],
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
    req = urllib2.Request(webhook_url, json.dumps(slack_message))

    try:
        resp = urllib2.urlopen(req)
        logger.info("Message posted to Slack")
    except urllib2.HTTPError as err:
        logger.error("Request failed: {} {}".format(err.code, err.reason))
    except urllib2.URLError as err:
        logger.error("Connection failed: {}".format(err.reason))

    return
