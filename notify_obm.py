#!/usr/bin/python3
# OBM-Notification
# Bulk: no


#
# OBM-notification plugin for checkmk
#
# written by H.Vogelsang, Aveniq AG, Switzerland
# first released June 2021
#
# This script is intended to send
# notifications from checkmk to Microfocus OBM.
#


import json
import urllib3
import requests
from os import environ
from pathlib import Path
from requests.auth import HTTPBasicAuth


# disable SSL-Warnings configured...
if config['enableSSLverification']:
    urllib3.disable_warnings()


# globals
global config


def buildMessage(eventData):
    template = '''
    <event xmlns="http://www.hp.com/2009/software/opr/data_model">
        <title>%%title</title>
        <description>%%description</description>
        <severity>%%severity</severity>
        <priority>%%priority</priority>
        <state>open</state>
        <object>Citrix</object>
        <application>ControlUP</application>
        <related_ci_hints type="urn:x-hp:2009:software:data_model:opr:type:related_ci_hints" version="1.0">
            <hint>@@%%host</hint>
        </related_ci_hints>
        </event>
    '''
    requestData = template.replace('%%title', eventData['title'])
    requestData = requestData.replace('%%description', eventData['description'])
    requestData = requestData.replace('%%severity', eventData['severity'])
    requestData = requestData.replace('%%priority', eventData['priority'])
    requestData = requestData.replace('%%host', eventData['host'])
    return requestData


def parseURL(_URL):
    # check if _URL ends with backslash and if so, remove it
    _URL = _URL if _URL[-1] != "/" else _URL[:-1]
    return _URL


def getEnvironment():
    _data = ''

    # check if checkmk set the environment vars
    if environ.get('NOTIFY_WHAT') is not None:
        # map priority
        if environ.get('NOTIFY_HOSTLABEL_SLA') is not None:
            _priority = {"Gold": "high",
                         "Silver": "medium",
                         "Bronze": "low"}
            _priority = _priority[environ.get('NOTIFY_HOSTLABEL_SLA')]
        else:
            _priority = "low"

        # build eventdata
        if environ.get('NOTIFY_WHAT') == "SERVICE":
            # map state severity for service
            _severity = ['normal', 'warning', 'critical', 'warning', 'warning']

            _data = {'title': environ.get('NOTIFY_SERVICEDESC'),
                     'description': environ.get('NOTIFY_SERVICEOUTPUT'),
                     'severity': _severity[int(environ.get('NOTIFY_SERVICESTATEID'))],
                     'priority': _priority,
                     'host': environ.get('NOTIFY_HOSTALIAS')}
        elif environ.get('NOTIFY_WHAT') == "HOST":
            # map state severity for host
            _severity = ['normal', 'critical', 'warning', 'warning']

            _titile = '{} is {}'.format(environ.get('NOTIFY_HOSTALIAS'), environ.get('NOTIFY_HOSTSTATE'))
            _description = '{} since {}'.format(environ.get('NOTIFY_HOSTSTATE'), environ.get('NOTIFY_LONGDATETIME'))
            _data = {'title': _titile,
                     'description': _description,
                     'severity': _severity[int(environ.get('NOTIFY_HOSTSTATEID'))],
                     'priority': _priority,
                     'host': environ.get('NOTIFY_HOSTALIAS')}

    else:
        print("no environment variables. exiting...")
        exit("ERROR#005_ENV_MISSING")
    return _data


def sendEvent(eventData):
    # start session to receive 'secureModifyToke' via cookie
    session = requests.Session()

    # receive 'secureModifyToke' via cookie
    session.get("{}/opr-console/rest/".format(parseURL(config['obmURL'])),
                auth=HTTPBasicAuth(config['obmUser'], config['obmPassword']),
                verify=config['enableSSLverification'])

    # send eventdata to OBM
    response = session.post("{}/opr-console/rest/9.10/event_list".format(parseURL(config['obmURL'])),
                            verify=config['enableSSLverification'],
                            data=eventData.encode('utf-8'),
                            auth=HTTPBasicAuth(config['obmUser'], config['obmPassword']),
                            headers={
                                'Content-Type': 'application/xml;charset=UTF-8',
                                'X-Secure-Modify-Token': session.cookies['secureModifyToken'].encode('utf-8'),
                                'cache-control': "no-cache",
                                'Accept': 'text/plain, text/xml, application/xml'
                            })

    # check if the responsecode is 202 (Accepted) or raise exit on all other responsecodes.
    if response.status_code == 202:
        if config['debug']:
            print(eventData)
        print("Event successfully sent to OBM")
    else:
        print("Event could not be sent to OBM.\nLast response:")
        print(response.text)
        if config['debug']:
            print(eventData)
        exit("ERROR#002_SENTFAULT")


if __name__ == '__main__':
    # determine my location
    scriptPath = Path(__file__).parent

    # check if configfile exists and parse it if so
    configFile = scriptPath.joinpath('config.json')
    if Path(configFile).exists():
        config = json.loads(open(configFile).read())
    else:
        print("config.json not found. exiting...")
        exit("ERROR#001_CONFIG_MISSING")

    # get environment variables
    data = getEnvironment()

    # check if given severity is fine
    if data['severity'] not in config['severityLevel']:
        print("'{}' seems to be not a correct severity.\nshould be one of these: {}\n"
              .format(data['severity'], config['severityLevel']))
        exit("ERROR#003_WRONG_SEVERITY")

    # check if given priority is fine
    if data['priority'] not in config['priorityLevel']:
        print("'{}' seems to be not a correct severity.\nshould be one of these: {}\n"
              .format(data['priority'], config['priorityLevel']))
        exit("ERROR#004_WRONG_PRIORITY")

    # send event with collected informations
    sendEvent(buildMessage(data))
