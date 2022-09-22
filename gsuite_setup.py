#!/usr/bin/env python3
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request



####################################
# written by:   Tim Smith
# e-mail:       tismith@extremenetworks.com
# date:         12 September 2022
# version:      1.0.0
####################################




CLIENT_SECRET_FILE = 'client_secret.json'
API_SERVICE_NAME = 'admin'
API_VERSION = 'v1'
SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly'
]


cred = None

if os.path.exists('gsuite_token.json'):
    cred = Credentials.from_authorized_user_file('gsuite_token.json', SCOPES)

if not cred or not cred.valid:
    if cred and cred.expired and cred.refresh_token:
        cred.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
        cred = flow.run_local_server()

    with open('gsuite_token.json', 'w') as token:
        token.write(cred.to_json())


try:
    service = build(API_SERVICE_NAME, API_VERSION, credentials=cred)
    print('Service created successfully')
    print(service)

    
except Exception as e:
    print(e)



