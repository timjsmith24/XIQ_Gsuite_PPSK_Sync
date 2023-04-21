#!/usr/bin/env python3
import os
import sys
from typing import Type
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import requests
from pprint import pprint as pp

####################################
# written by:   Tim Smith
# e-mail:       tismith@extremenetworks.com
# date:         19 April 2023
# version:      1.1.0
####################################

gs_domain = 'Domain Name'
gs_group_name = 'GSuite GROUP Name'


gs_base_url = 'https://admin.googleapis.com/admin/directory/v1'
gs_group_url = f"{gs_base_url}/groups"
gs_user_url = f"{gs_base_url}/users"
SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly'
]
gs_header = {"Accept": "application/json", "Content-Type": "application/json"}

def check_token():
    if os.path.exists('gsuite_token.json'):
        cred = Credentials.from_authorized_user_file('gsuite_token.json', SCOPES)
    else:
        log_msg = "gsuite_token.json was not found. Please run the 'gsuite_setup.py' script to authorize the gsuite API and receive an API token."
        raise TypeError(log_msg)
    if not cred.valid:
        if cred.expired and cred.refresh_token:
            try:
                cred.refresh(Request())
            except RefreshError as e:
                log_msg = f"Failed to refresh GSuite Token with - {e}"
                raise TypeError(log_msg)
        else:
            log_msg = "gsuite_token.json isn't valid. Please rerun the 'gsuite_setup.py script and test again."
            raise TypeError(log_msg)
    gs_header['Authorization'] = "Bearer " + cred.token

def getGSGroupID(gs_groupname):
    url = gs_group_url + '?domain=' + gs_domain + "&query=name='" + gs_groupname + "'"
    response = requests.get(url, headers=gs_header, verify=True)
    data = response.json()
    if 'groups' in data:
        found_group = False
        for group in data['groups']:
            if group['name'] == gs_groupname:
                return group['id']
        if found_group == False:
            logmsg = f"Group {gs_groupname} was not found in domain {gs_domain}"
            raise TypeError(logmsg)
    else:
        logmsg = f"No group was found in domain {gs_domain}"
        raise TypeError(logmsg)

def retrieveGSUsers(gs_groupname):
    try:
        group_id = getGSGroupID(gs_groupname)
    except TypeError as e:
        raise TypeError(e)
    except:
        raise TypeError(f"Unknown issue collecting the group ID for {gs_groupname}")

    gsUsers = []
    gs_member_url = gs_group_url + "/" + str(group_id) + "/members?includeDerivedMembership=true"
    checkForUsers = True
    pageToken = ''
    while checkForUsers:
        if pageToken:
            url = gs_member_url + "&pageToken=" + pageToken
        else:
            url = gs_member_url
        response = requests.get(url, headers=gs_header, verify=True)
        if response == None:
            log_msg = ("Error retrieving Gsuite users - no response!")
            raise TypeError(log_msg)
        elif response.status_code != 200:
            log_msg = (f"Error retrieving Gsuite users - HTTP Status Code: {str(response.status_code)}")
            raise TypeError(log_msg)
        rawData = response.json()
        if 'nextPageToken' in rawData:
            pageToken = rawData['nextPageToken']
        else:
            checkForUsers = False
        if 'members' in rawData:
            gsUsers = gsUsers + rawData['members']
    for user in gsUsers:
        if user['type'] == 'USER':
            user['name'] = updateUserInfo(user)
        else:
            log_msg = f"{user['email']} is type {user['type']} and not a user. Skipping group member."
            print(log_msg)

    gsUsers[:] = [x for x in gsUsers if x['type'] == 'USER']

    return gsUsers

def updateUserInfo(user):
    url = gs_user_url + "/" + str(user['id'])
    response = requests.get(url, headers=gs_header, verify=True)
    data = response.json()
    return data['name']['fullName']

def main():
    gs_users = {}
    
    #Check Gsuite Token
    try:
        check_token()
    except TypeError as e:
        print(e)
        print("script exiting....")
        raise SystemExit
    
    #Collect Gsuite Users
    try:
        gs_results = retrieveGSUsers(gs_group_name)
    except TypeError as e:
        print(e)
        print("script exiting....")
        raise SystemExit
    except:
        log_msg = ("Unknown Error: Failed to retrieve users from Gsuite")
        print(log_msg)
        print("script exiting....")
        raise SystemExit
    for gs_entry in gs_results:
        if gs_entry['name'] not in gs_users:
            try:
                gs_users[gs_entry['name']] = {
                    "accountEnabled": True if (gs_entry['status']=='ACTIVE') else False,
                    "email": gs_entry['email'],
                    "username": gs_entry['email']
                }
            except:
                log_msg = (f"Unexpected error: {sys.exc_info()[0]}")
                print(log_msg)
                ldap_capture_success = False
                continue
    for name, details in gs_users.items():
        print(name, details)
    
if __name__ == '__main__':
    main()