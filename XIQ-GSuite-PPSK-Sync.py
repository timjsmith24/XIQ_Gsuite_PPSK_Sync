#!/usr/bin/env python3
import json
import requests
import sys
import os
import logging
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

####################################
# written by:   Tim Smith
# e-mail:       tismith@extremenetworks.com
# date:         12 September 2022
# version:      1.0.0
####################################


# Global Variables - ADD CORRECT VALUES
gs_domain = 'Domain Name'


#XIQ_username = "enter your ExtremeCloudIQ Username"
#XIQ_password = "enter your ExtremeCLoudIQ password"
####OR###
## TOKEN permission needs - enduser, pcg:key
XIQ_token = "****"

group_roles = [
    # GSuite GROUP Name, XIQ group ID
    ("GSuite GROUP Name", "XIQ group ID"),
    ("GSuite GROUP Name", "XIQ group ID")
]

PCG_Enable = False

PCG_Maping = {
    "XIQ User Group ID" : {
        "UserGroupName": "XIQ User Group Name",
        "policy_id": "Network Policy ID associated with PCG",
         "policy_name": "Network Policy name associated with PCG"
    }
}



#-------------------------
# logging
PATH = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(
    filename='{}/XIQ-GSuite-PPSK-sync.log'.format(PATH),
    filemode='a',
    level=os.environ.get("LOGLEVEL", "INFO"),
    format= '%(asctime)s: %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
)

xiq_base_url = "https://api.extremecloudiq.com"
xiq_headers = {"Accept": "application/json", "Content-Type": "application/json"}

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
        logging.error(log_msg)
        raise TypeError(log_msg)
    if not cred.valid:
        if cred.expired and cred.refresh_token:
            try:
                cred.refresh(Request())
            except RefreshError as e:
                log_msg = f"Failed to refresh GSuite Token with - {e}"
                logging.error(log_msg)
                raise TypeError(log_msg)
        else:
            log_msg = "gsuite_token.json isn't valid. Please rerun the 'gsuite_setup.py script and test again."
            logging.error(log_msg)
            raise TypeError(log_msg)
    gs_header['Authorization'] = "Bearer " + cred.token

def getGSGroupID(gs_groupname):
    url = gs_group_url + '?domain=' + gs_domain
    response = requests.get(url, headers=gs_header, verify=True)
    data = response.json()
    if 'error' in data:
        log_msg = data['error']['message']
        raise TypeError(log_msg)
    if 'groups' in data:
        found_group = False
        for group in data['groups']:
            if group['name'] == gs_groupname:
                return group['id']
        if found_group == False:
            logmsg = f"Group '{gs_groupname}' was not found in domain {gs_domain}"
            raise TypeError(logmsg)
    else:
        logmsg = f"No group was not found in domain {gs_domain}"
        raise TypeError(logmsg)

def retrieveGSUsers(gs_groupname):
    try:
        group_id = getGSGroupID(gs_groupname)
    except TypeError as e:
        logging.error(e)
        raise TypeError(e)
    except:
        logging.error(f"An Unknown issue occured when collection the Group ID for {gs_groupname}")
        raise TypeError(f"Unknown issue collecting the group ID for {gs_groupname}")

    gsUsers = []
    gs_member_url = gs_group_url + "/" + str(group_id) + "/members"
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
            logging.error(log_msg)
            raise TypeError(log_msg)
        elif response.status_code != 200:
            log_msg = (f"Error retrieving Gsuite users - HTTP Status Code: {str(response.status_code)}")
            logging.error(log_msg)
            logging.warning(f"{response.test}")
            raise TypeError(log_msg)
        rawData = response.json()
        if 'nextPageToken' in rawData:
            pageToken = rawData['nextPageToken']
        else:
            checkForUsers = False
        if 'members' in rawData:
            gsUsers = gsUsers + rawData['members']
    for user in gsUsers:
        user['name'] = updateUserInfo(user)

    return gsUsers

def updateUserInfo(user):
    url = gs_user_url + "/" + str(user['id'])
    response = requests.get(url, headers=gs_header, verify=True)
    data = response.json()
    return data['name']['fullName']



def getAccessToken(XIQ_username, XIQ_password):
    url = xiq_base_url + "/login"
    payload = json.dumps({"username": XIQ_username, "password": XIQ_password})
    response = requests.post(url, headers=xiq_headers, data=payload)
    if response is None:
        log_msg = "ERROR: Not able to login into ExtremeCloudIQ - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    if response.status_code != 200:
        log_msg = f"Error getting access token - HTTP Status Code: {str(response.status_code)}"
        logging.error(f"{log_msg}")
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)
    data = response.json()

    if "access_token" in data:
        #print("Logged in and Got access token: " + data["access_token"])
        xiq_headers["Authorization"] = "Bearer " + data["access_token"]
        return 0

    else:
        log_msg = "Unknown Error: Unable to gain access token"
        logging.warning(log_msg)
        raise TypeError(log_msg)


def createPPSKuser(name,mail, usergroupID):
    url = xiq_base_url + "/endusers"

    payload = json.dumps({"user_group_id": usergroupID ,"name": name,"user_name": name,"password": "", "email_address": mail, "email_password_delivery": mail})

    response = requests.post(url, headers=xiq_headers, data=payload, verify=True)
    if response is None:
        log_msg = "Error adding PPSK user - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)

    elif response.status_code != 200:
        log_msg = f"Error adding PPSK user {name} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)

    elif response.status_code ==200:
        logging.info(f"successfully created PPSK user {name}")
        print(f"successfully created PPSK user {name}")
        return True


def retrievePPSKUsers(pageSize, usergroupID):
    page = 1
    pageCount = 1
    firstCall = True

    ppskUsers = []

    while page <= pageCount:
        url = xiq_base_url + "/endusers?page=" + str(page) + "&limit=" + str(pageSize) + "&user_group_ids=" + usergroupID

        # Get the next page of the ppsk users
        response = requests.get(url, headers=xiq_headers, verify = True)
        if response is None:
            log_msg = "Error retrieving PPSK users from XIQ - no response!"
            logging.error(log_msg)
            raise TypeError(log_msg)

        elif response.status_code != 200:
            log_msg = f"Error retrieving PPSK users from XIQ - HTTP Status Code: {str(response.status_code)}"
            logging.error(log_msg)
            logging.warning(f"\t\t{response.json()}")
            raise TypeError(log_msg)

        rawList = response.json()
        ppskUsers = ppskUsers + rawList['data']

        if firstCall == True:
            pageCount = rawList['total_pages']
        print(f"completed page {page} of {rawList['total_pages']} collecting PPSK Users")
        page = rawList['page'] + 1 
    return ppskUsers


def deleteUser(userId):
    url = xiq_base_url + "/endusers/" + str(userId)
    response = requests.delete(url, headers=xiq_headers, verify=True)
    if response is None:
        log_msg = f"Error deleting PPSK user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Error deleting PPSK user {userId} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)
    elif response.status_code == 200:
        return 'Success', str(userId)
    

def addUserToPcg(policy_id, name, email, user_group_name):
    url = xiq_base_url + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    payload = json.dumps({
                  "users": [
                    {
                      "name": name,
                      "email": email,
                      "user_group_name": user_group_name
                    }
                  ]
                })
    response = requests.post(url, headers=xiq_headers, data=payload, verify=True)
    if response is None:
        log_msg = f"- no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 202:
        log_msg = f"HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)
    elif response.status_code == 202:
        return 'Success'


def retrievePCGUsers(policy_id):
    url = xiq_base_url + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    response = requests.get(url, headers=xiq_headers, verify = True)
    if response is None:
        log_msg = f"Error retrieving PCG users for policy id {policy_id} from XIQ - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Error retrieving PCG users for policy id {policy_id} from XIQ - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)
    rawList = response.json()
    return rawList


def deletePCGUsers(policy_id, userId):
    url = xiq_base_url + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    payload = json.dumps({
                    "user_ids": [
                                    userId
                                ]
                })
    response = requests.delete(url, headers=xiq_headers, data=payload, verify = True)
    if response is None:
        log_msg = f"Error deleting PPSK user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 202:
        log_msg = f"Error deleting PPSK user {userId} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)
    elif response.status_code == 202:
        return 'Success'



def main():
    if 'XIQ_token' not in globals():
        try:
            login = getAccessToken(XIQ_username, XIQ_password)
        except TypeError as e:
            print(e)
            raise SystemExit
        except:
            log_msg = "Unknown Error: Failed to generate token"
            logging.error(log_msg)
            print(log_msg)
            raise SystemExit     
    else:
        xiq_headers["Authorization"] = "Bearer " + XIQ_token
 
    ListOfGSgroups, ListOfXIQUserGroups = zip(*group_roles)

    # Collect PSK users
    ppsk_users = []
    for usergroupID in ListOfXIQUserGroups:
        try:
            ppsk_users += retrievePPSKUsers(100,usergroupID)
        except TypeError as e:
            print(e)
            print("script exiting....")
            # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
            raise SystemExit
        except:
            log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
            logging.error(log_msg)
            print(log_msg)
            print("script exiting....")
            # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
            raise SystemExit
    log_msg = ("Successfully parsed " + str(len(ppsk_users)) + " XIQ users")
    logging.info(log_msg)
    print(f"{log_msg}\n")

    # Validate and refresh GSuite token
    try:
        check_token()
    except TypeError as e:
        print(e)
        print("script exiting....")
        raise SystemExit
    except:
        log_msg = "Failed to Authenticate with GSuite - Unknown reason"
        logging.error(log_msg)
        print(log_msg)
        print("script is exiting....")
        raise SystemExit
    #Collect Gsuite Users
    gs_users = {}
    gs_capture_success = True
    for gs_group_name,xiq_user_role in group_roles:
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

        for gs_entry in gs_results:
            if gs_entry['name'] not in gs_users:
                try:
                    gs_users[gs_entry['name']] = {
                        "accountEnabled": True if (gs_entry['status']=='ACTIVE') else False,
                        "email": gs_entry['email'],
                        "username": gs_entry['email'],
                        "xiq_role": xiq_user_role
                    }
                except:
                    log_msg = (f"Unexpected error: {sys.exc_info()[0]}")
                    print(log_msg)
                    gs_capture_success = False
                    continue
    log_msg = "Successfully parsed " + str(len(gs_users)) + " GSuite users"
    logging.info(log_msg)
    print(f"{log_msg}\n")

    # Track Error counts
    ppsk_create_error = 0
    pcg_create_error = 0
    ppsk_del_error = 0
    pcg_del_error = 0

    # Create PPSK Users
    ad_disabled = []
    for name, details in gs_users.items():
        user_created = False
        if details['email'] == None:
            log_msg = (f"User {name} doesn't have an email set and will not be created in xiq")
            logging.warning(log_msg)
            print(log_msg)
            continue
        if not any(d['user_name'] == name for d in ppsk_users) and details['accountEnabled'] == True:
            try:
                user_created = createPPSKuser(name, details["email"], details['xiq_role'])
            except TypeError as e:
                log_msg = f"failed to create {name}: {e}"
                logging.error(log_msg)
                print(log_msg)
                ppsk_create_error+=1
            except:
                log_msg = f"Unknown Error: Failed to create user {name} - {details['email']}"
                logging.error(log_msg)
                print(log_msg)
                ppsk_create_error+=1
            if PCG_Enable == True and user_created == True and str(details['xiq_role']) in PCG_Maping:
                ## add user to PCG if PCG is Enabled
                policy_id = PCG_Maping[details['xiq_role']]['policy_id']
                policy_name = PCG_Maping[details['xiq_role']]['policy_name']
                user_group_name = PCG_Maping[details['xiq_role']]['UserGroupName']
                email = details["email"]
                result = ''
                try:
                    result = addUserToPcg(policy_id, name, email, user_group_name)
                except TypeError as e:
                    log_msg = f"failed to add {name} to pcg {policy_name}: {e}"
                    logging.error(log_msg)
                    print(log_msg)
                    pcg_create_error+=1
                except:
                    log_msg = f"Unknown Error: Failed to add user {name} - {details['email']} to pcg {policy_name}"
                    logging.error(log_msg)
                    print(log_msg)
                    pcg_create_error+=1
                if result == 'Success':
                    log_msg = f"User {name} - was successfully add to pcg {policy_name}."
                    logging.info(log_msg)
                    print(log_msg)
                    pcg_create_error+=1

        elif details['accountEnabled'] == False:
            ad_disabled.append(name)
    
    # Remove disabled accounts from ad users
    for name in ad_disabled:
        logging.info(f"User {name} is disabled in GSuite.")
        del gs_users[name]
    
    if PCG_Enable == True:
        pcg_capture_success = True
        # Collect PCG Users if PCG is Enabled
        PCGUsers = []
        for policy in PCG_Maping:
            policy_id = PCG_Maping[policy]['policy_id']

            try:
                PCGUsers += retrievePCGUsers(policy_id)
            except TypeError as e:
                print(e)
                pcg_capture_success = False
                # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
            except:
                log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
                logging.error(log_msg)
                print(log_msg)
                pcg_capture_success = False
                # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):

        log_msg = "Successfully parsed " + str(len(PCGUsers)) + " PCG users"
        logging.info(log_msg)
        print(f"{log_msg}\n")

    if gs_capture_success:
        for x in ppsk_users:
            user_group_id = x['user_group_id']
            email = x['email_address']
            xiq_id = x['id']
            # check if any xiq user is not included in active ad users
            if not any(d['email'] == email for d in gs_users.values()):
                if PCG_Enable == True and str(user_group_id) in PCG_Maping:
                    if pcg_capture_success == False:
                        log_msg = f"Due to PCG read failure, user {email} cannot be deleted"
                        logging.error(log_msg)
                        print(log_msg)
                        ppsk_del_error+=1
                        pcg_del_error+=1
                        continue
                # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
                    # If PCG is Enabled, Users need to be deleted from PCG group before they can be deleted from User Group
                    if any(d['email'] == email for d in PCGUsers):
                        # Find specific PCG user and get the user id
                        PCGUser = (list(filter(lambda PCGUser: PCGUser['email'] == email, PCGUsers)))[0]
                        pcg_id = PCGUser['id']
                        for PCG_Map in PCG_Maping.values():
                            if PCG_Map['UserGroupName'] == PCGUser['user_group_name']:
                                policy_id = PCG_Map['policy_id']
                                policy_name = PCG_Map['policy_name']
                        result = ''
                        try:
                            result = deletePCGUsers(policy_id, pcg_id)
                        except TypeError as e:
                            logmsg = f"Failed to delete user {email} from PCG group {policy_name} with error {e}"
                            logging.error(logmsg)
                            print(logmsg)
                            ppsk_del_error+=1
                            pcg_del_error+=1
                            continue
                        except:
                            log_msg = f"Unknown Error: Failed to delete user {email} from pcg group {policy_name}"
                            logging.error(log_msg)
                            print(log_msg)
                            ppsk_del_error+=1
                            pcg_del_error+=1
                            continue
                        if result == 'Success':
                            log_msg = f"User {email} - {pcg_id} was successfully deleted from pcg group {policy_name}."
                            logging.info(log_msg)
                            print(log_msg)
                        else:
                            log_msg = f"User {email} - {pcg_id} was not successfully deleted from pcg group {policy_name}. User cannot be deleted from the PPSK Group."
                            logging.info(log_msg)
                            print(log_msg)
                            ppsk_del_error+=1
                            pcg_del_error+=1 
                            continue
                result = ''
                try:
                    result, userid = deleteUser(xiq_id)
                except TypeError as e:
                    logmsg = f"Failed to delete user {email}  with error {e}"
                    logging.error(logmsg)
                    print(logmsg)
                    ppsk_del_error+=1
                    continue
                except:
                    log_msg = f"Unknown Error: Failed to delete user {email} "
                    logging.error(log_msg)
                    print(log_msg)
                    ppsk_del_error+=1
                    continue
                if result == 'Success':
                    log_msg = f"User {email} - {userid} was successfully deleted."
                    logging.info(log_msg)
                    print(log_msg)
                else:
                    log_msg = f"User {email} - {userid} did not successfully delete from the PPSK Group."
                    logging.info(log_msg)
                    print(log_msg)
                    ppsk_del_error+=1

        if ppsk_create_error:
            log_msg = f"There were {ppsk_create_error} errors creating PPSK users on this run."
            logging.info(log_msg)
            print(log_msg)
        if pcg_create_error:
            log_msg = f"There were {pcg_create_error} errors creating PCG users on this run."
            logging.info(log_msg)
            print(log_msg)
        if ppsk_del_error:
            log_msg = f"There were {ppsk_del_error} errors deleting PPSK users on this run."
            logging.info(log_msg)
            print(log_msg)
        if pcg_del_error:
            log_msg = f"There were {pcg_del_error} errors deleting PCG users on this run."
            logging.info(log_msg)
            print(log_msg)

    else:
        log_msg = "No users will be deleted from XIQ because of the error(s) in reading GSuite users"
        logging.warning(log_msg)
        print(log_msg)


if __name__ == '__main__':
	main()
