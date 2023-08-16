"""
Copyright (c) 2023 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

"""

__author__ = "Aron Donaldson <ardonald@cisco.com>"
__contributors__ = "Matt Burke <matburke@cisco.com>"
__copyright__ = "Copyright (c) 2023 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import json
import sys
import csv
import time
from getpass import getpass
from argparse import ArgumentParser

# External packages
import requests

# Disable insecure connection warnings on destinations with untrusted certificates
requests.packages.urllib3.disable_warnings()

# Global variables to hold existing FMC object data
object_data = {
    'ikeV1PolicyObjects': [],
    'ikeV2PolicyObjects': [],
    'networkObjects': [],
    'ftdEndpoints': {}
}

def verbose_output(func_name, response):
    """
    Function to print out the full HTTP response data from API calls, when verbose option is chosen.
    params: func_name (str), response (Requests response object)
    """
    print(f'{func_name} Response:\nStatus Code: {response.status_code}\nHeaders: {response.headers}\nPayload: {response.text}\n')
    return


def csv_to_json(args):
    """
    Use Python built-in csv module to parse a CSV file, using the simplest method. 
    params: ArgParse namespace object
    returns: csv_data (list - JSON structure)
    """
    csv_data = []
    with open(args.input_file, 'rt') as f:
        reader = csv.DictReader(f)
        for row in reader:
            csv_data.append(row)
        f.close()
    if args.verbose:
        print(f'CSV Data:\n{json.dumps(csv_data, indent=4)}\n')
    return csv_data


def yaml_to_json(args):
    """
    Use PyYAML package from PyPi to parse a YAML file into JSON
    params: ArgParse namespace object
    returns: yaml_data (list - JSON structure)
    """
    # Only import PyYAML if needed
    import yaml # Packaged named "PyYAML" at pypi.org
    with open(args.input_file, 'r') as f:
        try:
            result = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f'Error parsing YAML file:\n{e}')
            sys.exit(1)
    f.close()
    if args.verbose:
        print(f'YAML Data:\n{json.dumps(result, indent=4)}\n')
    return result


def write_to_csv(input_data):
    """
    Function to write resulting output data to CSV format
    params: input_data
    returns: output file name (str)
    """
    # Import Pandas module only if needed
    from pandas import read_json
    # Get current date/time in proper format
    timestamp = time.strftime("%Y-%m-%d_%I-%M-%S%p_%Z", time.localtime())
    filename = f'results_{timestamp}.csv'
    # Use Pandas to read in JSON data
    data = read_json(json.dumps(input_data))
    data.to_csv(filename, index=False)
    return filename


def write_to_yaml(input_data):
    """
    Function to write resulting output data to YAML format
    params: input_data
    returns: output file name (str)
    """
    # Only import PyYAML if needed
    import yaml # Packaged named "PyYAML" at pypi.org
    # Get current date/time in proper format
    timestamp = time.strftime("%Y-%m-%d_%I-%M-%S%p_%Z", time.localtime())
    filename = f'results_{timestamp}.yaml'
    with open(filename, 'w') as f:
        yaml.dump(input_data, f)
    f.close()
    return filename


def write_to_text(input_data, obj_name=''):
    """
    Function to write resulting output data to JSON formatted text file.
    params: input_data
    returns: output file name (str)
    """
    # Get current date/time in proper format
    timestamp = time.strftime("%Y-%m-%d_%I-%M-%S%p_%Z", time.localtime())
    if obj_name == '':
        filename = f'results_{timestamp}.json'
    else:
        filename = f'{obj_name}_{timestamp}.json'
    with open(filename, 'w') as f:
        f.write(json.dumps(input_data, indent=4))
    f.close()
    return filename


def auth(args):
    """
    Authenticate to the FMC server and obtain a token.
    params: ArgParse namespace object
    returns: token (str), refresh_token (str), domain_uuid (str)
    """
    # If user didn't specify a password, prompt them interactively.
    # Passwords with special characters can be problematic as CLI arguments.
    if not args.password:
        password = getpass("Please enter the FMC password: ", stream=None)
    else:
        password = args.password
    
    url = f'https://{args.fmc_server}/api/fmc_platform/v1/auth/generatetoken'
    headers = {
        'Content-Type': 'application/json'
    }

    if args.cert_path:
        response = requests.post(url, headers=headers, auth=requests.auth.HTTPBasicAuth(args.username,password), verify=args.cert_path)
    else:
        response = requests.post(url, headers=headers, auth=requests.auth.HTTPBasicAuth(args.username,password), verify=False)
    
    if args.verbose:
        verbose_output('auth()', response)
    
    if response.status_code in [200, 204] and response.headers['X-auth-access-token'] != '':
        token = response.headers['X-auth-access-token']
        refresh_token = response.headers['X-auth-refresh-token']
        domain_uuid = response.headers['DOMAIN_UUID']
        return token, refresh_token, domain_uuid 
    else:
        print('Error encountered during authentication:\n')
        # Use verbose_output() to print out response details
        verbose_output('auth()', response)
        sys.exit(1)


def get_ike_object(args, token, domain_uuid):
    """
    Function to obtain data about IKE Policy Objects in FMC.  Updates global variable with results.
    params: ArgParse namespace object, token (str), domain_uuid (str)
    """
    global object_data

    urlIkeV1 = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/object/ikev1policies'
    urlIkeV2 = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/object/ikev2policies'

    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }
    if args.cert_path:
        responseV1 = requests.get(urlIkeV1, headers=headers, verify=args.cert_path)
        responseV2 = requests.get(urlIkeV2, headers=headers, verify=args.cert_path)
    else:
        responseV1 = requests.get(urlIkeV1, headers=headers, verify=False)
        responseV2 = requests.get(urlIkeV2, headers=headers, verify=False)
    
    if args.verbose:
        verbose_output('get_ike_object()', responseV1)
        verbose_output('get_ike_object()', responseV2)
    
    if responseV1.status_code in [200]:
        object_data['ikeV1PolicyObjects'] = responseV1.json()['items']
    else:
        print(f'!!!!!!!!!!\nError encountered when obtaining details about IKE Policy Objects."\n!!!!!!!!!!\n')
        verbose_output('get_ike_object()', responseV1)
    
    if responseV2.status_code in [200]:
        object_data['ikeV2PolicyObjects'] = responseV2.json()['items']
    else:
        print(f'!!!!!!!!!!\nError encountered when obtaining details about IKE Policy Objects."\n!!!!!!!!!!\n')
        verbose_output('get_ike_object()', responseV2)


def get_network_objects(args, token, domain_uuid):
    """
    Function to obtain data about Network Objects in FMC.  Updates global variable with results.
    params: ArgParse namespace object, token (str), domain_uuid (str)
    """
    global object_data

    url = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/object/networks'

    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }
    if args.cert_path:
        response = requests.get(url, headers=headers, verify=args.cert_path)
    else:
        response = requests.get(url, headers=headers, verify=False)
    
    if args.verbose:
        verbose_output('get_network_objects()', response)
    
    if response.status_code in [200]:
        object_data['networkObjects'] = response.json()['items']
    else:
        print(f'!!!!!!!!!!\nError encountered when obtaining details about Network Objects."\n!!!!!!!!!!\n')
        verbose_output('get_network_objects()', response)


def get_device_details(args, token, domain_uuid, input_data):
    """
    Function to obtain details of Devices in FMC.
    params: ArgParse namespace object, token (str), domain_uuid (str), input_data (list)
    """
    global object_data

    url = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords'

    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }

    for item in input_data:
        # Check if data was already collected on this device and pass
        if object_data['ftdEndpoints'].get(item['device_name']):
            pass
        # If data not already collected, move ahead and collect
        else:
            object_data['ftdEndpoints'][item["device_name"]] = {}
            # Filter results to just this device name in FMC
            params = {
                'filter': f'name:{item["device_name"]}'
            }
            if args.cert_path:
                response = requests.get(url, headers=headers, params=params, verify=args.cert_path)
            else:
                response = requests.get(url, headers=headers, params=params, verify=False)
            
            if args.verbose:
                verbose_output('get_device_details()', response)
            
            if response.status_code in [200]:
                for device in response.json()['items']:
                    if item['device_name'] == device['name']:
                        object_data['ftdEndpoints'][item['device_name']] = device
                        # Call helper function to gather interface details next
                        object_data['ftdEndpoints'][item['device_name']]['interfaces'] = get_device_interfaces(args, token, domain_uuid, device['id'])
                    else:
                        # If device is not found in the response payload, then take this action.
                        print(f'!!!!!!!!!!\nDevice Name {item["device_name"]}specified in input data was not found."\n!!!!!!!!!!\n')
                        verbose_output('get_device_details()', response)
            else:
                print(f'!!!!!!!!!!\nError encountered when obtaining details about device {item["device_name"]}."\n!!!!!!!!!!\n')
                verbose_output('get_device_details()', response)


def get_device_interfaces(args, token, domain_uuid, device_uuid):
    """
    Helper function to obtain interface details of a device in FMC.
    params: ArgParse namespace object, token (str), domain_uuid (str), device_uuid (str)
    returns: interfaces (list)
    """
    url = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{device_uuid}/ftdallinterfaces'

    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }
    # Request full details to be returned, not just summary (only way to get the "ifname" key in response data, which contains interface's "Logical Name")
    params = {
        "expanded": True
    }

    if args.cert_path:
        response = requests.get(url, headers=headers, params=params, verify=args.cert_path)
    else:
        response = requests.get(url, headers=headers, params=params, verify=False)
    
    if args.verbose:
        verbose_output('get_device_interfaces()', response)

    if response.status_code in [200]:
        return response.json()['items']
    else:
        print(f'!!!!!!!!!!\nError encountered when obtaining interface details about device with UUID: {device_uuid}."\n!!!!!!!!!!\n')
        verbose_output('get_device_details()', response)
        return []


def create_s2s_policy(args, token, domain_uuid, input_data):
    """
    Create the Site-to-Site VPN Policy object container.
    params: ArgParse namespace object, token (str), domain_uuid (str), input_data (list, JSON-formatted)
    returns: config_result (list)
    """
    url = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns'
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }

    result = []
    for policy in input_data:
        # Payload options vary depending on IKE Version
        if policy['ike_version'] == "1":
            payload = {
                "name": policy['s2s_policy_name'],
                "type": "FTDS2SVpn",
                "topologyType": "POINT_TO_POINT",
                "ikeV1Enabled": True,
                "ikeV2Enabled": False
            }
        else:
            payload = {
                "name": policy['s2s_policy_name'],
                "type": "FTDS2SVpn",
                "topologyType": "POINT_TO_POINT",
                "ikeV1Enabled": False,
                "ikeV2Enabled": True
            }
        
        if args.cert_path:
            response = requests.post(url, headers=headers, json=payload, verify=args.cert_path)
        else:
            response = requests.post(url, headers=headers, json=payload, verify=False)
        
        if args.verbose:
            verbose_output('create_s2s_policy()', response)

        if response.status_code in [200, 201, 202]:
            # Call helper function to update IKE settings
            ike_update_response = update_ike_settings(args, token, domain_uuid, policy, response.json())
            # Call helper function to add Node A endpoint
            node_a_response = create_nodeA_endpoint(args, token, domain_uuid, policy, response.json())
            # Call helper function to add Node B endpoint ONLY if Node A successful
            if node_a_response is not None:
                node_b_response = create_nodeB_endpoint(args, token, domain_uuid, policy, response.json())
            # Get resulting configuration of S2S VPN Policy
            config_result = get_s2s_policy_result(args, token, domain_uuid, response.json())
            # Check if result was not None
            if config_result:
                result.append(config_result)
        else:
            print(f'!!!!!!!!!!\nError encountered creating policy {policy["s2s_policy_name"]}\n!!!!!!!!!!\n')
            verbose_output('create_s2s_policy()', response)
    return result


def update_ike_settings(args, token, domain_uuid, input_data, response_data):
    """
    Function to update the ftds2svpns policy with IKE settings.  Helper function for create_s2s_policy().
    params: ArgParse namespace object, token (str), domain_uuid (str), input_data (dict, single element of user input data)
    returns: result (dict) OR None (if error)
    """
    url = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{response_data["id"]}/ikesettings/{response_data["ikeSettings"]["id"]}'
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }
    # Create variable to capture IKE Policy Object details
    ike_policy_object = None

    if input_data['ike_version'] == '1':
        for object in object_data['ikeV1PolicyObjects']:
            if input_data['ike_policy'].lower() == object['name'].lower():
                ike_policy_object = object
                break
        # Check if matching IKE Policy Object was found
        if ike_policy_object:
            payload = {
                "ikeV1Settings": {
                    "authenticationType": "MANUAL_PRE_SHARED_KEY",
                    "manualPreSharedKey": input_data['preshared_key'],
                    "policies": [
                        {
                            "name": ike_policy_object['name'],
                            "id": ike_policy_object['id'],
                            "type": ike_policy_object['type']
                        }
                    ]
                },
                "id": "",
                "type": "IkeSetting"
            }
        else:
            print(f'!!!!!!!!!!\nIKE Policy Name {input_data["ike_policy"]} not found in IKE Policy Objects."\n!!!!!!!!!!\n')
            print(f'Current IKE V1 Policy Objects:\n{json.dumps(object_data["ikeV1PolicyObjects"], indent=4)}\n')
            sys.exit(1)
    # If input_data['ike_version'] == '2', create this payload instead.
    else:
        for object in object_data['ikeV2PolicyObjects']:
            if input_data['ike_policy'].lower() == object['name'].lower():
                ike_policy_object = object
                break
        # Check if matching IKE Policy Object was found
        if ike_policy_object:
            payload = {
                "ikeV2Settings": {
                    "authenticationType": "MANUAL_PRE_SHARED_KEY",
                    "manualPreSharedKey": input_data['preshared_key'],
                    "enforceHexBasedPreSharedKeyOnly": False,
                    "policies": [
                        {
                            "name": ike_policy_object['name'],
                            "id": ike_policy_object['id'],
                            "type": ike_policy_object['type']
                        }
                    ]
                },
                "id": "",
                "type": "IkeSetting"
            }
        else:
            print(f'!!!!!!!!!!\nIKE Policy Name {input_data["ike_policy"]} not found in IKE Policy Objects."\n!!!!!!!!!!\n')
            print(f'Current IKE V2 Policy Objects:\n{json.dumps(object_data["ikeV2PolicyObjects"], indent=4)}\n')
            sys.exit(1)
    
    if args.cert_path:
        response = requests.put(url, headers=headers, json=payload, verify=args.cert_path)
    else:
        response = requests.put(url, headers=headers, json=payload, verify=False)
    
    if args.verbose:
        verbose_output('update_ike_settings()', response)

    if response.status_code in [200, 201, 202]:
        return response.json()
    else:
        print(f'!!!!!!!!!!\nError encountered updating IKE settings on policy {input_data["s2s_policy_name"]}\n!!!!!!!!!!\n')
        verbose_output('update_ike_settings()', response)
        return None


def create_nodeA_endpoint(args, token, domain_uuid, input_data, response_data):
    """
    Function to create a Node A endpoint on the ftds2svpns policy.
    params: ArgParse namespace object, token (str), domain_uuid (str), input_data (dict, single element of user input data)
    returns: result (dict) OR None (if error)
    """
    global object_data

    url = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{response_data["id"]}/endpoints'
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }
    interface_data = {
        'name': '',
        'id': '',
        'type': ''
    }

    # Loop through interfaces and look for a match by 'name' (Interface Name) or 'ifname' (Logical Name)
    for int in object_data['ftdEndpoints'][input_data['device_name']]['interfaces']:
        if input_data['device_interface_name'].lower() in int['name'].lower():
            interface_data['name'] = int['name']
            interface_data['id'] = int['id']
            interface_data['type'] = int['type']
            break
        else:
            # The 'ifname' key does not exist if no Logical Name was assigned. This handles 'KeyError' error messages.
            try:
                if input_data['device_interface_name'].lower() in int['ifname'].lower():
                    interface_data['name'] = int['ifname']
                    interface_data['id'] = int['id']
                    interface_data['type'] = int['type']
                    break
            except KeyError:
                pass
    
    network_data = {
        'name': '',
        'id': '',
        'type': ''
    }
    # Loop through network objects and look for match by name
    for network in object_data['networkObjects']:
        if input_data['protected_network_name'].lower() == network['name'].lower():
            network_data['name'] = network['name']
            network_data['id'] = network['id']
            network_data['type'] = network['type']
            break

    # If no match is found, 'name' field remains blank - print error and return None.
    if interface_data['name'] == '':
        print(f'!!!!!!!!!!\nError encountered locating interface {input_data["interface_name"]} on device {input_data["device_name"]}\n!!!!!!!!!!\n')
        print(json.dumps(object_data[input_data['device_name']], indent=4))
        return None
    elif network_data['name'] == '':
        print(f'!!!!!!!!!!\nError encountered locating protected network {input_data["protected_network_name"]}\n!!!!!!!!!!\n')
        print(json.dumps(object_data['networkObjects'], indent=4))
        return None
    else:
        payload = {
            "peerType": "PEER",
            "device": {
                "name": input_data['device_name'],
                "id": object_data['ftdEndpoints'][input_data['device_name']]['id'],
                "type": "Device"
            },
            "interface": {
                "name": interface_data['name'],
                "id": interface_data['id'],
                "type": interface_data['type']
            },
            "protectedNetworks": {
                "networks": [
                    {
                        "name": network_data['name'],
                        "id": network_data['id'],
                        "type": network_data['type']
                    }
                ]
            },
            "connectionType": "BIDIRECTIONAL",
            "isLocalTunnelIdEnabled": False,
            "type": "EndPoint",
            "overrideRemoteVpnFilter": False
        }

    if args.cert_path:
        response = requests.post(url, headers=headers, json=payload, verify=args.cert_path)
    else:
        response = requests.post(url, headers=headers, json=payload, verify=False)
    
    if args.verbose:
        verbose_output('create_nodeA_endpoint()', response)

    if response.status_code in [200, 201]:
        return response.json()
    else:
        print(f'!!!!!!!!!!\nError encountered adding Node A Endpoint to policy {input_data["s2s_policy_name"]}\n!!!!!!!!!!\n')
        verbose_output('create_nodeA_endpoint()', response)
        return None
    

def create_nodeB_endpoint(args, token, domain_uuid, input_data, response_data):
    """
    Function to create a Node B endpoint on the ftds2svpns policy.
    params: ArgParse namespace object, token (str), domain_uuid (str), input_data (dict, single element of user input data)
    returns: result (dict) OR None (if error)
    """
    global object_data

    url = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{response_data["id"]}/endpoints'
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }
    
    network_data = {
        'name': '',
        'id': '',
        'type': ''
    }
    # Loop through network objects and look for match by name
    for network in object_data['networkObjects']:
        if input_data['remote_protected_network_name'].lower() == network['name'].lower():
            network_data['name'] = network['name']
            network_data['id'] = network['id']
            network_data['type'] = network['type']
            break
    
    # If no match is found, 'name' field remains blank - print error and return None.
    if network_data['name'] == '':
        print(f'!!!!!!!!!!\nError encountered locating protected network object {input_data["remote_protected_network_name"]}\n!!!!!!!!!!\n')
        print(json.dumps(object_data['networkObjects'], indent=4))
        return None
    else:
        payload = {
            "peerType": "PEER",
            "extranetType": "GENERIC",
            "dynamicRRIEnabled": False,
            "connectionType": "ORIGINATE_ONLY",
            "isLocalTunnelIdEnabled": False,
            "type": "EndPoint",
            "name": input_data['remote_device_name'],
            "extranet": True,
            "extranetInfo": {
                "name": input_data['remote_device_name'],
                "ipAddress": input_data['remote_device_ip'],
                "isDynamicIP": input_data['is_dynamic_ip']
            },
            "protectedNetworks": {
                "networks": [
                    {
                        "name": network_data['name'],
                        "id": network_data['id'],
                        "type": network_data['type']
                    }
                ]
            },
            "overrideRemoteVpnFilter": False
        }

    if args.cert_path:
        response = requests.post(url, headers=headers, json=payload, verify=args.cert_path)
    else:
        response = requests.post(url, headers=headers, json=payload, verify=False)
    
    if args.verbose:
        verbose_output('create_nodeB_endpoint()', response)

    if response.status_code in [200, 201]:
        return response.json()
    else:
        print(f'!!!!!!!!!!\nError encountered adding Node B Endpoint to policy {input_data["s2s_policy_name"]}\n!!!!!!!!!!\n')
        verbose_output('create_nodeB_endpoint()', response)
        return None


def get_s2s_policy_result(args, token, domain_uuid, response_data):
    """
    Get the final resulting configuration of the policy object
    params: ArgParse namespace object, token (str), domain_uuid (str)
    returns: result (list)
    """
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': token
    }
    url = f'https://{args.fmc_server}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{response_data["id"]}'
    if args.cert_path:
        response = requests.get(url, headers=headers, verify=args.cert_path)
    else:
        response = requests.get(url, headers=headers, verify=False)

    if args.verbose:
        verbose_output('get_s2s_policy_result()', response)

    if response.status_code in [200]:
        return response.json()
    else:
        print(f'!!!!!!!!!!\nError occurred getting details of S2S VPN Policy {response_data["name"]}, ID: {response_data["id"]}.\n!!!!!!!!!!\n')
        verbose_output('get_s2s_policy_result()', response)
        return None


def main(args):
    """
    Main function to control workflow in this script.
    params: args (ArgParse Namespace object)
    """
    
    # Check input file extension and parse input data
    extension = args.input_file.split('.')[1].lower()
    if extension == 'csv':
        input_data = csv_to_json(args)
    elif extension in ['yml', 'yaml']:
        input_data = yaml_to_json(args)
    else:
        print(f'Input file extension "{extension}" is not supported.')
        sys.exit(1)
    
    # Authenticate to FMC and obtain token
    token, refresh_token, domain_uuid = auth(args)
    
    # Get IKE Policy Object information
    get_ike_object(args, token, domain_uuid)
    
    # Get Network Object information
    get_network_objects(args, token, domain_uuid)
    
    # Get details about FTD Device
    get_device_details(args, token, domain_uuid, input_data)
    
    # If user chose "collect_data" option, only perform GET requests and then write output to file.
    if args.collect_data:
        # Nested JSON does not flatten into CSV very well, so write to text file.
        filename = write_to_text(object_data, 'object_data')
        print(f'\n**********\nResults saved to output file {filename}\n**********')
    else:
        # Create the S2S VPN Policy object and all supporting configurations
        result = create_s2s_policy(args, token, domain_uuid, input_data)
        # Write results to an appropriate filetype, based on input file.
        if extension == 'csv':
            filename = write_to_csv(result)
        elif extension in ['yml', 'yaml']:
            filename = write_to_yaml(result)
        print(f'\n**********\nResults saved to output file {filename}\n**********')


# If this script is executed directly from the Python interpreter (not imported into another script), collect CLI arguments and then call main() function.
if __name__ == "__main__":
    parser = ArgumentParser(description='Select your options:')
    parser.add_argument('--username', '-u', type=str, required=True, help='FMC Username')
    parser.add_argument('--password', '-p', type=str, required=False, help='FMC Password')
    parser.add_argument('--fmc_server', '-s', type=str, required=True, help='FMC Server IP')
    parser.add_argument('--cert_path', '-c', type=str, required=False, help='Path to FMC cert, if you choose to verify it.')
    parser.add_argument('--input_file', '-f', type=str, required=True, help='Filename of the configuration input file.  Accepts CSV and YAML formats.')
    parser.add_argument('--collect_data', action='store_true', help='Only make GET API calls to collect object data from FMC, then save results to output files.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Print verbose output')
    args = parser.parse_args()
    
    main(args)