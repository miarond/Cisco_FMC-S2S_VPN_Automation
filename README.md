# Site to Site VPN Automation

This repository contains a Python script which can be used to create Site to Site VPN Policies (and associated objects) in a Cisco Firepower Management Center (FMC) controller.  It also contains [detailed documentation on the API endpoints](/API_DOCS.md) used by this script to perform these functions.  The FMC controller stores configurations as distinct "objects", each with a Universally Unique IDentifier (UUID), which must be used to identify the object when linking or "relating" it to another object.  In short, several API calls must be made to the FMC in order to collect these UUIDs so that future API payloads can be constructed.

The included Python script, `Site_to_Site_VPN_Automation.py` can perform all of these steps based on input data from the user, but you can also build your own automation using the API documentation provided and this Python script as an example.

## CLI Arguments

The Python script accepts several CLI arguments when you run it - some are required and others are optional.  Here is a list of the CLI arguments and their purpose (you can also view this output by issuing the command `python Site_to_Site_VPN_Automation.py --help`):

| **Argument** | **Required?** | **Description** |
| :---         |    :---:      | :---            |
| `--username`, `-u` | Yes | The username used to authenticate and make API calls to FMC. |
| `--password`, `-p` | No | The password used to authenticate and make API calls to FMC. If not specified as an argument, the script will prompt the user interactively for a password. |
| `--fmc_server`, `-s` | Yes | The IP address or DNS FQDN of the FMC. |
| `--cert_path`, `-c` | No | The path and filename of the FMC's SSL certificate, if you choose to validate it. |
| `--input_file`, `-f` | Yes | The path and filename of the input file, containing S2S VPN configuration details.  Can be either CSV (`.csv`) or YAML (`.yml`, `.yaml`) format. |
| `--collect_data` | No | Optional, no value needed. If specified, the script will only make GET API calls to collect data from the FMC, then write the data to an output file in either YAML or JSON format (based on the format of the input file). |
| `--verbose`, `-v` | No | Optional, no value needed.  If specified, the script will print out the Status Code, Headers, and Payload of all API responses from the FMC, as well as the resulting JSON derived from the contents of the input file. |

## Input File

The Python script requires an input file in CSV or YAML format.  An example of each of these files is provided with this project: `example_csv_input.csv` and `example_yaml_input.yml`

These files must contain the specific configuration parameters for the Site to Site VPN policies you want to create.  The files can contain an unlimited number of "rows" (CSV) or "dictionaries" (YAML), meaning that the script will loop through each element and create a Site to Site VPN policy using the parameters provided in them.  Note that the script will take some time (seconds, up to a minute) to process each element, so having a large number in your input file could require a significant amount of time to process.

The input file must specify these columns (CSV) or dictionary keys (YAML), with the appropriate data as the value:

| **Column/Key** | **Example** | **Description** |
| :---           | :---        | :---            |
| `s2s_policy_name` | "Test_Policy_1" | The name of the Site to Site VPN Policy you want to create. |
| `ike_version` | "1" or "2" | The IKE Version that you want to use for the Site to Site VPN Policy. |
| `ike_policy` | "DES-SHA-SHA-LATEST" | The name of the IKE Policy that exists in your FMC.  **NOTE: This policy MUST exist before the script is run** - it will not create a policy if one does not exist, and the script will exit. |
| `preshared_key` | "ABC123" | The pre-shared key that will be configured in the Site to Site VPN Policy. |
| `device_name` | "FTD" | The name of the FTD device that will be used as the "Node A" endpoint on the Site to Site VPN policy.  This corresponds to the "Local Name" in FMC, not the "Hostname" of the device. |
| `device_interface_name` | "Inside_Interface" | The name of the Interface on the FTD device that will be the termination point of the VPN tunnel.  **NOTE: This can be the interface's "Logical Name" or the actual "Physical Name".** |
| `protected_network_name` | "10.10.10.0_24" | The name of a Network Object in FMC that corresponds to the protected network assigned in the Site to Site VPN Policy.  **NOTE: This Network Object must exist before the script is run** - it will not create this object if it does not exist, and the script will exit. |
| `remote_device_name` | "Remote_Device" | The friendly name used for the remote device that terminates the VPN tunnel. |
| `remote_device_ip` | 192.168.1.1 | The IP address of the remote device, where the VPN tunnel should terminate. (This script assumes the remote device will be an "Extranet" device; this can be changed by altering the Python code and payload of the Node B Endpoint API call.) |
| `is_dynamic_ip` | `True` or `False` | Configures the Site to Site VPN "Node B Endpoint" to expect a static or dynamic IP address. |
| `remote_protected_network_name` | "192.168.1.0_24" | The name of the Network Object in FMC that corresponds to the remote node's protected network, assigned in the Site to Site VPN Policy. **NOTE: This Network Object must exist before the script is run** - it will not create this object if it does not exist, and the script will exit. |

## Dependencies

The included Python script utilizes the following external packages:

* [Requests](https://pypi.org/project/requests/): Used for constructing HTTP messages to make API calls.
* [Pandas](https://pypi.org/project/pandas/): A Python data analysis toolkit.  In this script it is used to flatten JSON and convert it to CSV in order to write output to a CSV file. (Only imported if the input file is in CSV format)
* [PyYAML](https://pypi.org/project/PyYAML/): A YAML parser for Python, used to read YAML input files and convert them to JSON objects. (Only imported if the input file is in YAML format)

These dependencies can be installed using Python's Pip Package Manager by running the command `pip install -r requirements.txt`.