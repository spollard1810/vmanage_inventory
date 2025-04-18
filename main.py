import requests
import json
import sys
import getpass
import argparse
import warnings
import csv
import urllib3

# Suppress insecure request warnings as we are intentionally disabling verification
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# --- Function to Handle Login ---
def vmanage_login(vmanage_ip, username, password):
    """Logs into vManage, explicitly DISABLING SSL verification."""
    session = requests.Session()
    session.verify = False # Disable SSL verification

    login_url = f"https://{vmanage_ip}/j_security_check"
    login_payload = {'j_username': username, 'j_password': password}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        print(f"Attempting login to {vmanage_ip} as user '{username}' (SSL Verification Disabled)...")
        response = session.post(login_url, headers=headers, data=login_payload)
        response.raise_for_status()

        if 'JSESSIONID' in session.cookies:
            print("Login successful.")
            # Fetch CSRF token (optional but good practice)
            token_url = f"https://{vmanage_ip}/dataservice/client/token"
            try:
                token_response = session.get(token_url) # verify=False inherited
                token_response.raise_for_status()
                if token_response.status_code == 200 and token_response.text:
                    session.headers['X-XSRF-TOKEN'] = token_response.text
                    print("CSRF Token obtained successfully.")
                else:
                     print(f"Warning: Could not obtain CSRF token (Status: {token_response.status_code}).")
            except requests.exceptions.RequestException as token_err:
                 print(f"Warning: Error fetching CSRF token: {token_err}")
            return session
        else:
            # ... (rest of login failure handling)
            print("Login failed: JSESSIONID cookie not found.")
            print(f"Status Code: {response.status_code}")
            print(f"Response Text (first 100 chars): {response.text[:100]}...")
            return None
    # ... (rest of login error handling)
    except requests.exceptions.Timeout:
        print(f"Error: Connection to {vmanage_ip} timed out during login.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"Error: Could not connect to {vmanage_ip}. Check IP/hostname and network.")
        print(f"Details: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"Error: HTTP Error during login: {e}")
        print(f"Status Code: {e.response.status_code}")
        print(f"Response Text (first 100 chars): {e.response.text[:100]}...")
        if e.response.status_code == 401:
            print("Hint: Authentication failed. Verify username/password.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during login: {e}")
        return None


# --- Function to Get Device Inventory ---
def get_device_inventory(vmanage_ip, session):
    """
    Fetches device inventory using /dataservice/device endpoint.
    Handles cases where the response is a dictionary containing a 'data' list.
    SSL verification is disabled via the session settings.

    Args:
        vmanage_ip (str): IP address or FQDN of the vManage server.
        session (requests.Session): The authenticated session object.

    Returns:
        list: A list of device dictionaries, or None on error. Returns [] if
              the request succeeds but no devices are found or data format is unexpected.
    """
    if not session:
        print("Error: Cannot fetch inventory without a valid session.")
        return None

    inventory_url = f"https://{vmanage_ip}/dataservice/device"
    print(f"Fetching device inventory from {inventory_url} (SSL Verification Disabled)...")

    try:
        response = session.get(inventory_url) # verify=False inherited
        response.raise_for_status()
        response_data = response.json() # Parse the JSON response

        # --- MODIFICATION START ---
        # Check if the response is a dictionary and has a 'data' key containing a list
        if isinstance(response_data, dict) and 'data' in response_data and isinstance(response_data['data'], list):
            devices_list = response_data['data']
            print(f"Successfully retrieved inventory for {len(devices_list)} devices (found list within 'data' key).")
            return devices_list
        # --- MODIFICATION END ---

        # --- Keep Original Fallback: Check if the response is directly a list ---
        elif isinstance(response_data, list):
             # This might happen on different vManage versions or was the case in the example spec
            print(f"Successfully retrieved inventory for {len(response_data)} devices (response was a direct list).")
            return response_data
        # --- Handle Unexpected Format ---
        else:
            print(f"Warning: Expected JSON dictionary with a 'data' list or a direct list from {inventory_url}, but received unexpected format.")
            print(f"Received Type: {type(response_data)}")
            # Try to print keys if it's a dict, otherwise print sample
            if isinstance(response_data, dict):
                 print(f"Dictionary Keys: {list(response_data.keys())}")
            else:
                 print(f"Response sample: {str(response_data)[:200]}...")
            return [] # Return empty list as data format is not recognized


    except requests.exceptions.Timeout:
        print(f"Error: Request to {inventory_url} timed out.")
        return None
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to {vmanage_ip} for inventory.")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"Error: HTTP Error fetching inventory: {e}")
        print(f"Status Code: {e.response.status_code}")
        print(f"Response Text (first 100 chars): {e.response.text[:100]}...")
        return None
    except json.JSONDecodeError:
        print("Error: Failed to parse JSON response from inventory endpoint.")
        print(f"Response Text (first 100 chars): {response.text[:100]}...")
        return None
    except Exception as e:
        print(f"An unexpected error occurred fetching inventory: {e}")
        return None

# --- Function to Write Inventory to CSV ---
def write_inventory_to_csv(inventory_list, filename):
    """Writes hostname, model, serial from the inventory list to a CSV file."""
    csv_headers = ["hostname", "model", "serial"]
    api_keys = ["host-name", "device-model", "board-serial"]

    print(f"Writing inventory to CSV file: {filename}")
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(csv_headers) # Write header

            count = 0
            for device in inventory_list:
                # Use .get() for safety, provide 'N/A' if key is missing
                hostname = device.get(api_keys[0], 'N/A')
                model = device.get(api_keys[1], 'N/A')
                serial = device.get(api_keys[2], 'N/A')
                writer.writerow([hostname, model, serial])
                count += 1

        print(f"Successfully wrote {count} device records to {filename}.")
        return True
    # ... (rest of CSV writing error handling)
    except IOError as e:
        print(f"Error: Could not write to file {filename}: {e}")
        return False
    except Exception as e:
         print(f"An unexpected error occurred during CSV writing: {e}")
         return False


# --- Main Execution Block ---
def main():
    parser = argparse.ArgumentParser(description="Login to vManage (ignoring SSL), get inventory, and dump specific fields to CSV.")
    parser.add_argument("vmanage_ip", help="IP address or FQDN of the vManage server.")
    parser.add_argument("-u", "--username", required=True, help="vManage username.")
    parser.add_argument("-p", "--password", help="Password. If not provided, will be prompted securely.")
    parser.add_argument("-o", "--outfile", required=True, help="Path for the output CSV file.")

    args = parser.parse_args()

    # --- SSL WARNING ---
    print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!! WARNING: SSL CERTIFICATE VERIFICATION DISABLED !!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

    if not args.password:
        password = getpass.getpass(f"Enter password for user '{args.username}': ")
    else:
        password = args.password

    # --- Step 1: Login ---
    authenticated_session = vmanage_login(args.vmanage_ip, args.username, password)
    if not authenticated_session:
        print("\nExiting due to login failure.")
        sys.exit(1)

    # --- Step 2: Get Inventory ---
    device_inventory = get_device_inventory(args.vmanage_ip, authenticated_session)
    if device_inventory is None:
        print("\nFailed to retrieve device inventory.")
        sys.exit(1)
    if not device_inventory:
        print("\nNo devices found or data format was unexpected. Nothing written to CSV.")
        sys.exit(0)

    # --- Step 3: Write to CSV ---
    if not write_inventory_to_csv(device_inventory, args.outfile):
        print("\nExiting due to CSV writing failure.")
        sys.exit(1)

    print("\nScript completed successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()