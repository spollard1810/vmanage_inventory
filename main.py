import requests
import json
import sys
import getpass
import argparse
import warnings
import csv # Import the CSV module

# Suppress insecure request warnings as we are intentionally disabling verification
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# --- Function to Handle Login ---
def vmanage_login(vmanage_ip, username, password):
    """
    Logs into vManage, explicitly DISABLING SSL verification.

    Args:
        vmanage_ip (str): IP address or FQDN of the vManage server.
        username (str): The username.
        password (str): The password.

    Returns:
        requests.Session: An authenticated session object if successful, None otherwise.
    """
    session = requests.Session()
    # --- SSL Verification DISABLED ---
    session.verify = False

    login_url = f"https://{vmanage_ip}/j_security_check"
    login_payload = {'j_username': username, 'j_password': password}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        print(f"Attempting login to {vmanage_ip} as user '{username}' (SSL Verification Disabled)...")
        response = session.post(login_url, headers=headers, data=login_payload)
        response.raise_for_status()

        if 'JSESSIONID' in session.cookies:
            print("Login successful.")
            # Fetch CSRF token
            token_url = f"https://{vmanage_ip}/dataservice/client/token"
            try:
                token_response = session.get(token_url) # verify=False is inherited from session
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
            print("Login failed: JSESSIONID cookie not found.")
            print(f"Status Code: {response.status_code}")
            print(f"Response Text (first 100 chars): {response.text[:100]}...")
            return None

    except requests.exceptions.Timeout:
        print(f"Error: Connection to {vmanage_ip} timed out during login.")
        return None
    except requests.exceptions.ConnectionError as e:
        # This error often occurs first if SSL verification fails *and* was enabled
        # Since we disabled it, this is more likely a network path issue.
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
    Fetches device inventory using the /dataservice/device endpoint.
    SSL verification is disabled via the session settings.

    Args:
        vmanage_ip (str): IP address or FQDN of the vManage server.
        session (requests.Session): The authenticated session object.

    Returns:
        list: A list of device dictionaries, or None on error.
    """
    if not session:
        print("Error: Cannot fetch inventory without a valid session.")
        return None

    inventory_url = f"https://{vmanage_ip}/dataservice/device"
    print(f"Fetching device inventory from {inventory_url} (SSL Verification Disabled)...")

    try:
        response = session.get(inventory_url) # verify=False inherited from session
        response.raise_for_status()
        devices_list = response.json()

        if isinstance(devices_list, list):
            print(f"Successfully retrieved inventory for {len(devices_list)} devices.")
            return devices_list
        else:
            print(f"Warning: Expected a JSON list from {inventory_url}, but received type {type(devices_list)}.")
            return [] # Return empty list

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
    """
    Writes specific fields from the inventory list to a CSV file.

    Args:
        inventory_list (list): The list of device dictionaries.
        filename (str): The path to the output CSV file.

    Returns:
        bool: True if writing was successful, False otherwise.
    """
    # Define the headers/columns for the CSV file
    # These should match keys in the device dictionaries or use .get() below
    csv_headers = ["hostname", "model", "serial"]
    # These are the corresponding keys expected in the vManage API response dict
    api_keys = ["host-name", "device-model", "board-serial"]

    print(f"Writing inventory to CSV file: {filename}")
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Write the header row
            writer.writerow(csv_headers)

            # Write data rows
            count = 0
            for device in inventory_list:
                # Extract data using .get() for safety in case a key is missing
                hostname = device.get(api_keys[0], 'N/A')
                model = device.get(api_keys[1], 'N/A')
                serial = device.get(api_keys[2], 'N/A') # board-serial might be missing for vManages
                writer.writerow([hostname, model, serial])
                count += 1

        print(f"Successfully wrote {count} device records to {filename}.")
        return True

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
    # --outfile is now required for CSV output
    parser.add_argument("-o", "--outfile", required=True, help="Path for the output CSV file.")

    args = parser.parse_args()

    # --- IMPORTANT: SSL Verification is DISABLED for this script ---
    print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!! WARNING: SSL CERTIFICATE VERIFICATION DISABLED !!!")
    print("!!! This is insecure and should only be used     !!!")
    print("!!! in trusted environments or for testing.      !!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

    if not args.password:
        password = getpass.getpass(f"Enter password for user '{args.username}': ")
    else:
        password = args.password

    # --- Step 1: Login (SSL verification is implicitly disabled in the function) ---
    authenticated_session = vmanage_login(args.vmanage_ip, args.username, password)

    if not authenticated_session:
        print("\nExiting due to login failure.")
        sys.exit(1)

    # --- Step 2: Get Inventory (SSL verification is implicitly disabled) ---
    device_inventory = get_device_inventory(args.vmanage_ip, authenticated_session)

    if device_inventory is None:
        print("\nFailed to retrieve device inventory.")
        sys.exit(1)

    if not device_inventory:
        print("\nNo devices found in the inventory. Nothing to write to CSV.")
        sys.exit(0)

    # --- Step 3: Write to CSV ---
    if not write_inventory_to_csv(device_inventory, args.outfile):
        print("\nExiting due to CSV writing failure.")
        sys.exit(1)

    print("\nScript completed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()