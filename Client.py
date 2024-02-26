import json
import hashlib
import socket
import threading
import datetime
import ipaddress
import time
from datetime import datetime

class LicenseClientAPI:
    # Initialize the client with no server address, license details, or token.
    def __init__(self):
        self.server_address = None  # Server IP and port
        self.license_username = None  # Username for the license
        self.license_key = None  # License key generated using the username
        self.token = None  # Token received from the server
        self.renewal_timer = None  # Timer for automatic token renewal

    # Set up the server address by validating the IP and port input.
    def start(self):
        while True:
            ip_address = input("Enter the server's IP address: ")
            try:
                ipaddress.ip_address(ip_address)  # Validate the IP address
                break
            except ValueError:
                print("Invalid IP address. Please enter a valid IP address.")
        
        while True:
            port = int(input("Enter the server's TCP port: "))
            if port <= 0 or port > 65535:
                print("Invalid port number. Please enter a number between 1 and 65535.")
            else:
                break

        self.server_address = (ip_address, port)  # Set the server address
        print(f"Server address set to {self.server_address}")

    # Set the license details by getting the username and generating a key.
    def set_license(self):
        username = input("Enter the license username: ")
        key = hashlib.md5(username.encode()).hexdigest()  # Generate license key using MD5
        self.license_username = username
        self.license_key = key
        print("License details set.")

    # Request or renew the license token if it's invalid or expired.
    def get_license_token(self):
        if not self.token or self.is_token_expired():
            print("Token is invalid or expired. Requesting a new license token...")
            self.request_license_token()  # Request a new token

            request_timeout = 10  # seconds
            start_time = time.time()
            while not self.token and (time.time() - start_time) < request_timeout:
                time.sleep(0.1)  # Wait for the token to be updated

            if not self.token:
                self.token = {'Licence': False, 'Description': 'Failed to obtain license token within timeout.'}
                print(self.token['Description'])
                return self.token

        if self.token['Licence']:
            print("Current token is valid.")
        else:
            print("Failed to obtain license token:", self.token['Description'])

        return self.token

    # Internal method to request a license token from the server in a separate thread.
    def request_license_token(self):
        def request_thread():
            try:
                if self.server_address is None:
                    print("Server address is not set. Please call start() method before requesting a license token.")
                    return
                print(f"Attempting to connect to {self.server_address}")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    client_socket.connect(self.server_address)
                    print("Connection established.")
                    request_data = json.dumps({"LicenceUserName": self.license_username, "LicenceKey": self.license_key})
                    client_socket.sendall(request_data.encode('utf-8'))
                    response_data = client_socket.recv(1024)
                    response = json.loads(response_data.decode('utf-8'))
                    if 'Licence' in response and response['Licence']:
                        self.token = response  # Update the token
                        print("License token received:", self.token)
                        if response.get('Expired') != 'unlimited':
                            self.schedule_token_renewal(response.get('Expired'))  # Schedule renewal
                    else:
                        self.token = {'Licence': False, 'Description': response.get('Description', 'License Error')}
                        print("Failed to obtain license token:", self.token['Description'])
            except ConnectionRefusedError:
                print("Connection failed: The target machine actively refused it.")
            except Exception as e:
                self.token = {'Licence': False, 'Description': f"Unexpected error: {e}"}
                print(self.token['Description'])

        threading.Thread(target=request_thread).start()  # Start the request in a new thread

    # Schedule the renewal of the token before it expires.
    def schedule_token_renewal(self, expiry_time):
        expiry_time = datetime.strptime(expiry_time, '%Y-%m-%dT%H:%M:%S.%f')
        now = datetime.utcnow()
        delay = (expiry_time - now).total_seconds()
        if delay > 0:
            if self.renewal_timer:
                self.renewal_timer.cancel()
            self.renewal_timer = threading.Timer(delay, self.request_license_token)
            self.renewal_timer.start()

    # Check if the current token is expired.
    def is_token_expired(self):
        if self.token and 'Expired' in self.token:
            if self.token['Expired'] == 'unlimited':
                return False
            expiration_time = datetime.strptime(self.token['Expired'], "%Y-%m-%dT%H:%M:%S.%f")
            return expiration_time < datetime.utcnow()
        return True

    # Calculate the remaining time until the token expires.
    def get_remaining_time(self):
        if self.token and 'Expired' in self.token and self.token['Expired'] != 'unlimited':
            expiry_time = datetime.strptime(self.token['Expired'], '%Y-%m-%dT%H:%M:%S.%f')
            remaining_time = expiry_time - datetime.utcnow()
            return remaining_time
        return None

    # Stop the client and cancel any renewal timer.
    def stop(self):
        if self.renewal_timer:
            self.renewal_timer.cancel()
        self.server_address = None
        self.license_username = None
        self.license_key = None
        self.token = None
        print("Client stopped.")

if __name__ == "__main__":
    client = LicenseClientAPI()
    client.start()  # Initialize the client by setting the server's address
    client.set_license()  # Set the license details

    client.get_license_token()  # Request or renew the license token
    time.sleep(2)  # Wait a bit for the token request to complete

    # Allow the user to check the token's validity or stop the client
    while True:
        command = input("Enter 'gettoken' to check token validity or 'stop' to exit: ")
        if command == "gettoken":
            client.get_license_token()
        elif command == "stop":
            client.stop()
            break
