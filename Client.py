import json
import hashlib
import socket
import threading
import datetime
import ipaddress
import time
from datetime import datetime

class LicenseClientAPI:
    def __init__(self):
        self.server_address = None
        self.license_username = None
        self.license_key = None
        self.token = None
        self.renewal_timer = None

    def start(self):
        while True:
            ip_address = input("Enter the server's IP address: ")
            try:
                ipaddress.ip_address(ip_address)
                break
            except ValueError:
                print("Invalid IP address. Please enter a valid IP address.")
        
        while True:
            port = int(input("Enter the server's TCP port: "))
            if port <= 0 or port > 65535:
                print("Invalid port number. Please enter a number between 1 and 65535.")
            else:
                break

        self.server_address = (ip_address, port)
        print(f"Server address set to {self.server_address}")

    def set_license(self):
        username = input("Enter the license username: ")
        key = hashlib.md5(username.encode()).hexdigest()
        self.license_username = username
        self.license_key = key
        print("License details set.")

    def get_license_token(self):
        if not self.token or self.is_token_expired():
            print("Requesting license token...")
            self.request_license_token()
        else:
            print("Current token is valid.")

    def request_license_token(self):
        def request_thread():
            try:
                if self.server_address is None:
                    print("Server address is not set. Please call start() method before requesting a license token.")
                    return
                print(f"Attempting to connect to {self.server_address}")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    try:
                        client_socket.connect(self.server_address)
                        print("Connection established.")
                        request_data = json.dumps({"LicenceUserName": self.license_username, "LicenceKey": self.license_key})
                        client_socket.sendall(request_data.encode('utf-8'))
                        response_data = client_socket.recv(1024)
                        response = json.loads(response_data.decode('utf-8'))
                        if 'Licence' in response and response['Licence']:
                            self.token = response
                            print("License token received:", self.token)
                            if response.get('Expired') != 'unlimited':
                                self.schedule_token_renewal(response.get('Expired'))
                        else:
                            self.token = {'Licence': False, 'Description': response.get('Description', 'License Error')}
                            print("Failed to obtain license token:", self.token['Description'])
                    except ConnectionRefusedError:
                        print("Connection failed: The target machine actively refused it.")
            except Exception as e:
                self.token = {'Licence': False, 'Description': f"Unexpected error: {e}"}
                print(self.token['Description'])

        threading.Thread(target=request_thread).start()

    def schedule_token_renewal(self, expiry_time):
        expiry_time = datetime.strptime(expiry_time, '%Y-%m-%dT%H:%M:%S.%f')
        now = datetime.utcnow()
        delay = (expiry_time - now).total_seconds()
        if delay > 0:
            if self.renewal_timer:
                self.renewal_timer.cancel()
            self.renewal_timer = threading.Timer(delay, self.request_license_token)
            self.renewal_timer.start()

    def is_token_expired(self):
        if self.token and 'Expired' in self.token:
            if self.token['Expired'] == 'unlimited':
                return False
            expiration_time = datetime.strptime(self.token['Expired'], "%Y-%m-%dT%H:%M:%S.%f")
            return expiration_time < datetime.utcnow()
        return True

    def get_remaining_time(self):
        if self.token and 'Expired' in self.token and self.token['Expired'] != 'unlimited':
            expiry_time = datetime.strptime(self.token['Expired'], '%Y-%m-%dT%H:%M:%S.%f')
            remaining_time = expiry_time - datetime.utcnow()
            return remaining_time
        return None

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
    client.start()
    client.set_license()

    client.get_license_token()
    time.sleep(2)  # Short delay to allow for asynchronous token request to complete

    while True:
        command = input("Enter 'gettoken' to check token validity or 'stop' to exit: ")
        if command == "gettoken":
            client.get_license_token()
        elif command == "stop":
            client.stop()
            break
