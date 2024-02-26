import json
import hashlib
import socket
import threading
import datetime
import time
from typing import Dict

def load_licenses(file_path: str) -> Dict[str, int]:
    print("Loading licenses from", file_path)
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return {item['LicenceUserName']: item['ValidationTime'] for item in data['payload']}
    except FileNotFoundError:
        print("File not found:", file_path)
        return {}
    except json.JSONDecodeError:
        print("Error decoding JSON from file:", file_path)
        return {}

def generate_license_key(username: str) -> str:
    return hashlib.md5(username.encode()).hexdigest()

def handle_client(connection, address, licenses, active_licenses, active_connections):
    print("Handling client from", address)
    try:
        data = connection.recv(1024).decode()
        request = json.loads(data)
        username, client_key = request.get('LicenceUserName'), request.get('LicenceKey')
        
        if not username or not client_key:
            print("Invalid request received from", address)
            return
        
        server_key = generate_license_key(username)
        response = {'LicenceUserName': username, 'ServerLicenceKey': server_key}
        
        if server_key == client_key:
            validation_time = licenses.get(username)
            if validation_time is not None:
                expiry = datetime.datetime.now() + datetime.timedelta(seconds=validation_time) if validation_time > 0 else 'unlimited'
                active_licenses[username] = {'expiry': expiry}
                response.update({'Licence': True, 'Expired': expiry.isoformat() if expiry != 'unlimited' else expiry})
                print("Licence validated for", username)
            else:
                response.update({'Licence': False, 'Description': 'No valid license found for user'})
                print("No valid license found for", username)
        else:
            response.update({'Licence': False, 'Description': 'Invalid License Key'})
            print("Invalid license key for", username)
        
        connection.sendall(json.dumps(response).encode())
    except Exception as e:
        print("Error handling client", address, ":", e)
    finally:
        connection.close()

def monitor_licenses(active_licenses):
    while True:
        current_time = datetime.datetime.now()
        for username, details in list(active_licenses.items()):
            if details['expiry'] != 'unlimited' and details['expiry'] < current_time:
                print("License expired for", username)
                del active_licenses[username]
        time.sleep(10)  # Check every 10 seconds for expired licenses

def server_commands(server_socket, active_licenses, active_connections):
    while True:
        cmd = input("Enter command (status/stop): ").strip().lower()
        if cmd == "status":
            for username, details in active_licenses.items():
                print(username, "- Expires:", details['expiry'])
        elif cmd == "stop":
            print("Server shutting down...")
            server_socket.close()
            for connection in active_connections:
                connection.close()
            active_connections.clear()
            break

def start_server(port: int, licenses: Dict[str, int]):
    active_licenses = {}
    active_connections = []
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind(('', port))
        server_socket.listen()
        print("Server listening on port", port)

        # Start the license monitoring thread
        monitor_thread = threading.Thread(target=monitor_licenses, args=(active_licenses,))
        monitor_thread.daemon = True
        monitor_thread.start()

        # Start the command thread
        cmd_thread = threading.Thread(target=server_commands, args=(server_socket, active_licenses, active_connections))
        cmd_thread.daemon = True
        cmd_thread.start()

        while True:
            client_socket, address = server_socket.accept()
            active_connections.append(client_socket)
            print("Accepted connection from", address)
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address, licenses, active_licenses, active_connections))
            client_thread.start()
    except Exception as e:
        print("Server error:", e)
    finally:
        server_socket.close()
        print("Server socket closed.")

def main():
    licenses = load_licenses('licenses.json')
    while True:
        try:
            port = int(input("Enter the TCP port number for the server: "))
            if 0 < port < 65536:
                break
            else:
                print("Invalid port number. Please enter a number between 1 and 65535.")
        except ValueError:
            print("Invalid input. Please enter a valid port number.")
    start_server(port, licenses)

if __name__ == '__main__':
    main()
