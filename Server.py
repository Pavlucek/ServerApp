import json
import hashlib
import socket
import threading
import datetime
import time
from typing import Dict

# Flag to control the server's main loop and threads.
should_continue = threading.Event()

def load_licenses(file_path: str) -> Dict[str, int]:
    """Load license information from a JSON file."""
    print("Loading licenses from", file_path)
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        # Return a dictionary with LicenceUserName as key and ValidationTime as value.
        return {item['LicenceUserName']: item['ValidationTime'] for item in data['payload']}
    except FileNotFoundError:
        print("File not found:", file_path)
        return {}
    except json.JSONDecodeError:
        print("Error decoding JSON from file:", file_path)
        return {}

def generate_license_key(username: str) -> str:
    """Generate a license key using MD5 hash of the username."""
    return hashlib.md5(username.encode()).hexdigest()

def handle_client(connection, address, licenses, active_licenses, active_connections):
    """Handle incoming client connections and validate their license requests."""
    print("Handling client from", address)
    try:
        data = connection.recv(1024).decode()
        request = json.loads(data)
        username, client_key = request.get('LicenceUserName'), request.get('LicenceKey')
        
        if not username or not client_key:
            print("Invalid request received from", address)
            return
        
        # Generate server's version of the license key to compare with client's key.
        server_key = generate_license_key(username)
        response = {'LicenceUserName': username, 'ServerLicenceKey': server_key}
        
        # Validate the license key and check the license status.
        if server_key == client_key:
            if username in active_licenses:
                # License is already in use by the same user.
                response.update({'Licence': False, 'Description': 'Licence is already in use'})
                print("Licence for", username, "is already in use")
            elif username in licenses:
                # License is valid, calculate expiry and update active licenses.
                validation_time = licenses[username]
                expiry = datetime.datetime.now() + datetime.timedelta(seconds=validation_time) if validation_time > 0 else 'unlimited'
                active_licenses[username] = {'expiry': expiry}
                response.update({'Licence': True, 'Expired': expiry.isoformat() if expiry != 'unlimited' else expiry})
                print("Licence validated for", username)
            else:
                # No valid license found for the user.
                response.update({'Licence': False, 'Description': 'No valid license found for user'})
                print("No valid license found for", username)
        else:
            # Client's license key does not match the server's key.
            response.update({'Licence': False, 'Description': 'Invalid License Key'})
            print("Invalid license key for", username)
        
        # Send the response back to the client.
        connection.sendall(json.dumps(response).encode())
    except Exception as e:
        print("Error handling client", address, ":", e)
    finally:
        # Ensure the connection is closed after handling the request.
        connection.close()

def monitor_licenses(active_licenses):
    """Monitor active licenses and remove expired ones."""
    while True:
        current_time = datetime.datetime.now()
        for username, details in list(active_licenses.items()):
            if details['expiry'] != 'unlimited' and details['expiry'] < current_time:
                # License has expired, remove it from active licenses.
                print("License expired for", username)
                del active_licenses[username]
        # Check for expired licenses every 10 seconds.
        time.sleep(10)

def server_commands(server_socket, active_licenses, active_connections):
    """Handle server commands like 'status' and 'stop'."""
    while True:
        cmd = input("Enter command (status/stop): ").strip().lower()
        if cmd == "status":
            # Display the status of active licenses.
            for username, details in active_licenses.items():
                print(username, "- Expires:", details['expiry'])
        elif cmd == "stop":
            # Stop the server and clean up resources.
            print("Server shutting down...")
            should_continue.clear()
            server_socket.close()
            for connection in active_connections:
                connection.close()
            active_connections.clear()
            break

def close_all_connections(active_connections):
    """Safely close all active client connections."""
    for conn in active_connections:
        try:
            conn.close()
        except Exception as e:
            print(f"Error closing connection: {e}")

def start_server(port: int, licenses: Dict[str, int]):
    """Start the server, listen for connections, and handle commands."""
    active_licenses = {}
    active_connections = []
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', port))
    server_socket.listen()
    server_socket.settimeout(1)  # Set a timeout for the server socket to periodically check the should_continue flag.
    print(f"Server listening on port {port}")

    # Start the command handling thread.
    cmd_thread = threading.Thread(target=server_commands, args=(server_socket, active_licenses, active_connections,))
    cmd_thread.daemon = True
    cmd_thread.start()

    # Start the license monitoring thread.
    monitor_thread = threading.Thread(target=monitor_licenses, args=(active_licenses,))
    monitor_thread.daemon = True
    monitor_thread.start()

    while True:
        try:
            client_socket, address = server_socket.accept()
            active_connections.append(client_socket)
            print(f"Accepted connection from {address}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address, licenses, active_licenses, active_connections))
            client_thread.start()
        except socket.timeout:
            continue  # If the socket times out, just continue the loop.
        except KeyboardInterrupt:
            print("Server interrupted. Shutting down...")
            break
        except OSError as e:
            print(f"Socket error: {e}")
            break

def main():
    """Load licenses and start the server."""
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
