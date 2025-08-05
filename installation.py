#!/usr/bin/env python3

import subprocess
import sys
import platform

def test_go_installation():
    """Test Go tool installation with the fixed methods"""
    print("Testing Go tool installation fixes...")
    
    # Test amass installation
    print("\n1. Testing amass installation...")
    try:
        # Try the fixed version first
        cmd = ["go", "install", "github.com/owasp-amass/amass/v3/...@master"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print("✅ amass installed successfully with fixed method")
        else:
            print(f"⚠️ amass failed with fixed method: {result.stderr}")
            # Try alternative
            alt_cmd = ["go", "install", "github.com/owasp-amass/amass/v3/...@v3.23.3"]
            alt_result = subprocess.run(alt_cmd, capture_output=True, text=True, timeout=60)
            if alt_result.returncode == 0:
                print("✅ amass installed successfully with alternative method")
            else:
                print(f"⚠️ amass alternative also failed: {alt_result.stderr}")
    except Exception as e:
        print(f"❌ amass installation error: {str(e)}")
    
    # Test aquatone installation
    print("\n2. Testing aquatone installation...")
    try:
        # Try the fixed version first
        cmd = ["go", "install", "github.com/michenriksen/aquatone@v1.6.0"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print("✅ aquatone installed successfully with fixed method")
        else:
            print(f"⚠️ aquatone failed with fixed method: {result.stderr}")
            # Try alternative
            alt_cmd = ["go", "install", "github.com/michenriksen/aquatone@v1.7.0"]
            alt_result = subprocess.run(alt_cmd, capture_output=True, text=True, timeout=60)
            if alt_result.returncode == 0:
                print("✅ aquatone installed successfully with alternative method")
            else:
                print(f"⚠️ aquatone alternative also failed: {alt_result.stderr}")
    except Exception as e:
        print(f"❌ aquatone installation error: {str(e)}")

def test_windows_tools():
    """Test Windows system tools installation"""
    if platform.system() == "Windows":
        print("\n3. Testing Windows system tools installation...")
        
        # Test nmap installation
        print("\nTesting nmap installation...")
        
        # Try to find winget using full path
        winget_paths = [
            "winget",  # Try PATH first
            r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.26.430.0_x64__8wekyb3d8bbwe\winget.exe",
            r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe"
        ]
        
        winget_found = False
        winget_executable = None
        
        for winget_path in winget_paths:
            try:
                if winget_path == "winget":
                    subprocess.run([winget_path, "--version"], capture_output=True, check=True, timeout=10)
                else:
                    # Use PowerShell to handle wildcards and find the actual path
                    if "*" in winget_path:
                        ps_cmd = f'Get-ChildItem "{winget_path}" | Select-Object -First 1 | ForEach-Object {{ $_.FullName }}'
                        result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=10)
                        if result.returncode == 0 and result.stdout.strip():
                            actual_winget_path = result.stdout.strip()
                            subprocess.run([actual_winget_path, "--version"], capture_output=True, check=True, timeout=10)
                            winget_executable = actual_winget_path
                        else:
                            continue
                    else:
                        subprocess.run([winget_path, "--version"], capture_output=True, check=True, timeout=10)
                        winget_executable = winget_path
                winget_found = True
                break
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        if winget_found and winget_executable:
            try:
                # Try winget first
                cmd = [winget_executable, "install", "nmap.nmap", "--accept-source-agreements"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    print("✅ nmap installed successfully via winget")
                else:
                    print(f"⚠️ nmap winget failed: {result.stderr}")
                    # Try chocolatey
                    try:
                        choco_cmd = ["choco", "install", "nmap", "-y"]
                        choco_result = subprocess.run(choco_cmd, capture_output=True, text=True, timeout=120)
                        if choco_result.returncode == 0:
                            print("✅ nmap installed successfully via chocolatey")
                        else:
                            print(f"⚠️ nmap chocolatey also failed: {choco_result.stderr}")
                    except FileNotFoundError:
                        print("⚠️ chocolatey not available")
            except Exception as e:
                print(f"⚠️ winget installation error: {str(e)}")
        else:
            print("⚠️ winget not available")
        
        # Test whois installation
        print("\nTesting whois installation...")
        
        if winget_found and winget_executable:
            try:
                # Try winget first
                cmd = [winget_executable, "install", "Microsoft.Sysinternals.Whois", "--accept-source-agreements"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    print("✅ whois installed successfully via winget")
                else:
                    print(f"⚠️ whois winget failed: {result.stderr}")
                    # Try chocolatey
                    try:
                        choco_cmd = ["choco", "install", "sysinternals", "-y"]
                        choco_result = subprocess.run(choco_cmd, capture_output=True, text=True, timeout=120)
                        if choco_result.returncode == 0:
                            print("✅ whois installed successfully via chocolatey")
                        else:
                            print(f"⚠️ whois chocolatey also failed: {choco_result.stderr}")
                    except FileNotFoundError:
                        print("⚠️ chocolatey not available")
            except Exception as e:
                print(f"⚠️ winget installation error: {str(e)}")
        else:
            print("⚠️ winget not available")

def main():
    print("🔧 Testing Tool Installation Fixes")
    print("=" * 50)
    
    # Check if Go is available
    try:
        result = subprocess.run(["go", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Go is available: {result.stdout.strip()}")
        else:
            print("❌ Go is not available")
            return
    except FileNotFoundError:
        print("❌ Go is not installed")
        return
    
    test_go_installation()
    test_windows_tools()
    
    print("\n🎉 Installation test completed!")

if __name__ == "__main__":
    main() 