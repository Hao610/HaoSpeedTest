import socket
import subprocess
import sys
import os
import platform
import psutil
import requests
from datetime import datetime

def check_port(port):
    """Check if a port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return True
        except socket.error:
            return False

def get_available_port(start_port=5000, max_port=5100):
    """Find an available port"""
    for port in range(start_port, max_port):
        if check_port(port):
            return port
    return None

def check_firewall():
    """Check firewall status"""
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'currentprofile'], 
                                 capture_output=True, text=True)
            return "ON" in result.stdout
        except:
            return "Unknown"
    return "Not Windows"

def check_network():
    """Check network connectivity"""
    try:
        requests.get("http://www.google.com", timeout=5)
        return True
    except:
        return False

def get_network_info():
    """Get network interface information"""
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces.append({
                    'interface': interface,
                    'address': addr.address,
                    'netmask': addr.netmask
                })
    return interfaces

def run_diagnostics():
    print("\n=== Network Diagnostics ===")
    print(f"Timestamp: {datetime.now()}")
    print(f"Python Version: {sys.version}")
    print(f"Operating System: {platform.system()} {platform.release()}")
    
    print("\n=== Port Check ===")
    port = 5000
    if check_port(port):
        print(f"Port {port} is available")
    else:
        print(f"Port {port} is in use")
        new_port = get_available_port()
        if new_port:
            print(f"Suggested alternative port: {new_port}")
    
    print("\n=== Firewall Status ===")
    firewall_status = check_firewall()
    print(f"Firewall is {firewall_status}")
    
    print("\n=== Network Connectivity ===")
    if check_network():
        print("Internet connection: OK")
    else:
        print("Internet connection: Failed")
    
    print("\n=== Network Interfaces ===")
    for interface in get_network_info():
        print(f"Interface: {interface['interface']}")
        print(f"  IP Address: {interface['address']}")
        print(f"  Netmask: {interface['netmask']}")
    
    print("\n=== Recommendations ===")
    if not check_port(5000):
        print("1. Change the port number in run.py to an available port")
    if firewall_status == "ON":
        print("2. Check Windows Firewall settings for Python")
    if not check_network():
        print("3. Check your internet connection")
    
    print("\n=== End of Diagnostics ===\n")

if __name__ == "__main__":
    run_diagnostics() 