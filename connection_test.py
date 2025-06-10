import socket
import subprocess
import sys
import os
import platform
import psutil
import requests
import json
import time
from datetime import datetime
import logging
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import dns.resolver
import speedtest
import netifaces
import scapy.all as scapy
from scapy.layers import http

class ConnectionTester:
    def __init__(self):
        self.setup_logging()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'server_status': {},
            'network_config': {},
            'firewall_status': {},
            'dns_status': {},
            'proxy_status': {},
            'traffic_analysis': {},
            'issues': []
        }
        self.traffic_monitor = None
        self.is_monitoring = False
        
    def setup_logging(self):
        log_path = Path('logs')
        log_path.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path / 'connection_test.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def check_server_status(self, host='localhost', port=5000):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                result = s.connect_ex((host, port))
                self.results['server_status'] = {
                    'is_running': result == 0,
                    'error_code': result,
                    'host': host,
                    'port': port
                }
                if result != 0:
                    self.results['issues'].append(f"Server not running on {host}:{port}")
        except Exception as e:
            self.results['server_status'] = {
                'is_running': False,
                'error': str(e)
            }
            self.results['issues'].append(f"Error checking server: {str(e)}")

    def check_network_config(self):
        try:
            # Get all network interfaces
            interfaces = psutil.net_if_addrs()
            self.results['network_config']['interfaces'] = {}
            
            for interface, addrs in interfaces.items():
                self.results['network_config']['interfaces'][interface] = []
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        self.results['network_config']['interfaces'][interface].append({
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
            
            # Check default gateway
            if platform.system() == 'Windows':
                output = subprocess.check_output('ipconfig', shell=True).decode()
                self.results['network_config']['gateway'] = output
            else:
                output = subprocess.check_output('ip route', shell=True).decode()
                self.results['network_config']['gateway'] = output
                
        except Exception as e:
            self.results['issues'].append(f"Error checking network config: {str(e)}")

    def check_dns_resolution(self):
        try:
            resolver = dns.resolver.Resolver()
            domains = ['google.com', 'cloudflare.com', 'github.com']
            results = {}
            
            for domain in domains:
                try:
                    answers = resolver.resolve(domain, 'A')
                    results[domain] = {
                        'resolved': True,
                        'ips': [str(rdata) for rdata in answers],
                        'nameservers': [str(ns) for ns in resolver.nameservers]
                    }
                except Exception as e:
                    results[domain] = {
                        'resolved': False,
                        'error': str(e)
                    }
                    self.results['issues'].append(f"DNS resolution failed for {domain}: {str(e)}")
            
            self.results['dns_status'] = results
        except Exception as e:
            self.results['issues'].append(f"Error checking DNS: {str(e)}")

    def check_proxy(self):
        try:
            # Check system proxy settings
            if platform.system() == 'Windows':
                output = subprocess.check_output(
                    'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"',
                    shell=True
                ).decode()
                self.results['proxy_status']['system_settings'] = output
            else:
                self.results['proxy_status']['system_settings'] = "Not Windows"

            # Check environment variables
            proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']
            env_proxies = {}
            for var in proxy_vars:
                if var in os.environ:
                    env_proxies[var] = os.environ[var]
            self.results['proxy_status']['environment_variables'] = env_proxies

            # Test connection through proxy
            try:
                response = requests.get('http://httpbin.org/ip')
                self.results['proxy_status']['public_ip'] = response.json()['origin']
            except Exception as e:
                self.results['issues'].append(f"Error checking public IP: {str(e)}")

        except Exception as e:
            self.results['issues'].append(f"Error checking proxy: {str(e)}")

    def start_traffic_monitoring(self):
        if self.is_monitoring:
            return

        self.is_monitoring = True
        self.traffic_monitor = threading.Thread(target=self._monitor_traffic)
        self.traffic_monitor.daemon = True
        self.traffic_monitor.start()

    def stop_traffic_monitoring(self):
        self.is_monitoring = False
        if self.traffic_monitor:
            self.traffic_monitor.join()

    def _monitor_traffic(self):
        try:
            def packet_callback(packet):
                if packet.haslayer(http.HTTPRequest):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    method = packet[http.HTTPRequest].Method.decode()
                    path = packet[http.HTTPRequest].Path.decode()
                    
                    if 'traffic' not in self.results['traffic_analysis']:
                        self.results['traffic_analysis']['traffic'] = []
                    
                    self.results['traffic_analysis']['traffic'].append({
                        'timestamp': datetime.now().isoformat(),
                        'source': src_ip,
                        'destination': dst_ip,
                        'method': method,
                        'path': path
                    })

            scapy.sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self.is_monitoring)
        except Exception as e:
            self.results['issues'].append(f"Error monitoring traffic: {str(e)}")

    def check_firewall(self):
        try:
            if platform.system() == 'Windows':
                # Check Windows Firewall status
                output = subprocess.check_output(
                    'netsh advfirewall show currentprofile',
                    shell=True
                ).decode()
                
                self.results['firewall_status']['windows'] = {
                    'status': 'ON' in output,
                    'details': output
                }
                
                # Check all firewall rules
                output = subprocess.check_output(
                    'netsh advfirewall firewall show rule name=all',
                    shell=True
                ).decode()
                
                self.results['firewall_status']['all_rules'] = output
                
                # Check specific rules for Python and port 5000
                python_rules = subprocess.check_output(
                    'netsh advfirewall firewall show rule name=all | findstr "Python"',
                    shell=True
                ).decode()
                
                port_rules = subprocess.check_output(
                    'netsh advfirewall firewall show rule name=all | findstr "5000"',
                    shell=True
                ).decode()
                
                self.results['firewall_status']['python_rules'] = python_rules
                self.results['firewall_status']['port_rules'] = port_rules
                
                if not python_rules:
                    self.results['issues'].append("Python not found in firewall rules")
                if not port_rules:
                    self.results['issues'].append("Port 5000 not found in firewall rules")
            else:
                self.results['firewall_status']['status'] = "Not Windows"
                
        except Exception as e:
            self.results['issues'].append(f"Error checking firewall: {str(e)}")

    def attempt_fix(self):
        fixes = []
        try:
            if platform.system() == 'Windows':
                # Add Python to firewall
                python_path = sys.executable
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="Python" dir=in action=allow program="{python_path}" enable=yes',
                    shell=True
                )
                fixes.append("Added Python to Windows Firewall")
                
                # Add port 5000 to firewall
                subprocess.run(
                    'netsh advfirewall firewall add rule name="Port 5000" dir=in action=allow protocol=TCP localport=5000',
                    shell=True
                )
                fixes.append("Added port 5000 to Windows Firewall")
                
                # Add outbound rules
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="Python Out" dir=out action=allow program="{python_path}" enable=yes',
                    shell=True
                )
                fixes.append("Added Python outbound rule to Windows Firewall")
                
                subprocess.run(
                    'netsh advfirewall firewall add rule name="Port 5000 Out" dir=out action=allow protocol=TCP localport=5000',
                    shell=True
                )
                fixes.append("Added port 5000 outbound rule to Windows Firewall")
                
        except Exception as e:
            self.results['issues'].append(f"Error applying fixes: {str(e)}")
            
        return fixes

    def run_tests(self):
        self.check_server_status()
        self.check_network_config()
        self.check_firewall()
        self.check_dns_resolution()
        self.check_proxy()
        self.start_traffic_monitoring()
        return self.results

class ConnectionTesterGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Connection Tester")
        self.root.geometry("1000x800")
        
        self.tester = ConnectionTester()
        self.setup_gui()
        
    def setup_gui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Add test button
        test_button = ttk.Button(main_frame, text="Run Tests", command=self.run_tests)
        test_button.grid(row=0, column=0, pady=5)
        
        # Add fix button
        fix_button = ttk.Button(main_frame, text="Attempt Fixes", command=self.attempt_fixes)
        fix_button.grid(row=0, column=1, pady=5)
        
        # Add stop monitoring button
        stop_button = ttk.Button(main_frame, text="Stop Monitoring", command=self.stop_monitoring)
        stop_button.grid(row=0, column=2, pady=5)
        
        # Add results text area
        self.results_text = scrolledtext.ScrolledText(main_frame, width=100, height=40)
        self.results_text.grid(row=1, column=0, columnspan=3, pady=5)
        
    def run_tests(self):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Running tests...\n\n")
        
        def run_tests_thread():
            results = self.tester.run_tests()
            
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "Test Results:\n\n")
            
            # Server Status
            self.results_text.insert(tk.END, "Server Status:\n")
            self.results_text.insert(tk.END, f"Running: {results['server_status'].get('is_running', False)}\n")
            if 'error' in results['server_status']:
                self.results_text.insert(tk.END, f"Error: {results['server_status']['error']}\n")
            self.results_text.insert(tk.END, "\n")
            
            # Network Config
            self.results_text.insert(tk.END, "Network Configuration:\n")
            for interface, addrs in results['network_config'].get('interfaces', {}).items():
                self.results_text.insert(tk.END, f"\nInterface: {interface}\n")
                for addr in addrs:
                    self.results_text.insert(tk.END, f"  IP: {addr['address']}\n")
            self.results_text.insert(tk.END, "\n")
            
            # DNS Status
            self.results_text.insert(tk.END, "DNS Resolution:\n")
            for domain, status in results['dns_status'].items():
                self.results_text.insert(tk.END, f"\n{domain}:\n")
                if status['resolved']:
                    self.results_text.insert(tk.END, f"  IPs: {', '.join(status['ips'])}\n")
                else:
                    self.results_text.insert(tk.END, f"  Error: {status['error']}\n")
            self.results_text.insert(tk.END, "\n")
            
            # Proxy Status
            self.results_text.insert(tk.END, "Proxy Status:\n")
            if 'public_ip' in results['proxy_status']:
                self.results_text.insert(tk.END, f"Public IP: {results['proxy_status']['public_ip']}\n")
            self.results_text.insert(tk.END, "\n")
            
            # Firewall Status
            self.results_text.insert(tk.END, "Firewall Status:\n")
            if 'windows' in results['firewall_status']:
                self.results_text.insert(tk.END, f"Windows Firewall: {'ON' if results['firewall_status']['windows']['status'] else 'OFF'}\n")
            self.results_text.insert(tk.END, "\n")
            
            # Issues
            if results['issues']:
                self.results_text.insert(tk.END, "Issues Found:\n")
                for issue in results['issues']:
                    self.results_text.insert(tk.END, f"- {issue}\n")
            
        threading.Thread(target=run_tests_thread).start()
        
    def attempt_fixes(self):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Attempting fixes...\n\n")
        
        def fix_thread():
            fixes = self.tester.attempt_fix()
            
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "Fix Results:\n\n")
            
            if fixes:
                for fix in fixes:
                    self.results_text.insert(tk.END, f"- {fix}\n")
            else:
                self.results_text.insert(tk.END, "No fixes were applied.\n")
                
        threading.Thread(target=fix_thread).start()
        
    def stop_monitoring(self):
        self.tester.stop_traffic_monitoring()
        self.results_text.insert(tk.END, "\nTraffic monitoring stopped.\n")
        
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    gui = ConnectionTesterGUI()
    gui.run() 