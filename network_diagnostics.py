import socket
import subprocess
import psutil
import requests
import json
import logging
import os
import platform
import time
from datetime import datetime
from typing import Dict, List, Any
import dns.resolver
import speedtest
import netifaces
from scapy.all import sniff, IP, TCP, UDP
import threading
import queue

class NetworkDiagnostics:
    def __init__(self):
        self.setup_logging()
        self.results = {}
        self.traffic_data = queue.Queue()
        self.stop_monitoring = False

    def setup_logging(self):
        """Set up logging configuration"""
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        logging.basicConfig(
            filename='logs/network_diagnostics.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def check_system_info(self) -> Dict[str, Any]:
        """Check system information"""
        try:
            info = {
                'os': platform.system(),
                'os_version': platform.version(),
                'python_version': platform.python_version(),
                'hostname': socket.gethostname(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available
            }
            logging.info(f"System info collected: {info}")
            return info
        except Exception as e:
            logging.error(f"Error collecting system info: {str(e)}")
            return {}

    def check_network_interfaces(self) -> List[Dict[str, Any]]:
        """Check network interfaces with detailed information"""
        interfaces = []
        try:
            for interface, addrs in netifaces.interfaces().items():
                interface_info = {
                    'name': interface,
                    'addresses': addrs,
                    'status': 'up' if netifaces.AF_INET in addrs else 'down',
                    'mac_address': netifaces.ifaddresses(interface).get(netifaces.AF_LINK, [{}])[0].get('addr', ''),
                    'ipv4': netifaces.ifaddresses(interface).get(netifaces.AF_INET, [{}])[0].get('addr', ''),
                    'netmask': netifaces.ifaddresses(interface).get(netifaces.AF_INET, [{}])[0].get('netmask', ''),
                    'broadcast': netifaces.ifaddresses(interface).get(netifaces.AF_INET, [{}])[0].get('broadcast', '')
                }
                interfaces.append(interface_info)
            logging.info(f"Network interfaces checked: {len(interfaces)} found")
            return interfaces
        except Exception as e:
            logging.error(f"Error checking network interfaces: {str(e)}")
            return []

    def check_connectivity(self) -> Dict[str, Any]:
        """Check connectivity to various endpoints"""
        endpoints = {
            'localhost': '127.0.0.1',
            'google': '8.8.8.8',
            'dns': '8.8.4.4',
            'cloudflare': '1.1.1.1'
        }
        results = {}
        
        for name, ip in endpoints.items():
            try:
                start_time = time.time()
                socket.create_connection((ip, 80), timeout=5)
                latency = (time.time() - start_time) * 1000
                results[name] = {
                    'status': 'connected',
                    'latency_ms': round(latency, 2)
                }
            except Exception as e:
                results[name] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        logging.info(f"Connectivity check completed: {results}")
        return results

    def check_dns_resolution(self) -> Dict[str, Any]:
        """Check DNS resolution for various domains"""
        domains = ['google.com', 'github.com', 'cloudflare.com']
        results = {}
        
        for domain in domains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                
                start_time = time.time()
                answers = resolver.resolve(domain, 'A')
                latency = (time.time() - start_time) * 1000
                
                results[domain] = {
                    'status': 'resolved',
                    'ip_addresses': [str(rdata) for rdata in answers],
                    'latency_ms': round(latency, 2)
                }
            except Exception as e:
                results[domain] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        logging.info(f"DNS resolution check completed: {results}")
        return results

    def check_speed(self) -> Dict[str, Any]:
        """Check internet speed using speedtest-cli"""
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            ping = st.results.ping
            
            results = {
                'download_speed_mbps': round(download_speed, 2),
                'upload_speed_mbps': round(upload_speed, 2),
                'ping_ms': round(ping, 2),
                'server': st.results.server['host']
            }
            logging.info(f"Speed test completed: {results}")
            return results
        except Exception as e:
            logging.error(f"Error during speed test: {str(e)}")
            return {'error': str(e)}

    def check_firewall(self) -> Dict[str, Any]:
        """Check firewall status and rules"""
        try:
            if platform.system() == 'Windows':
                # Check Windows Firewall status
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                    capture_output=True,
                    text=True
                )
                firewall_status = result.stdout
                
                # Check specific rules
                rules_result = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                    capture_output=True,
                    text=True
                )
                firewall_rules = rules_result.stdout
                
                return {
                    'status': 'checked',
                    'firewall_status': firewall_status,
                    'rules': firewall_rules
                }
            else:
                # Check iptables for Linux
                result = subprocess.run(
                    ['iptables', '-L'],
                    capture_output=True,
                    text=True
                )
                return {
                    'status': 'checked',
                    'rules': result.stdout
                }
        except Exception as e:
            logging.error(f"Error checking firewall: {str(e)}")
            return {'error': str(e)}

    def monitor_traffic(self, duration: int = 60):
        """Monitor network traffic for specified duration"""
        def packet_callback(packet):
            if IP in packet:
                traffic_info = {
                    'timestamp': datetime.now().isoformat(),
                    'source': packet[IP].src,
                    'destination': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet)
                }
                if TCP in packet:
                    traffic_info['sport'] = packet[TCP].sport
                    traffic_info['dport'] = packet[TCP].dport
                elif UDP in packet:
                    traffic_info['sport'] = packet[UDP].sport
                    traffic_info['dport'] = packet[UDP].dport
                
                self.traffic_data.put(traffic_info)

        try:
            # Start packet capture in a separate thread
            capture_thread = threading.Thread(
                target=sniff,
                kwargs={
                    'prn': packet_callback,
                    'store': 0,
                    'timeout': duration
                }
            )
            capture_thread.start()
            capture_thread.join()
            
            # Process collected traffic data
            traffic_results = []
            while not self.traffic_data.empty():
                traffic_results.append(self.traffic_data.get())
            
            logging.info(f"Traffic monitoring completed: {len(traffic_results)} packets captured")
            return traffic_results
        except Exception as e:
            logging.error(f"Error monitoring traffic: {str(e)}")
            return []

    def run_all_tests(self) -> Dict[str, Any]:
        """Run all diagnostic tests"""
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'system_info': self.check_system_info(),
            'network_interfaces': self.check_network_interfaces(),
            'connectivity': self.check_connectivity(),
            'dns_resolution': self.check_dns_resolution(),
            'speed_test': self.check_speed(),
            'firewall': self.check_firewall(),
            'traffic_monitoring': self.monitor_traffic(duration=30)
        }
        
        # Save results to file
        with open('network_diagnostics_results.json', 'w') as f:
            json.dump(self.results, f, indent=4)
        
        logging.info("All diagnostic tests completed")
        return self.results

    def analyze_results(self) -> Dict[str, Any]:
        """Analyze test results and provide recommendations"""
        analysis = {
            'issues': [],
            'recommendations': []
        }
        
        # Check connectivity issues
        for endpoint, result in self.results.get('connectivity', {}).items():
            if result.get('status') == 'failed':
                analysis['issues'].append(f"Connection to {endpoint} failed")
                analysis['recommendations'].append(f"Check network configuration for {endpoint}")
        
        # Check DNS issues
        for domain, result in self.results.get('dns_resolution', {}).items():
            if result.get('status') == 'failed':
                analysis['issues'].append(f"DNS resolution failed for {domain}")
                analysis['recommendations'].append("Check DNS server configuration")
        
        # Check speed issues
        speed_test = self.results.get('speed_test', {})
        if speed_test:
            if speed_test.get('download_speed_mbps', 0) < 5:
                analysis['issues'].append("Low download speed detected")
                analysis['recommendations'].append("Contact your ISP for speed issues")
            if speed_test.get('upload_speed_mbps', 0) < 1:
                analysis['issues'].append("Low upload speed detected")
                analysis['recommendations'].append("Check upload bandwidth allocation")
        
        # Check firewall issues
        firewall = self.results.get('firewall', {})
        if firewall.get('error'):
            analysis['issues'].append("Firewall check failed")
            analysis['recommendations'].append("Verify firewall configuration and permissions")
        
        logging.info(f"Analysis completed: {len(analysis['issues'])} issues found")
        return analysis

def main():
    """Main function to run diagnostics"""
    print("Starting network diagnostics...")
    diagnostics = NetworkDiagnostics()
    
    # Run all tests
    results = diagnostics.run_all_tests()
    
    # Analyze results
    analysis = diagnostics.analyze_results()
    
    # Print summary
    print("\nDiagnostic Summary:")
    print("------------------")
    print(f"System: {results['system_info']['os']} {results['system_info']['os_version']}")
    print(f"Hostname: {results['system_info']['hostname']}")
    
    print("\nNetwork Interfaces:")
    for interface in results['network_interfaces']:
        print(f"- {interface['name']}: {interface['ipv4']} ({interface['status']})")
    
    print("\nConnectivity:")
    for endpoint, result in results['connectivity'].items():
        status = "✓" if result['status'] == 'connected' else "✗"
        print(f"- {endpoint}: {status}")
    
    print("\nSpeed Test:")
    speed = results['speed_test']
    print(f"Download: {speed.get('download_speed_mbps', 'N/A')} Mbps")
    print(f"Upload: {speed.get('upload_speed_mbps', 'N/A')} Mbps")
    print(f"Ping: {speed.get('ping_ms', 'N/A')} ms")
    
    print("\nIssues Found:")
    for issue in analysis['issues']:
        print(f"- {issue}")
    
    print("\nRecommendations:")
    for recommendation in analysis['recommendations']:
        print(f"- {recommendation}")
    
    print("\nDetailed results saved to network_diagnostics_results.json")
    print("Logs available in logs/network_diagnostics.log")

if __name__ == "__main__":
    main() 