from app import app, socketio
import socket
import sys
import logging
from datetime import datetime
import os
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def get_local_ip():
    """Get the local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        return "127.0.0.1"

def check_port(port):
    """Check if a port is available"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return True
        except socket.error:
            return False

def find_available_port(start_port=5000, max_port=5100):
    """Find an available port"""
    for port in range(start_port, max_port):
        if check_port(port):
            return port
    return None

def setup_firewall_rules(port):
    """Set up firewall rules for Windows"""
    if os.name == 'nt':  # Windows
        try:
            # Add inbound rule
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=Python_Web_Server_{port}',
                'dir=in',
                'action=allow',
                'protocol=TCP',
                f'localport={port}'
            ], check=True)
            
            # Add outbound rule
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=Python_Web_Server_{port}',
                'dir=out',
                'action=allow',
                'protocol=TCP',
                f'localport={port}'
            ], check=True)
            
            logger.info(f"Firewall rules added for port {port}")
        except Exception as e:
            logger.error(f"Error setting up firewall rules: {e}")

def main():
    try:
        # Find available port
        port = 5000
        if not check_port(port):
            logger.warning(f"Port {port} is in use")
            new_port = find_available_port()
            if new_port:
                port = new_port
                logger.info(f"Using alternative port: {port}")
            else:
                logger.error("No available ports found")
                sys.exit(1)

        # Get local IP
        local_ip = get_local_ip()
        
        # Setup firewall rules
        setup_firewall_rules(port)
        
        # Print server information
        print("\n=== Server Starting ===")
        print(f"Timestamp: {datetime.now()}")
        print(f"Local IP: {local_ip}")
        print(f"Port: {port}")
        print(f"Access the application at:")
        print(f"http://{local_ip}:{port}")
        print(f"=====================\n")
        
        # Start the server
        logger.info(f"Starting server on {local_ip}:{port}")
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=True,
            allow_unsafe_werkzeug=True
        )
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 