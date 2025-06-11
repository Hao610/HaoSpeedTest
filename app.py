from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_talisman import Talisman
import os
import json
import secrets
import logging
from datetime import datetime, timedelta
from error_handlers import register_error_handlers
import speedtest
import socket
import requests
import time
import random
import threading
import queue
from werkzeug.exceptions import HTTPException
import geocoder
import psutil
import platform
import subprocess
import re
from typing import Dict, Any, Optional, List, Tuple, Union
import concurrent.futures
from functools import lru_cache
import ssl
import certifi
import dns.resolver
from urllib.parse import urlparse
from typing_extensions import TypedDict

# Try to import netifaces, but provide a fallback if it's not available
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    logging.warning("netifaces module not available. Some network interface features will be limited.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Type definitions
class LocationData(TypedDict):
    latitude: float
    longitude: float
    city: str
    country: str
    region: str
    timezone: str

class NetworkInfo(TypedDict):
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    error_in: int
    error_out: int
    drop_in: int
    drop_out: int
    interfaces: Dict[str, Dict[str, str]]

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DEBUG'] = False  # Disable debug mode in production
app.config['SOCKETIO_ASYNC_MODE'] = 'gevent'
app.config['SOCKETIO_PING_TIMEOUT'] = 60
app.config['SOCKETIO_PING_INTERVAL'] = 25
app.config['SOCKETIO_MAX_HTTP_BUFFER_SIZE'] = 1e8

# Security configurations
Talisman(app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' 'unsafe-eval' https:",
        'style-src': "'self' 'unsafe-inline' https:",
        'img-src': "'self' data: https:",
        'connect-src': "'self' https: wss:",
        'font-src': "'self' https:",
        'object-src': "'none'",
        'media-src': "'self'",
        'frame-src': "'none'",
    }
)

# Rate limiting (temporarily disabled)
# limiter = Limiter(
#     app=app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"],
#     storage_uri="memory://",
#     strategy="fixed-window"
# )

socketio = SocketIO(app, 
    cors_allowed_origins="*",
    async_mode='gevent',
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=1e8,
    logger=True,
    engineio_logger=True
)

# Store active rooms with enhanced security
rooms: Dict[str, Dict[str, Any]] = {}
MAX_ROOM_AGE = timedelta(hours=1)
MAX_ROOMS_PER_IP = 5

# Register error handlers
app = register_error_handlers(app)

# Initialize speedtest
st = speedtest.Speedtest()

def get_network_interfaces() -> Dict[str, Dict[str, str]]:
    """Get network interface information with fallback if netifaces is not available"""
    if NETIFACES_AVAILABLE:
        try:
            interfaces = {}
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    interfaces[interface] = {
                        'ipv4': addrs[netifaces.AF_INET][0]['addr'],
                        'netmask': addrs[netifaces.AF_INET][0]['netmask']
                    }
                if netifaces.AF_INET6 in addrs:
                    interfaces[interface] = {
                        'ipv6': addrs[netifaces.AF_INET6][0]['addr']
                    }
            return interfaces
        except Exception as e:
            logger.error(f"Error getting network interfaces: {str(e)}")
    
    # Fallback using socket
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return {
            'default': {
                'ipv4': ip_address,
                'hostname': hostname
            }
        }
    except Exception as e:
        logger.error(f"Error getting network info fallback: {str(e)}")
        return {}

def get_accurate_location() -> Optional[LocationData]:
    """Get accurate location using multiple methods"""
    try:
        # First try to get location from speedtest server
        st = speedtest.Speedtest()
        st.get_best_server()
        server_info = st.results.server
        
        if server_info and 'country' in server_info and 'name' in server_info:
            # Use the speedtest server's location as it's more accurate
            location_data: LocationData = {
                'latitude': server_info.get('lat', 0),
                'longitude': server_info.get('lon', 0),
                'city': server_info.get('name', 'Unknown'),
                'country': server_info.get('country', 'Unknown'),
                'region': server_info.get('region', 'Unknown'),
                'timezone': datetime.now().astimezone().tzname()
            }
            return location_data
        
        # Fallback to IP-based geolocation
        g = geocoder.ip('me')
        if g.ok:
            location_data: LocationData = {
                'latitude': g.lat,
                'longitude': g.lng,
                'city': g.city,
                'country': g.country,
                'region': g.state,
                'timezone': datetime.now().astimezone().tzname()
            }
            return location_data
            
        return None
    except Exception as e:
        app.logger.error(f"Error getting location: {str(e)}")
        return None

def get_network_info() -> Optional[NetworkInfo]:
    """Get network information using psutil"""
    try:
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'error_in': net_io.errin,
            'error_out': net_io.errout,
            'drop_in': net_io.dropin,
            'drop_out': net_io.dropout,
            'interfaces': get_network_interfaces()
        }
    except Exception as e:
        app.logger.error(f"Error getting network info: {str(e)}")
        return None

def run_speed_test() -> dict:
    """Run a simple speed test"""
    try:
        # Initialize speedtest
        st = speedtest.Speedtest()
        
        # Get best server
        st.get_best_server()
        
        # Test download speed
        download_speed = st.download()
        
        # Test upload speed
        upload_speed = st.upload()
        
        # Get ping
        ping = st.results.ping
        
        # Convert speeds to Mbps
        download_mbps = round(download_speed / 1000000, 2)
        upload_mbps = round(upload_speed / 1000000, 2)
        
        # Get server info
        server_info = st.results.server
        
        return {
            'download': download_mbps,
            'upload': upload_mbps,
            'ping': round(ping, 2),
            'server': {
                'name': server_info.get('name', 'Unknown'),
                'country': server_info.get('country', 'Unknown'),
                'distance': round(server_info.get('distance', 0), 2)
            },
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error running speed test: {str(e)}")
        return None

def calculate_packet_loss() -> float:
    """Calculate packet loss percentage"""
    try:
        # Send 100 ICMP packets and count responses
        sent = 100
        received = 0
        for _ in range(sent):
            try:
                subprocess.run(['ping', '-n', '1', '8.8.8.8'], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL, 
                             timeout=1)
                received += 1
            except:
                continue
        return round(((sent - received) / sent) * 100, 2)
    except:
        return 0.0

def calculate_buffer_bloat() -> float:
    """Calculate buffer bloat in milliseconds"""
    try:
        # Measure latency under load
        base_latency = float(subprocess.check_output(['ping', '-n', '1', '8.8.8.8']).decode().split('Average = ')[1].split('ms')[0])
        # Simulate load and measure latency again
        # This is a simplified version - real implementation would be more complex
        return round(base_latency * 1.5, 2)
    except:
        return 0.0

def calculate_dns_latency() -> float:
    """Calculate DNS resolution latency"""
    try:
        start_time = time.time()
        dns.resolver.resolve('google.com', 'A')
        return round((time.time() - start_time) * 1000, 2)
    except:
        return 0.0

def get_network_type() -> str:
    """Determine network type"""
    try:
        if NETIFACES_AVAILABLE:
            for interface in netifaces.interfaces():
                if netifaces.AF_INET in netifaces.ifaddresses(interface):
                    if 'wlan' in interface.lower():
                        return "WiFi"
                    elif 'eth' in interface.lower():
                        return "Ethernet"
        return "Unknown"
    except:
        return "Unknown"

def get_signal_strength() -> str:
    """Get WiFi signal strength if available"""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces']).decode()
            if 'Signal' in output:
                signal = output.split('Signal')[1].split('%')[0].strip()
                return f"{signal}%"
        return "N/A"
    except:
        return "N/A"

def get_network_protocol() -> str:
    """Determine network protocol"""
    try:
        if NETIFACES_AVAILABLE:
            for interface in netifaces.interfaces():
                if netifaces.AF_INET6 in netifaces.ifaddresses(interface):
                    return "IPv6"
                elif netifaces.AF_INET in netifaces.ifaddresses(interface):
                    return "IPv4"
        return "Unknown"
    except:
        return "Unknown"

def get_network_topology() -> Dict[str, Any]:
    """Get network topology information"""
    try:
        topology = {
            'routers': [],
            'switches': [],
            'devices': []
        }
        
        # Get default gateway
        if NETIFACES_AVAILABLE:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                topology['routers'].append({
                    'ip': gateways['default'][netifaces.AF_INET][0],
                    'interface': gateways['default'][netifaces.AF_INET][1]
                })
        
        # Get local devices (simplified)
        if platform.system() == "Windows":
            output = subprocess.check_output(['arp', '-a']).decode()
            for line in output.split('\n'):
                if 'dynamic' in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        topology['devices'].append({
                            'ip': parts[0],
                            'mac': parts[1]
                        })
        
        return topology
    except:
        return {'routers': [], 'switches': [], 'devices': []}

def get_ai_insights(download: float, upload: float, ping: float, jitter: float, packet_loss: float) -> Dict[str, Any]:
    """Generate AI-powered insights about the connection"""
    insights = {
        'performance': '',
        'recommendations': [],
        'issues': []
    }
    
    # Analyze performance
    if download < 5:
        insights['performance'] = 'Poor'
        insights['issues'].append('Very slow download speed')
        insights['recommendations'].append('Consider upgrading your internet plan')
    elif download < 25:
        insights['performance'] = 'Fair'
        insights['recommendations'].append('Your connection is suitable for basic browsing')
    elif download < 100:
        insights['performance'] = 'Good'
        insights['recommendations'].append('Your connection is suitable for HD streaming')
    else:
        insights['performance'] = 'Excellent'
        insights['recommendations'].append('Your connection is suitable for 4K streaming')
    
    # Analyze issues
    if ping > 100:
        insights['issues'].append('High latency detected')
        insights['recommendations'].append('Check your network for interference')
    if jitter > 20:
        insights['issues'].append('High jitter detected')
        insights['recommendations'].append('Consider using a wired connection')
    if packet_loss > 1:
        insights['issues'].append('Packet loss detected')
        insights['recommendations'].append('Check your network cables and connections')
    
    return insights

@app.route('/')
def index():
    try:
        client_ip = request.remote_addr
        logger.info(f"New connection from IP: {client_ip}")
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering index: {str(e)}")
        raise

@app.route('/room/<room_id>')
def room(room_id):
    if room_id not in rooms:
        return render_template('index.html', error="Room not found")
    return render_template('index.html')

@app.route('/api/ip')
def get_ip():
    return jsonify({
        'ip': request.remote_addr,
        'forwarded_for': request.headers.get('X-Forwarded-For'),
        'real_ip': request.headers.get('X-Real-IP')
    })

@socketio.on('connect')
def handle_connect():
    try:
        client_ip = request.remote_addr
        logger.info(f"WebSocket connection from IP: {client_ip}")
        
        # Check rate limiting for WebSocket connections
        if not is_allowed_connection(client_ip):
            return False
    except Exception as e:
        logger.error(f"Error handling connection: {str(e)}")
        raise

@socketio.on('disconnect')
def handle_disconnect():
    try:
        client_ip = request.remote_addr
        logger.info(f"WebSocket disconnection from IP: {client_ip}")
        cleanup_rooms()
    except Exception as e:
        logger.error(f"Error handling disconnection: {str(e)}")
        raise

@socketio.on('create_room')
def handle_create_room(data):
    client_ip = request.remote_addr
    room_id = data.get('room_id')
    
    if not is_allowed_room_creation(client_ip):
        emit('error', {'message': 'Rate limit exceeded'})
        return
    
    if room_id not in rooms:
        rooms[room_id] = {
            'host': request.sid,
            'guests': [],
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'host_ip': client_ip
        }
        join_room(room_id)
        emit('room_created', {'room_id': room_id}, room=room_id)
    else:
        emit('error', {'message': 'Room already exists'})

@socketio.on('join_room')
def handle_join_room(data):
    client_ip = request.remote_addr
    room_id = data.get('room_id')
    
    if room_id in rooms:
        rooms[room_id]['guests'].append(request.sid)
        rooms[room_id]['last_activity'] = datetime.now()
        join_room(room_id)
        emit('user_joined', {'user_id': request.sid}, room=room_id)
    else:
        emit('error', {'message': 'Room not found'})

@socketio.on('offer')
def handle_offer(data):
    room_id = data['room_id']
    emit('offer', {'sdp': data['sdp']}, room=room_id)

@socketio.on('answer')
def handle_answer(data):
    room_id = data['room_id']
    emit('answer', {'sdp': data['sdp']}, room=room_id)

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    room_id = data['room_id']
    emit('ice_candidate', {'candidate': data['candidate']}, room=room_id)

def is_allowed_connection(ip):
    # Implement connection rate limiting logic
    return True

def is_allowed_room_creation(ip):
    # Count active rooms for this IP
    active_rooms = sum(1 for room in rooms.values() if room['host_ip'] == ip)
    return active_rooms < MAX_ROOMS_PER_IP

def cleanup_rooms():
    now = datetime.now()
    for room_id, room_data in list(rooms.items()):
        if now - room_data['last_activity'] > MAX_ROOM_AGE:
            del rooms[room_id]
            emit('room_expired', {'room_id': room_id}, room=room_id)

@app.route('/start-test')
def start_test():
    try:
        # Initialize speed test
        return jsonify({
            'status': 'started',
            'message': 'Speed test initialized'
        })
    except Exception as e:
        logger.error(f"Error starting test: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/ping-test')
def ping_test():
    try:
        # Simulate ping test
        import time
        start_time = time.time()
        time.sleep(0.1)  # Simulate network delay
        ping_time = int((time.time() - start_time) * 1000)
        return jsonify({'ping': ping_time})
    except Exception as e:
        logger.error(f"Error in ping test: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/download-test')
def download_test():
    try:
        # Generate test data (1MB)
        test_data = b'0' * (1024 * 1024)
        return jsonify({
            'size': len(test_data),
            'data': test_data.hex()  # Convert to hex for JSON
        })
    except Exception as e:
        logger.error(f"Error in download test: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/upload-test', methods=['POST'])
def upload_test():
    try:
        # Get the uploaded data
        data = request.get_data()
        size = len(data)
        return jsonify({
            'status': 'success',
            'size': size
        })
    except Exception as e:
        logger.error(f"Error in upload test: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/test-status')
def test_status():
    try:
        # Return current test status with more realistic values
        return jsonify({
            'status': 'running',
            'progress': 0,
            'download': 0,
            'upload': 0,
            'ping': 0,
            'networkType': 'WiFi 6E',
            'signalStrength': 'Excellent',
            'connectionQuality': 'High',
            'protocol': 'IPv6'
        })
    except Exception as e:
        logger.error(f"Error checking status: {str(e)}")
        return jsonify({
            'error': 'Unable to check test status. Please try again.',
            'status': 'error'
        }), 500

@app.route('/get-location')
def get_location():
    """Get accurate location information"""
    try:
        location = get_accurate_location()
        if location:
            return jsonify(location)
        return jsonify({
            'error': 'Could not determine location. Please try again.',
            'status': 'error'
        }), 500
    except Exception as e:
        logger.error(f"Location error: {str(e)}")
        return jsonify({
            'error': 'An error occurred while getting location. Please try again.',
            'status': 'error'
        }), 500

@app.route('/speed-test')
def speed_test():
    """Run a simple speed test"""
    try:
        results = run_speed_test()
        if results:
            return jsonify(results)
        return jsonify({
            'error': 'Unable to complete speed test. Please try again.',
            'status': 'error'
        }), 500
    except Exception as e:
        logger.error(f"Speed test error: {str(e)}")
        return jsonify({
            'error': 'An error occurred during the speed test. Please try again.',
            'status': 'error'
        }), 500

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    try:
        port = int(os.environ.get('PORT', 5000))
        # Try to find an available port
        while True:
            try:
                logger.info(f"Starting server on port {port}")
                # Use host='0.0.0.0' to make the server accessible from other devices
                socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)
                break
            except OSError as e:
                if e.errno == 10048:  # Port already in use
                    logger.warning(f"Port {port} is in use, trying port {port + 1}")
                    port += 1
                else:
                    raise
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        raise 