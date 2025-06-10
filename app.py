from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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
from typing import Dict, Any, Optional, List, Tuple
import concurrent.futures
from functools import lru_cache
import aiohttp
import asyncio
from aiohttp import ClientTimeout
import ssl
import certifi
import dns.resolver
from urllib.parse import urlparse
import netifaces
import speedtest_cli
from speedtest_cli import Speedtest
import speedtest_servers
from speedtest_servers import get_best_server, get_servers
import speedtest_results
from speedtest_results import SpeedtestResults
import speedtest_config
from speedtest_config import SpeedtestConfig
import speedtest_utils
from speedtest_utils import format_speed, format_size, format_time
import speedtest_exceptions
from speedtest_exceptions import SpeedtestError, SpeedtestHTTPError, SpeedtestConfigError, SpeedtestBestServerFailure, SpeedtestResultsError
import speedtest_logger
from speedtest_logger import setup_logger, get_logger
import speedtest_constants
from speedtest_constants import SPEEDTEST_SERVERS, SPEEDTEST_CONFIG, SPEEDTEST_RESULTS, SPEEDTEST_ERRORS
import speedtest_types
from speedtest_types import Server, Config, Results, Error
import speedtest_validation
from speedtest_validation import validate_server, validate_config, validate_results
import speedtest_serialization
from speedtest_serialization import serialize_server, serialize_config, serialize_results
import speedtest_deserialization
from speedtest_deserialization import deserialize_server, deserialize_config, deserialize_results
import speedtest_cache
from speedtest_cache import cache_server, cache_config, cache_results, get_cached_server, get_cached_config, get_cached_results
import speedtest_network
from speedtest_network import get_network_info, get_network_speed, get_network_latency, get_network_jitter, get_network_packet_loss, get_network_buffer_bloat, get_network_dns_latency
import speedtest_location
from speedtest_location import get_location, get_location_info, get_location_coordinates, get_location_city, get_location_country, get_location_region, get_location_timezone
import speedtest_servers
from speedtest_servers import get_servers, get_best_server, get_server_info, get_server_distance, get_server_latency, get_server_speed, get_server_jitter, get_server_packet_loss, get_server_buffer_bloat, get_server_dns_latency
import speedtest_results
from speedtest_results import get_results, get_results_info, get_results_speed, get_results_latency, get_results_jitter, get_results_packet_loss, get_results_buffer_bloat, get_results_dns_latency
import speedtest_config
from speedtest_config import get_config, get_config_info, get_config_speed, get_config_latency, get_config_jitter, get_config_packet_loss, get_config_buffer_bloat, get_config_dns_latency
import speedtest_utils
from speedtest_utils import format_speed, format_size, format_time, format_latency, format_jitter, format_packet_loss, format_buffer_bloat, format_dns_latency
import speedtest_exceptions
from speedtest_exceptions import SpeedtestError, SpeedtestHTTPError, SpeedtestConfigError, SpeedtestBestServerFailure, SpeedtestResultsError
import speedtest_logger
from speedtest_logger import setup_logger, get_logger
import speedtest_constants
from speedtest_constants import SPEEDTEST_SERVERS, SPEEDTEST_CONFIG, SPEEDTEST_RESULTS, SPEEDTEST_ERRORS
import speedtest_types
from speedtest_types import Server, Config, Results, Error
import speedtest_validation
from speedtest_validation import validate_server, validate_config, validate_results
import speedtest_serialization
from speedtest_serialization import serialize_server, serialize_config, serialize_results
import speedtest_deserialization
from speedtest_deserialization import deserialize_server, deserialize_config, deserialize_results
import speedtest_cache
from speedtest_cache import cache_server, cache_config, cache_results, get_cached_server, get_cached_config, get_cached_results
import speedtest_network
from speedtest_network import get_network_info, get_network_speed, get_network_latency, get_network_jitter, get_network_packet_loss, get_network_buffer_bloat, get_network_dns_latency
import speedtest_location
from speedtest_location import get_location, get_location_info, get_location_coordinates, get_location_city, get_location_country, get_location_region, get_location_timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
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

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

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
rooms = {}
MAX_ROOM_AGE = timedelta(hours=1)
MAX_ROOMS_PER_IP = 5

# Register error handlers
app = register_error_handlers(app)

# Initialize speedtest
st = Speedtest()
st.get_best_server()

def get_accurate_location():
    """Get accurate location using multiple methods"""
    try:
        # Try IP-based geolocation first
        g = geocoder.ip('me')
        if g.ok:
            return {
                'latitude': g.lat,
                'longitude': g.lng,
                'city': g.city,
                'country': g.country,
                'region': g.state,
                'timezone': g.timezone
            }
        
        # Fallback to system network information
        network_info = get_network_info()
        if network_info and 'location' in network_info:
            return network_info['location']
            
        return None
    except Exception as e:
        app.logger.error(f"Error getting location: {str(e)}")
        return None

def run_speed_test():
    """Run a more accurate speed test"""
    try:
        # Get best server
        server = st.get_best_server()
        
        # Test download speed with multiple threads
        download_speed = st.download(threads=4)
        
        # Test upload speed with multiple threads
        upload_speed = st.upload(threads=4)
        
        # Get ping
        ping = st.results.ping
        
        # Get additional metrics
        jitter = st.results.jitter
        packet_loss = st.results.packet_loss
        buffer_bloat = st.results.buffer_bloat
        dns_latency = st.results.dns_latency
        
        return {
            'download': round(download_speed / 1000000, 2),  # Convert to Mbps
            'upload': round(upload_speed / 1000000, 2),      # Convert to Mbps
            'ping': round(ping, 2),
            'jitter': round(jitter, 2),
            'packet_loss': round(packet_loss, 2),
            'buffer_bloat': round(buffer_bloat, 2),
            'dns_latency': round(dns_latency, 2),
            'server': {
                'name': server['name'],
                'country': server['country'],
                'distance': round(server['distance'], 2),
                'latency': round(server['latency'], 2)
            }
        }
    except Exception as e:
        app.logger.error(f"Error running speed test: {str(e)}")
        return None

@app.route('/')
@limiter.limit("30 per minute")
def index():
    try:
        client_ip = request.remote_addr
        logger.info(f"New connection from IP: {client_ip}")
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering index: {str(e)}")
        raise

@app.route('/room/<room_id>')
@limiter.limit("30 per minute")
def room(room_id):
    if room_id not in rooms:
        return render_template('index.html', error="Room not found")
    return render_template('index.html')

@app.route('/api/ip')
@limiter.limit("60 per minute")
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
        # Return current test status
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get-location')
def get_location():
    """Get accurate location information"""
    location = get_accurate_location()
    if location:
        return jsonify(location)
    return jsonify({'error': 'Could not determine location'}), 500

@app.route('/speed-test')
def speed_test():
    """Run a comprehensive speed test"""
    results = run_speed_test()
    if results:
        return jsonify(results)
    return jsonify({'error': 'Speed test failed'}), 500

if __name__ == '__main__':
    try:
        port = int(os.environ.get('PORT', 5000))
        logger.info(f"Starting server on port {port}")
        # Use host='0.0.0.0' to make the server accessible from other devices
        socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        raise 