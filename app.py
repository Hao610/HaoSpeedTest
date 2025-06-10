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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SOCKETIO_ASYNC_MODE'] = 'eventlet'

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
    async_mode='eventlet',
    ping_timeout=60,
    ping_interval=25
)

# Store active rooms with enhanced security
rooms = {}
MAX_ROOM_AGE = timedelta(hours=1)
MAX_ROOMS_PER_IP = 5

@app.route('/')
@limiter.limit("30 per minute")
def index():
    client_ip = request.remote_addr
    logger.info(f"New connection from IP: {client_ip}")
    return render_template('index.html')

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
    client_ip = request.remote_addr
    logger.info(f"WebSocket connection from IP: {client_ip}")
    
    # Check rate limiting for WebSocket connections
    if not is_allowed_connection(client_ip):
        return False

@socketio.on('disconnect')
def handle_disconnect():
    client_ip = request.remote_addr
    logger.info(f"WebSocket disconnection from IP: {client_ip}")
    cleanup_rooms()

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False) 