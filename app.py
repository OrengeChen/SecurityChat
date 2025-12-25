from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import time
import asyncio
import os
import threading
import base64
import json
from core import p2p_manager, dht_network, init_database, p2p_chat_manager, direct_p2p_messenger
from core.file_encryption import file_encryption_manager
from core.crypto import crypto_manager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# 存储聊天室和用户信息（简单内存存储）
rooms = {}
users = {}
p2p_peers = {}  # P2P连接信息
user_p2p_info = {}  # 用户P2P信息（IP、端口、公钥）

@app.route('/')
def index():
    """主页面"""
    return render_template('index.html')

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy'})

@app.route('/api/rooms')
def get_rooms():
    return jsonify({
        'rooms': list(rooms.keys()),
        'count': len(rooms)
    })

@app.route('/api/p2p/info')
def get_p2p_info():
    """获取P2P连接信息"""
    try:
        p2p_manager.start()
        return jsonify({
            'peer_id': p2p_manager.get_peer_id(),
            'public_key': p2p_manager.get_public_key_pem(),
            'port': p2p_manager.local_port,
            'connected_peers': p2p_manager.get_connected_peers(),
            'p2p_chat_stats': p2p_chat_manager.get_stats()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/p2p/connect', methods=['POST'])
def connect_to_peer():
    """连接到P2P节点"""
    data = request.json
    ip = data.get('ip')
    port = data.get('port')
    public_key = data.get('public_key')
    
    if not ip or not port:
        return jsonify({'error': 'IP and port are required'}), 400
    
    try:
        success = p2p_manager.connect_to_peer(ip, port, public_key)
        if success:
            # 将节点添加到DHT网络
            dht_network.add_node(ip, port)
            return jsonify({'success': True, 'message': f'Connected to {ip}:{port}'})
        else:
            return jsonify({'success': False, 'message': 'Connection failed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/p2p/chat/sessions')
def get_p2p_chat_sessions():
    """获取P2P聊天会话"""
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400
    
    sessions = p2p_chat_manager.get_user_sessions(user_id)
    return jsonify({
        'sessions': [s.get_session_info() for s in sessions],
        'count': len(sessions)
    })

@app.route('/api/p2p/chat/create', methods=['POST'])
def create_p2p_chat():
    """创建P2P聊天会话"""
    data = request.json
    user1_id = data.get('user1')
    user2_id = data.get('user2')
    
    if not user1_id or not user2_id:
        return jsonify({'error': 'Both user1 and user2 are required'}), 400
    
    try:
        session = p2p_chat_manager.create_session(user1_id, user2_id)
        return jsonify({
            'success': True,
            'session': session.get_session_info(),
            'public_key': session.public_key_pem
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/p2p/chat/invite', methods=['POST'])
def create_p2p_invitation():
    """创建P2P聊天邀请"""
    data = request.json
    from_user = data.get('from')
    to_user = data.get('to')
    public_key = data.get('public_key')
    
    if not from_user or not to_user or not public_key:
        return jsonify({'error': 'from, to and public_key are required'}), 400
    
    try:
        invitation = p2p_chat_manager.create_invitation(from_user, to_user, public_key)
        return jsonify({
            'success': True,
            'invitation': invitation
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/p2p/chat/accept', methods=['POST'])
def accept_p2p_invitation():
    """接受P2P聊天邀请"""
    data = request.json
    invitation_id = data.get('invitation_id')
    public_key = data.get('public_key')
    
    if not invitation_id or not public_key:
        return jsonify({'error': 'invitation_id and public_key are required'}), 400
    
    try:
        session = p2p_chat_manager.accept_invitation(invitation_id, public_key)
        if session:
            return jsonify({
                'success': True,
                'session': session.get_session_info()
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid invitation'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/p2p/chat/send', methods=['POST'])
def send_p2p_message():
    """发送P2P消息"""
    data = request.json
    session_id = data.get('session_id')
    content = data.get('content')
    ephemeral = data.get('ephemeral', False)
    
    if not session_id or not content:
        return jsonify({'error': 'session_id and content are required'}), 400
    
    try:
        success, message = p2p_chat_manager.send_direct_message(session_id, content, ephemeral)
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/p2p/chat/messages/<session_id>')
def get_p2p_messages(session_id):
    """获取P2P聊天消息"""
    limit = request.args.get('limit', 50, type=int)
    
    session = p2p_chat_manager.get_session(session_id)
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    
    messages = session.get_messages(limit)
    return jsonify({
        'success': True,
        'messages': messages,
        'count': len(messages)
    })

@app.route('/api/p2p/chat/encrypt', methods=['POST'])
def encrypt_p2p_message():
    """加密P2P消息"""
    data = request.json
    content = data.get('content')
    session_key_b64 = data.get('session_key')
    
    if not content:
        return jsonify({'error': 'Content is required'}), 400
    
    try:
        if session_key_b64:
            # 使用提供的会话密钥加密
            session_key = base64.b64decode(session_key_b64)
            encrypted_content = crypto_manager.encrypt_with_session_key(session_key, content)
            return jsonify({
                'success': True,
                'encrypted_content': encrypted_content,
                'algorithm': 'AES-GCM',
                'key_type': 'session_key'
            })
        else:
            # 生成新的会话密钥并加密
            session_key = crypto_manager.generate_session_key()
            encrypted_content = crypto_manager.encrypt_with_session_key(session_key, content)
            return jsonify({
                'success': True,
                'encrypted_content': encrypted_content,
                'session_key': base64.b64encode(session_key).decode('utf-8'),
                'algorithm': 'AES-GCM',
                'key_type': 'session_key'
            })
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/api/p2p/chat/decrypt', methods=['POST'])
def decrypt_p2p_message():
    """解密P2P消息"""
    data = request.json
    encrypted_content = data.get('encrypted_content')
    session_key_b64 = data.get('session_key')
    
    if not encrypted_content or not session_key_b64:
        return jsonify({'error': 'Both encrypted_content and session_key are required'}), 400
    
    try:
        session_key = base64.b64decode(session_key_b64)
        decrypted_content = crypto_manager.decrypt_with_session_key(session_key, encrypted_content)
        return jsonify({
            'success': True,
            'decrypted_content': decrypted_content,
            'decryption_method': 'AES-GCM with session key'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Decryption failed: {str(e)}',
            'note': '可能是密钥不匹配或数据损坏'
        }), 500

@app.route('/api/dht/info')
def get_dht_info():
    """获取DHT网络信息"""
    return jsonify(dht_network.get_network_info())

@app.route('/api/dht/store', methods=['POST'])
def store_in_dht():
    """在DHT中存储数据"""
    data = request.json
    key = data.get('key')
    value = data.get('value')
    
    if not key or not value:
        return jsonify({'error': 'Key and value are required'}), 400
    
    dht_network.store_value(key, value)
    return jsonify({'success': True, 'message': f'Stored {key} in DHT'})

@app.route('/api/dht/get/<key>')
def get_from_dht(key):
    """从DHT获取数据"""
    value = dht_network.get_value(key)
    if value:
        return jsonify({'success': True, 'key': key, 'value': value})
    else:
        return jsonify({'success': False, 'message': 'Key not found'}), 404

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'message': 'Connected to server'})
    
    # 默认加入公共房间
    join_room('public')
    rooms.setdefault('public', []).append(request.sid)
    print(f'Client {request.sid} joined public room')
    
    # 发送P2P信息给客户端
    try:
        p2p_manager.start()
        emit('p2p_info', {
            'peer_id': p2p_manager.get_peer_id(),
            'public_key': p2p_manager.get_public_key_pem(),
            'port': p2p_manager.local_port
        })
    except Exception as e:
        print(f"Error starting P2P manager: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
    
    # 清理用户数据
    username_to_remove = None
    for sid, user_info in users.items():
        if sid == request.sid:
            username_to_remove = user_info.get('username')
            break
    
    # 从users字典中移除
    if request.sid in users:
        del users[request.sid]
    
    # 从user_p2p_info中移除
    if username_to_remove and username_to_remove in user_p2p_info:
        del user_p2p_info[username_to_remove]
        print(f'用户 {username_to_remove} 已从在线列表中移除')
        
        # 广播用户下线通知
        emit('user_offline', {
            'username': username_to_remove
        }, broadcast=True)
    
    # 从p2p_peers中移除
    if username_to_remove and username_to_remove in p2p_peers:
        del p2p_peers[username_to_remove]
    
    # 清理房间数据
    for room in list(rooms.keys()):
        if request.sid in rooms[room]:
            rooms[room].remove(request.sid)
            # 如果房间为空，删除房间
            if not rooms[room]:
                del rooms[room]

@socketio.on('join')
def handle_join(room_id):
    join_room(room_id)
    if room_id not in rooms:
        rooms[room_id] = []
    rooms[room_id].append(request.sid)
    print(f'Client {request.sid} joined room {room_id}')
    emit('joined', {'room': room_id}, room=room_id)
    emit('room_update', {
        'room': room_id,
        'users': len(rooms[room_id])
    }, room=room_id)

@socketio.on('leave')
def handle_leave(room_id):
    leave_room(room_id)
    if room_id in rooms and request.sid in rooms[room_id]:
        rooms[room_id].remove(request.sid)
    print(f'Client {request.sid} left room {room_id}')
    emit('left', {'room': room_id}, room=room_id)
    emit('room_update', {
        'room': room_id,
        'users': len(rooms.get(room_id, []))
    }, room=room_id)

@socketio.on('message')
def handle_message(data):
    room_id = None
    # 查找用户所在的房间
    for room, clients in rooms.items():
        if request.sid in clients:
            room_id = room
            break
    
    if room_id:
        print(f'Message from {request.sid} in {room_id}: {data}')
        # 广播消息到房间
        emit('message', {
            'sender': users.get(request.sid, {}).get('username', 'Anonymous'),
            'content': data.get('content', ''),
            'timestamp': data.get('timestamp', ''),
            'room': room_id
        }, room=room_id)
    else:
        emit('error', {'message': 'You are not in any room'})

@socketio.on('register')
def handle_register(data):
    username = data.get('username', '')
    public_key = data.get('publicKey', '')
    p2p_ip = data.get('p2p_ip', request.remote_addr)
    p2p_port = data.get('p2p_port', 0)
    
    # 检查用户名是否已在线
    if username in user_p2p_info:
        # 用户名已在线，拒绝注册
        emit('register_error', {
            'error': f'用户名 {username} 已在其他设备登录，请使用其他用户名或退出其他登录'
        })
        print(f'注册失败: 用户名 {username} 已在线')
        return
    
    users[request.sid] = {
        'username': username,
        'publicKey': public_key,
        'sid': request.sid,
        'p2p_ip': p2p_ip,
        'p2p_port': p2p_port
    }
    
    print(f'User registered: {username}')
    emit('registered', {'username': username})
    
    # 如果用户提供了公钥，可以将其用于P2P连接
    if public_key and public_key != 'auto-generated-key':
        p2p_peers[username] = {
            'public_key': public_key,
            'sid': request.sid
        }
        
    # 存储用户P2P信息 - 修复：即使port为0也存储
    if p2p_ip:
        user_p2p_info[username] = {
            'ip': p2p_ip,
            'port': p2p_port,
            'public_key': public_key,
            'sid': request.sid
        }
        
        # 通知其他用户有新用户上线
        emit('user_online', {
            'username': username,
            'ip': p2p_ip,
            'port': p2p_port,
            'public_key': public_key
        }, broadcast=True, include_self=False)
        
        print(f'User {username} added to online list: {p2p_ip}:{p2p_port}')

@socketio.on('p2p_connect')
def handle_p2p_connect(data):
    """处理P2P连接请求"""
    target_username = data.get('username')
    target_ip = data.get('ip')
    target_port = data.get('port')
    
    if target_username in p2p_peers:
        target_sid = p2p_peers[target_username]['sid']
        public_key = p2p_peers[target_username]['public_key']
        
        # 通知目标用户有连接请求
        emit('p2p_connection_request', {
            'from': users[request.sid]['username'],
            'ip': request.remote_addr,
            'port': data.get('suggested_port', 0),
            'public_key': users[request.sid].get('publicKey', '')
        }, room=target_sid)
        
        emit('p2p_connection_initiated', {
            'target': target_username,
            'success': True,
            'message': 'Connection request sent'
        })
    elif target_ip and target_port:
        # 直接IP连接
        success = p2p_manager.connect_to_peer(target_ip, target_port)
        emit('p2p_connection_initiated', {
            'target': f'{target_ip}:{target_port}',
            'success': success
        })
    else:
        # 目标用户不在p2p_peers中，但可能在user_p2p_info中
        if target_username in user_p2p_info:
            target_info = user_p2p_info[target_username]
            target_sid = target_info['sid']
            
            # 通知目标用户有连接请求
            emit('p2p_connection_request', {
                'from': users[request.sid]['username'],
                'ip': request.remote_addr,
                'port': data.get('suggested_port', 0),
                'public_key': users[request.sid].get('publicKey', '')
            }, room=target_sid)
            
            emit('p2p_connection_initiated', {
                'target': target_username,
                'success': True,
                'message': 'Connection request sent'
            })
        else:
            emit('p2p_connection_initiated', {
                'target': target_username,
                'success': False,
                'error': 'Target user not found'
            })

@socketio.on('p2p_accept')
def handle_p2p_accept(data):
    """处理P2P连接接受/拒绝"""
    from_user = data.get('from')
    accepted = data.get('accepted', False)
    
    if from_user in user_p2p_info:
        from_info = user_p2p_info[from_user]
        from_sid = from_info['sid']
        
        current_user = users[request.sid]['username']
        
        if accepted:
            # 通知发起方连接被接受
            emit('p2p_connection_initiated', {
                'target': current_user,
                'success': True,
                'message': f'Connection accepted by {current_user}'
            }, room=from_sid)
            
            # 通知接受方连接已建立
            emit('p2p_connection_initiated', {
                'target': from_user,
                'success': True,
                'message': f'Connected to {from_user}'
            })
            
            print(f'P2P连接建立: {from_user} <-> {current_user}')
        else:
            # 通知发起方连接被拒绝
            emit('p2p_connection_initiated', {
                'target': current_user,
                'success': False,
                'error': f'Connection rejected by {current_user}'
            }, room=from_sid)
            
            print(f'P2P连接被拒绝: {from_user} -> {current_user}')
    else:
        emit('p2p_connection_initiated', {
            'target': from_user,
            'success': False,
            'error': 'User not found'
        })

@socketio.on('p2p_message')
def handle_p2p_message(data):
    """处理P2P消息（通过服务器中转，实际应该直接P2P）"""
    target = data.get('target')
    message = data.get('message')
    
    if target in p2p_peers:
        target_sid = p2p_peers[target]['sid']
        emit('p2p_message', {
            'from': users[request.sid]['username'],
            'message': message,
            'timestamp': time.time()
        }, room=target_sid)
        emit('p2p_message_sent', {'success': True})
    else:
        emit('p2p_message_sent', {'success': False, 'error': 'Target not found'})

@socketio.on('p2p_chat_invite')
def handle_p2p_chat_invite(data):
    """处理P2P聊天邀请"""
    target_username = data.get('target')
    public_key = data.get('public_key')
    
    if target_username in user_p2p_info:
        target_info = user_p2p_info[target_username]
        target_sid = target_info['sid']
        
        # 创建邀请
        from_user = users[request.sid]['username']
        invitation = p2p_chat_manager.create_invitation(
            from_user, target_username, public_key
        )
        
        # 发送邀请给目标用户
        emit('p2p_chat_invitation', {
            'invitation_id': invitation['id'],
            'from': from_user,
            'public_key': public_key,
            'timestamp': invitation['timestamp']
        }, room=target_sid)
        
        emit('p2p_invitation_sent', {
            'success': True,
            'invitation_id': invitation['id'],
            'target': target_username
        })
    else:
        emit('p2p_invitation_sent', {
            'success': False,
            'error': 'Target user not found or offline'
        })

@socketio.on('p2p_chat_accept')
def handle_p2p_chat_accept(data):
    """处理P2P聊天邀请接受"""
    invitation_id = data.get('invitation_id')
    public_key = data.get('public_key')
    
    session = p2p_chat_manager.accept_invitation(invitation_id, public_key)
    if session:
        # 通知双方会话已建立
        for user_id in [session.user1_id, session.user2_id]:
            if user_id in user_p2p_info:
                user_sid = user_p2p_info[user_id]['sid']
                emit('p2p_chat_established', {
                    'session_id': session.session_id,
                    'peer': session.user2_id if user_id == session.user1_id else session.user1_id,
                    'public_key': session.peer_public_key_pem,
                    'session_info': session.get_session_info()
                }, room=user_sid)
        
        emit('p2p_chat_accepted', {
            'success': True,
            'session_id': session.session_id
        })
    else:
        emit('p2p_chat_accepted', {
            'success': False,
            'error': 'Failed to establish session'
        })

@socketio.on('p2p_disconnect')
def handle_p2p_disconnect(data):
    """处理P2P断开连接"""
    target_username = data.get('target')
    
    if target_username in user_p2p_info:
        target_info = user_p2p_info[target_username]
        target_sid = target_info['sid']
        
        current_user = users[request.sid]['username']
        
        # 通知目标用户连接已断开
        emit('p2p_connection_disconnected', {
            'from': current_user,
            'message': f'{current_user} 已断开P2P连接'
        }, room=target_sid)
        
        print(f'P2P连接断开: {current_user} -> {target_username}')
        
        emit('p2p_disconnect_success', {
            'success': True,
            'message': f'已断开与 {target_username} 的P2P连接'
        })
    else:
        emit('p2p_disconnect_success', {
            'success': False,
            'error': 'Target user not found'
        })

@socketio.on('p2p_chat_message')
def handle_p2p_chat_message(data):
    """处理P2P聊天消息"""
    session_id = data.get('session_id')
    content = data.get('content')
    ephemeral = data.get('ephemeral', False)
    
    print(f'收到P2P聊天消息: session_id={session_id}, content={content}, ephemeral={ephemeral}')
    
    current_user = users[request.sid]['username']
    
    # 从session_id中提取目标用户
    # session_id格式: p2p_user1_user2
    parts = session_id.split('_')
    if len(parts) >= 3 and parts[0] == 'p2p':
        user1 = parts[1]
        user2 = parts[2]
        target_user = user2 if current_user == user1 else user1
        
        print(f'当前用户: {current_user}, 目标用户: {target_user}')
        
        if target_user in user_p2p_info:
            target_info = user_p2p_info[target_user]
            
            # 检查是否需要加密
            encrypted = data.get('encrypted', False)
            encrypted_content = data.get('encrypted_content')
            session_key = data.get('session_key')
            
            if encrypted and encrypted_content and session_key:
                # 发送加密消息
                emit('p2p_chat_message_received', {
                    'session_id': session_id,
                    'from': current_user,
                    'content': '[加密消息]',  # 前端会解密后显示真实内容
                    'encrypted': True,
                    'encrypted_content': encrypted_content,
                    'session_key': session_key,
                    'timestamp': time.time(),
                    'ephemeral': ephemeral
                }, room=target_info['sid'])
            else:
                # 发送明文消息
                emit('p2p_chat_message_received', {
                    'session_id': session_id,
                    'from': current_user,
                    'content': content,
                    'timestamp': time.time(),
                    'ephemeral': ephemeral
                }, room=target_info['sid'])
            
            print(f'消息已转发给 {target_user} (sid: {target_info["sid"]})')
            
            # 发送确认给发送方
            emit('p2p_chat_message_sent', {
                'success': True,
                'message_id': f'msg_{int(time.time())}'
            })
        else:
            print(f'目标用户 {target_user} 不在user_p2p_info中')
            emit('p2p_chat_message_sent', {
                'success': False,
                'error': f'Target user {target_user} not found'
            })
    else:
        print(f'无效的session_id格式: {session_id}')
        emit('p2p_chat_message_sent', {
            'success': False,
            'error': 'Invalid session_id format'
        })

# WebRTC信令处理
@socketio.on('webrtc_signal')
def handle_webrtc_signal(data):
    """处理WebRTC信令"""
    target = data.get('target')
    signal = data.get('signal')
    signal_type = data.get('type', 'signal')
    
    if target in user_p2p_info:
        target_sid = user_p2p_info[target]['sid']
        
        emit('webrtc_signal', {
            'from': users[request.sid]['username'],
            'signal': signal,
            'type': signal_type
        }, room=target_sid)
        
        emit('webrtc_signal_sent', {
            'success': True,
            'target': target
        })
    else:
        emit('webrtc_signal_sent', {
            'success': False,
            'error': 'Target user not found'
        })

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    """处理WebRTC Offer"""
    handle_webrtc_signal({**data, 'type': 'offer'})

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    """处理WebRTC Answer"""
    handle_webrtc_signal({**data, 'type': 'answer'})

@socketio.on('webrtc_ice_candidate')
def handle_webrtc_ice_candidate(data):
    """处理WebRTC ICE候选"""
    target = data.get('target')
    candidate = data.get('candidate')
    
    if target in user_p2p_info:
        target_sid = user_p2p_info[target]['sid']
        
        emit('webrtc_ice_candidate', {
            'from': users[request.sid]['username'],
            'candidate': candidate
        }, room=target_sid)
        
        emit('webrtc_ice_candidate_sent', {
            'success': True,
            'target': target
        })
    else:
        emit('webrtc_ice_candidate_sent', {
            'success': False,
            'error': 'Target user not found'
        })

@socketio.on('get_online_users')
def handle_get_online_users(data=None):
    """获取在线用户列表"""
    online_users = []
    for username, info in user_p2p_info.items():
        if info.get('sid'):
            online_users.append({
                'username': username,
                'ip': info.get('ip', ''),
                'port': info.get('port', 0),
                'public_key': info.get('public_key', '')
            })
    
    emit('online_users', online_users)

@socketio.on('send_emoji')
def handle_send_emoji(data):
    """发送表情"""
    target = data.get('target')
    emoji = data.get('emoji')
    session_id = data.get('session_id')
    
    if not emoji:
        emit('emoji_sent', {'success': False, 'error': 'No emoji provided'})
        return
    
    current_user = users[request.sid]['username']
    
    # 表情实际上是特殊的文本，可以直接用现有的文本加密机制
    # 对于公共聊天
    if not target and not session_id:
        room_id = None
        for room, clients in rooms.items():
            if request.sid in clients:
                room_id = room
                break
        
        if room_id:
            emit('message', {
                'sender': current_user,
                'content': f'[表情] {emoji}',
                'timestamp': time.time(),
                'room': room_id,
                'type': 'emoji'
            }, room=room_id)
            emit('emoji_sent', {'success': True})
        else:
            emit('emoji_sent', {'success': False, 'error': 'Not in any room'})
    
    # 对于P2P聊天
    elif target and target in user_p2p_info:
        target_info = user_p2p_info[target]
        
        # 发送表情给目标用户
        emit('p2p_chat_message_received', {
            'session_id': session_id or f'p2p_{current_user}_{target}',
            'from': current_user,
            'content': f'[表情] {emoji}',
            'timestamp': time.time(),
            'type': 'emoji'
        }, room=target_info['sid'])
        
        emit('emoji_sent', {'success': True})
    
    else:
        emit('emoji_sent', {'success': False, 'error': 'Target user not found'})

@socketio.on('send_file')
def handle_send_file(data):
    """发送文件"""
    target = data.get('target')
    file_data_b64 = data.get('file_data')
    file_name = data.get('file_name')
    file_size = data.get('file_size')
    file_type = data.get('file_type')
    session_id = data.get('session_id')
    
    if not file_data_b64 or not file_name:
        emit('file_sent', {'success': False, 'error': 'No file data or file name provided'})
        return
    
    current_user = users[request.sid]['username']
    
    try:
        # 解码base64文件数据
        file_data = base64.b64decode(file_data_b64)
        
        # 对于公共聊天
        if not target and not session_id:
            room_id = None
            for room, clients in rooms.items():
                if request.sid in clients:
                    room_id = room
                    break
            
            if room_id:
                # 公共聊天不加密文件
                emit('file_received', {
                    'sender': current_user,
                    'file_name': file_name,
                    'file_size': file_size,
                    'file_type': file_type,
                    'file_data': file_data_b64,
                    'timestamp': time.time(),
                    'room': room_id
                }, room=room_id)
                emit('file_sent', {'success': True})
            else:
                emit('file_sent', {'success': False, 'error': 'Not in any room'})
        
        # 对于P2P聊天 - 需要加密文件
        elif target and target in user_p2p_info:
            target_info = user_p2p_info[target]
            
            # 生成会话密钥
            session_key = crypto_manager.generate_session_key()
            session_key_b64 = base64.b64encode(session_key).decode('utf-8')
            
            # 加密文件数据
            # 将文件数据转换为字符串进行加密
            file_data_str = base64.b64encode(file_data).decode('utf-8')
            encrypted_file_data = crypto_manager.encrypt_with_session_key(session_key, file_data_str)
            
            # 发送加密文件给目标用户
            emit('p2p_file_received', {
                'session_id': session_id or f'p2p_{current_user}_{target}',
                'from': current_user,
                'file_name': file_name,
                'file_size': file_size,
                'file_type': file_type,
                'file_data': encrypted_file_data,  # 加密后的文件数据
                'encrypted': True,
                'session_key': session_key_b64,  # 会话密钥
                'timestamp': time.time()
            }, room=target_info['sid'])
            
            # 同时发送回给发送方，让发送方也能看到自己发送的文件
            emit('p2p_file_received', {
                'session_id': session_id or f'p2p_{current_user}_{target}',
                'from': current_user,
                'file_name': file_name,
                'file_size': file_size,
                'file_type': file_type,
                'file_data': encrypted_file_data,
                'encrypted': True,
                'session_key': session_key_b64,
                'timestamp': time.time()
            }, room=request.sid)
            
            emit('file_sent', {'success': True})
        
        else:
            emit('file_sent', {'success': False, 'error': 'Target user not found'})
    
    except Exception as e:
        print(f'文件发送错误: {e}')
        emit('file_sent', {'success': False, 'error': f'File send error: {str(e)}'})

@socketio.on('request_file_encryption')
def handle_request_file_encryption(data):
    """请求文件加密（客户端上传文件前调用）"""
    file_name = data.get('file_name')
    file_size = data.get('file_size')
    target_user = data.get('target_user')
    
    if not file_name:
        emit('file_encryption_response', {
            'success': False,
            'error': 'No file name provided'
        })
        return
    
    current_user = users[request.sid]['username']
    
    try:
        # 在实际系统中，这里应该生成加密密钥
        # 为了演示，我们返回一个模拟的加密密钥
        encryption_key = crypto_manager.generate_session_key()
        key_b64 = base64.b64encode(encryption_key).decode('utf-8')
        
        emit('file_encryption_response', {
            'success': True,
            'encryption_key': key_b64,
            'file_name': file_name,
            'target_user': target_user,
            'timestamp': time.time()
        })
    
    except Exception as e:
        print(f'文件加密请求错误: {e}')
        emit('file_encryption_response', {
            'success': False,
            'error': f'File encryption error: {str(e)}'
        })

@socketio.on('decrypt_file')
def handle_decrypt_file(data):
    """请求文件解密（客户端收到加密文件后调用）"""
    encrypted_data_b64 = data.get('encrypted_data')
    encryption_key_b64 = data.get('encryption_key')
    
    if not encrypted_data_b64 or not encryption_key_b64:
        emit('file_decryption_response', {
            'success': False,
            'error': 'No encrypted data or encryption key provided'
        })
        return
    
    try:
        # 在实际系统中，这里应该使用file_encryption_manager解密文件
        # 为了演示，我们返回一个模拟的解密结果
        encryption_key = base64.b64decode(encryption_key_b64)
        
        # 模拟解密过程
        # 在实际系统中，应该调用：file_encryption_manager.decrypt_file_data(encryption_key, encrypted_data_b64)
        
        emit('file_decryption_response', {
            'success': True,
            'decrypted': True,
            'message': 'File decrypted successfully (simulated)'
        })
    
    except Exception as e:
        print(f'文件解密错误: {e}')
        emit('file_decryption_response', {
            'success': False,
            'error': f'File decryption error: {str(e)}'
        })

def start_p2p_background():
    """启动P2P后台服务"""
    time.sleep(2)  # 等待Flask启动
    try:
        p2p_manager.start()
        print(f"P2P service started on port {p2p_manager.local_port}")
        
        # 初始化DHT网络
        dht_network.add_node('127.0.0.1', 5000)
        print("DHT network initialized")
        
        # 初始化数据库
        init_database()
        print("Database initialized")
        
        # 启动P2P消息监听器
        asyncio.run(direct_p2p_messenger.start_listening())
        print("P2P message listener started")
    except Exception as e:
        print(f"Error starting background services: {e}")


if __name__ == '__main__':
    # 1. 启动后台服务线程 (仅在直接运行 app.py 时启动)
    bg_thread = threading.Thread(target=start_p2p_background, daemon=True)
    bg_thread.start()

    # 2. 端口获取：Zeabur 会自动注入 PORT 环境变量
    port = int(os.environ.get("PORT", 5000))

    print(f'Starting P2P Chat Server on port {port}')

    # 3. 启动服务
    # 注意：生产环境建议 debug=False。allow_unsafe_werkzeug 在使用自带 server 时是必须的
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
