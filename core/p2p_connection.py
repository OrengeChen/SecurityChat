"""
P2P连接管理模块
处理直接的点对点连接，包括NAT穿透和直接通信
"""
import socket
import threading
import time
import json
import hashlib
from typing import Dict, List, Optional, Tuple
import struct
from .crypto import crypto_manager

class P2PConnection:
    """P2P连接类"""
    
    def __init__(self, local_port: int = 0):
        self.local_port = local_port
        self.socket = None
        self.connections: Dict[str, socket.socket] = {}
        self.peers: Dict[str, Dict] = {}
        self.running = False
        self.listener_thread = None
        self.private_key = None
        self.public_key = None
        self.shared_secrets: Dict[str, bytes] = {}
        
    def initialize(self):
        """初始化P2P连接"""
        # 生成密钥对
        self.private_key, self.public_key = crypto_manager.generate_key_pair()
        
        # 创建UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        if self.local_port:
            self.socket.bind(('0.0.0.0', self.local_port))
        else:
            self.socket.bind(('0.0.0.0', 0))
            self.local_port = self.socket.getsockname()[1]
        
        print(f"P2P socket bound to port {self.local_port}")
        
    def start(self):
        """启动P2P服务"""
        if not self.socket:
            self.initialize()
        
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()
        print(f"P2P service started on port {self.local_port}")
        
    def stop(self):
        """停止P2P服务"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.listener_thread:
            self.listener_thread.join(timeout=2)
        print("P2P service stopped")
        
    def _listen(self):
        """监听传入的消息"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                self._handle_message(data, addr)
            except (socket.error, OSError):
                if self.running:
                    print("Socket error in listener")
                break
                
    def _handle_message(self, data: bytes, addr: Tuple[str, int]):
        """处理接收到的消息"""
        try:
            # 解析消息头
            if len(data) < 4:
                return
                
            msg_type = data[0]
            payload = data[1:]
            
            addr_str = f"{addr[0]}:{addr[1]}"
            
            if msg_type == 0x01:  # 握手请求
                self._handle_handshake(payload, addr)
            elif msg_type == 0x02:  # 握手响应
                self._handle_handshake_response(payload, addr)
            elif msg_type == 0x03:  # 加密消息
                self._handle_encrypted_message(payload, addr_str)
            elif msg_type == 0x04:  # 心跳
                self._handle_heartbeat(addr)
            elif msg_type == 0x05:  # NAT穿透请求
                self._handle_nat_traversal(payload, addr)
                
        except Exception as e:
            print(f"Error handling message from {addr}: {e}")
            
    def _handle_handshake(self, payload: bytes, addr: Tuple[str, int]):
        """处理握手请求"""
        try:
            # 解析公钥和节点信息
            peer_info = json.loads(payload.decode('utf-8'))
            peer_public_key_pem = peer_info.get('public_key')
            peer_id = peer_info.get('peer_id')
            
            if not peer_public_key_pem or not peer_id:
                return
                
            # 反序列化公钥
            peer_public_key = crypto_manager.deserialize_public_key(peer_public_key_pem)
            
            # 派生共享密钥
            shared_secret = crypto_manager.derive_shared_secret(
                self.private_key, peer_public_key
            )
            
            addr_str = f"{addr[0]}:{addr[1]}"
            self.shared_secrets[addr_str] = shared_secret
            self.peers[addr_str] = {
                'public_key': peer_public_key_pem,
                'peer_id': peer_id,
                'address': addr[0],
                'port': addr[1],
                'last_seen': time.time()
            }
            
            # 发送握手响应
            response = {
                'public_key': crypto_manager.serialize_public_key(self.public_key),
                'peer_id': hashlib.sha256(
                    crypto_manager.serialize_public_key(self.public_key).encode()
                ).hexdigest()[:16],
                'success': True
            }
            
            response_data = json.dumps(response).encode('utf-8')
            self._send_message(0x02, response_data, addr)
            
            print(f"Handshake completed with {addr_str}")
            
        except Exception as e:
            print(f"Error in handshake: {e}")
            
    def _handle_handshake_response(self, payload: bytes, addr: Tuple[str, int]):
        """处理握手响应"""
        try:
            response = json.loads(payload.decode('utf-8'))
            if response.get('success'):
                addr_str = f"{addr[0]}:{addr[1]}"
                print(f"Handshake response received from {addr_str}")
        except Exception as e:
            print(f"Error handling handshake response: {e}")
            
    def _handle_encrypted_message(self, payload: bytes, addr_str: str):
        """处理加密消息"""
        if addr_str not in self.shared_secrets:
            print(f"No shared secret for {addr_str}")
            return
            
        try:
            # 解密消息
            encrypted_data = payload.decode('utf-8')
            shared_secret = self.shared_secrets[addr_str]
            decrypted = crypto_manager.decrypt_message(shared_secret, encrypted_data)
            
            # 解析消息内容
            message = json.loads(decrypted)
            print(f"Received encrypted message from {addr_str}: {message.get('type', 'unknown')}")
            
            # 这里可以触发事件或回调
            self._on_message_received(addr_str, message)
            
        except Exception as e:
            print(f"Error decrypting message: {e}")
            
    def _handle_heartbeat(self, addr: Tuple[str, int]):
        """处理心跳"""
        addr_str = f"{addr[0]}:{addr[1]}"
        if addr_str in self.peers:
            self.peers[addr_str]['last_seen'] = time.time()
            
    def _handle_nat_traversal(self, payload: bytes, addr: Tuple[str, int]):
        """处理NAT穿透请求"""
        try:
            request = json.loads(payload.decode('utf-8'))
            target_addr = (request['target_ip'], request['target_port'])
            
            # 发送穿透包到目标
            punch_packet = b'\x06' + json.dumps({
                'type': 'punch',
                'from_ip': addr[0],
                'from_port': addr[1]
            }).encode('utf-8')
            
            self.socket.sendto(punch_packet, target_addr)
            print(f"NAT traversal packet sent to {target_addr}")
            
        except Exception as e:
            print(f"Error in NAT traversal: {e}")
            
    def _on_message_received(self, addr_str: str, message: dict):
        """消息接收回调（子类可重写）"""
        pass
        
    def _send_message(self, msg_type: int, payload: bytes, addr: Tuple[str, int]):
        """发送消息"""
        try:
            packet = bytes([msg_type]) + payload
            self.socket.sendto(packet, addr)
        except Exception as e:
            print(f"Error sending message to {addr}: {e}")
            
    def connect_to_peer(self, ip: str, port: int, peer_public_key_pem: str = None):
        """连接到对等节点"""
        try:
            addr = (ip, port)
            addr_str = f"{ip}:{port}"
            
            # 发送握手请求
            handshake_data = {
                'public_key': crypto_manager.serialize_public_key(self.public_key),
                'peer_id': hashlib.sha256(
                    crypto_manager.serialize_public_key(self.public_key).encode()
                ).hexdigest()[:16]
            }
            
            if peer_public_key_pem:
                handshake_data['expected_public_key'] = peer_public_key_pem
                
            payload = json.dumps(handshake_data).encode('utf-8')
            self._send_message(0x01, payload, addr)
            
            print(f"Handshake request sent to {addr_str}")
            
            # 等待握手完成（简化实现）
            time.sleep(1)
            
            if peer_public_key_pem:
                peer_public_key = crypto_manager.deserialize_public_key(peer_public_key_pem)
                shared_secret = crypto_manager.derive_shared_secret(
                    self.private_key, peer_public_key
                )
                self.shared_secrets[addr_str] = shared_secret
                
            return True
            
        except Exception as e:
            print(f"Error connecting to peer {ip}:{port}: {e}")
            return False
            
    def send_encrypted_message(self, ip: str, port: int, message: dict) -> bool:
        """发送加密消息"""
        try:
            addr_str = f"{ip}:{port}"
            if addr_str not in self.shared_secrets:
                print(f"No shared secret for {addr_str}")
                return False
                
            # 加密消息
            shared_secret = self.shared_secrets[addr_str]
            message_json = json.dumps(message)
            encrypted = crypto_manager.encrypt_message(shared_secret, message_json)
            
            # 发送
            payload = encrypted.encode('utf-8')
            self._send_message(0x03, payload, (ip, port))
            
            print(f"Encrypted message sent to {addr_str}")
            return True
            
        except Exception as e:
            print(f"Error sending encrypted message: {e}")
            return False
            
    def get_public_key_pem(self) -> str:
        """获取公钥PEM字符串"""
        return crypto_manager.serialize_public_key(self.public_key)
        
    def get_peer_id(self) -> str:
        """获取节点ID"""
        return hashlib.sha256(
            crypto_manager.serialize_public_key(self.public_key).encode()
        ).hexdigest()[:16]
        
    def get_connected_peers(self) -> List[Dict]:
        """获取已连接的节点列表"""
        peers = []
        for addr_str, info in self.peers.items():
            if time.time() - info['last_seen'] < 60:  # 60秒内活跃
                peers.append({
                    'address': info['address'],
                    'port': info['port'],
                    'peer_id': info['peer_id'],
                    'last_seen': info['last_seen']
                })
        return peers

# 全局P2P连接管理器
p2p_manager = P2PConnection()

__all__ = ['P2PConnection', 'p2p_manager']
