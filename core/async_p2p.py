"""
异步P2P连接模块
使用asyncio实现高性能P2P通信
"""
import asyncio
import socket
import struct
import json
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from .crypto import crypto_manager
from .stun_client import stun_client


class AsyncP2PConnection:
    """异步P2P连接类"""
    
    def __init__(self, local_port: int = 0):
        self.local_port = local_port
        self.transport = None
        self.protocol = None
        self.connections: Dict[str, asyncio.Transport] = {}
        self.peers: Dict[str, Dict] = {}
        self.shared_secrets: Dict[str, bytes] = {}
        self.private_key = None
        self.public_key = None
        self.public_key_pem = None
        self.peer_id = None
        self.running = False
        
    async def initialize(self):
        """初始化P2P连接"""
        # 生成密钥对
        self.private_key, self.public_key = crypto_manager.generate_key_pair()
        self.public_key_pem = crypto_manager.serialize_public_key(self.public_key)
        self.peer_id = hashlib.sha256(self.public_key_pem.encode()).hexdigest()[:16]
        
        # 创建事件循环
        loop = asyncio.get_event_loop()
        
        # 创建UDP端点
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: P2PProtocol(self),
            local_addr=('0.0.0.0', self.local_port)
        )
        
        self.local_port = self.transport.get_extra_info('sockname')[1]
        print(f"异步P2P服务启动在端口 {self.local_port}")
        
    async def start(self):
        """启动P2P服务"""
        if not self.transport:
            await self.initialize()
            
        self.running = True
        
        # 获取公网地址
        public_ip, public_port = await self.get_public_address()
        if public_ip and public_port:
            print(f"公网地址: {public_ip}:{public_port}")
            
        print(f"节点ID: {self.peer_id}")
        
    async def stop(self):
        """停止P2P服务"""
        self.running = False
        if self.transport:
            self.transport.close()
            
    async def get_public_address(self) -> Tuple[Optional[str], Optional[int]]:
        """获取公网IP和端口"""
        try:
            # 使用STUN获取公网地址
            result = stun_client.get_public_address(self.local_port)
            if result:
                return result
            else:
                return None, None
        except Exception as e:
            print(f"获取公网地址失败: {e}")
            return None, None
            
    async def connect_to_peer(self, ip: str, port: int, peer_public_key_pem: str = None) -> bool:
        """
        连接到对等节点
        
        Args:
            ip: 对等节点IP
            port: 对等节点端口
            peer_public_key_pem: 对等节点公钥PEM
            
        Returns:
            是否连接成功
        """
        try:
            addr = (ip, port)
            addr_str = f"{ip}:{port}"
            
            # 发送握手请求
            handshake_data = {
                'type': 'handshake_request',
                'peer_id': self.peer_id,
                'public_key': self.public_key_pem,
                'timestamp': time.time()
            }
            
            if peer_public_key_pem:
                handshake_data['expected_public_key'] = peer_public_key_pem
                
            await self.send_message(handshake_data, addr)
            
            print(f"握手请求发送到 {addr_str}")
            
            # 等待握手响应
            await asyncio.sleep(1)
            
            if peer_public_key_pem:
                # 预计算共享密钥
                peer_public_key = crypto_manager.deserialize_public_key(peer_public_key_pem)
                shared_secret = crypto_manager.derive_shared_secret(
                    self.private_key, peer_public_key
                )
                self.shared_secrets[addr_str] = shared_secret
                
            return True
            
        except Exception as e:
            print(f"连接到对等节点失败 {ip}:{port}: {e}")
            return False
            
    async def send_message(self, message: dict, addr: Tuple[str, int]):
        """发送消息到指定地址"""
        try:
            data = json.dumps(message).encode('utf-8')
            self.transport.sendto(data, addr)
        except Exception as e:
            print(f"发送消息失败: {e}")
            
    async def send_encrypted_message(self, ip: str, port: int, message: dict) -> bool:
        """发送加密消息"""
        try:
            addr_str = f"{ip}:{port}"
            if addr_str not in self.shared_secrets:
                print(f"没有共享密钥用于 {addr_str}")
                return False
                
            # 加密消息
            shared_secret = self.shared_secrets[addr_str]
            message_json = json.dumps(message)
            encrypted = crypto_manager.encrypt_message(shared_secret, message_json)
            
            # 构建加密消息
            encrypted_msg = {
                'type': 'encrypted_message',
                'data': encrypted,
                'timestamp': time.time()
            }
            
            await self.send_message(encrypted_msg, (ip, port))
            
            print(f"加密消息发送到 {addr_str}")
            return True
            
        except Exception as e:
            print(f"发送加密消息失败: {e}")
            return False
            
    def handle_message(self, data: bytes, addr: Tuple[str, int]):
        """处理接收到的消息"""
        try:
            message = json.loads(data.decode('utf-8'))
            msg_type = message.get('type')
            
            addr_str = f"{addr[0]}:{addr[1]}"
            
            if msg_type == 'handshake_request':
                self._handle_handshake_request(message, addr)
            elif msg_type == 'handshake_response':
                self._handle_handshake_response(message, addr)
            elif msg_type == 'encrypted_message':
                self._handle_encrypted_message(message, addr_str)
            elif msg_type == 'ping':
                self._handle_ping(message, addr)
            elif msg_type == 'nat_traversal':
                self._handle_nat_traversal(message, addr)
                
        except Exception as e:
            print(f"处理消息错误: {e}")
            
    def _handle_handshake_request(self, message: dict, addr: Tuple[str, int]):
        """处理握手请求"""
        try:
            peer_id = message.get('peer_id')
            peer_public_key_pem = message.get('public_key')
            
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
                'type': 'handshake_response',
                'peer_id': self.peer_id,
                'public_key': self.public_key_pem,
                'success': True,
                'timestamp': time.time()
            }
            
            # 异步发送响应
            asyncio.create_task(self.send_message(response, addr))
            
            print(f"握手完成与 {addr_str}")
            
        except Exception as e:
            print(f"处理握手请求错误: {e}")
            
    def _handle_handshake_response(self, message: dict, addr: Tuple[str, int]):
        """处理握手响应"""
        try:
            if message.get('success'):
                addr_str = f"{addr[0]}:{addr[1]}"
                print(f"握手响应来自 {addr_str}")
        except Exception as e:
            print(f"处理握手响应错误: {e}")
            
    def _handle_encrypted_message(self, message: dict, addr_str: str):
        """处理加密消息"""
        if addr_str not in self.shared_secrets:
            print(f"没有共享密钥用于 {addr_str}")
            return
            
        try:
            encrypted_data = message.get('data')
            shared_secret = self.shared_secrets[addr_str]
            decrypted = crypto_manager.decrypt_message(shared_secret, encrypted_data)
            
            # 解析消息内容
            inner_message = json.loads(decrypted)
            print(f"收到加密消息来自 {addr_str}: {inner_message.get('type', 'unknown')}")
            
        except Exception as e:
            print(f"解密消息错误: {e}")
            
    def _handle_ping(self, message: dict, addr: Tuple[str, int]):
        """处理ping消息"""
        addr_str = f"{addr[0]}:{addr[1]}"
        if addr_str in self.peers:
            self.peers[addr_str]['last_seen'] = time.time()
            
    def _handle_nat_traversal(self, message: dict, addr: Tuple[str, int]):
        """处理NAT穿透消息"""
        try:
            target_ip = message.get('target_ip')
            target_port = message.get('target_port')
            
            if target_ip and target_port:
                # 发送穿透包到目标
                punch_msg = {
                    'type': 'punch',
                    'from_ip': addr[0],
                    'from_port': addr[1],
                    'timestamp': time.time()
                }
                
                asyncio.create_task(self.send_message(punch_msg, (target_ip, target_port)))
                print(f"NAT穿透包发送到 {target_ip}:{target_port}")
                
        except Exception as e:
            print(f"处理NAT穿透错误: {e}")
            
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


class P2PProtocol(asyncio.DatagramProtocol):
    """P2P协议处理器"""
    
    def __init__(self, connection: AsyncP2PConnection):
        self.connection = connection
        
    def connection_made(self, transport):
        self.transport = transport
        
    def datagram_received(self, data, addr):
        self.connection.handle_message(data, addr)
        
    def error_received(self, exc):
        print(f"UDP错误: {exc}")
        
    def connection_lost(self, exc):
        print("UDP连接关闭")


# 全局异步P2P连接实例
async_p2p = AsyncP2PConnection()
