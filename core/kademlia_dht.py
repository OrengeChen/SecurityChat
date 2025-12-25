"""
Kademlia DHT实现
基于Kademlia协议的分布式哈希表
"""
import hashlib
import socket
import threading
import time
import json
from typing import Dict, List, Optional, Tuple, Set
from collections import OrderedDict
import random


class KBucket:
    """Kademlia K桶，存储距离相近的节点"""
    
    def __init__(self, k: int = 20):
        self.k = k  # Kademlia参数，每个桶最多存储k个节点
        self.nodes = OrderedDict()  # 节点ID -> (ip, port, last_seen)
        
    def add_node(self, node_id: str, ip: str, port: int) -> bool:
        """添加节点到K桶"""
        if node_id in self.nodes:
            # 更新最后可见时间
            self.nodes[node_id] = (ip, port, time.time())
            return True
            
        if len(self.nodes) < self.k:
            self.nodes[node_id] = (ip, port, time.time())
            return True
            
        # K桶已满，检查是否有失效节点
        oldest_node_id = None
        oldest_time = float('inf')
        
        for nid, (_, _, last_seen) in self.nodes.items():
            if time.time() - last_seen > 3600:  # 1小时未活跃
                del self.nodes[nid]
                self.nodes[node_id] = (ip, port, time.time())
                return True
                
            if last_seen < oldest_time:
                oldest_time = last_seen
                oldest_node_id = nid
                
        # 如果所有节点都活跃，替换最旧的节点
        if oldest_node_id:
            del self.nodes[oldest_node_id]
            self.nodes[node_id] = (ip, port, time.time())
            return True
            
        return False
        
    def remove_node(self, node_id: str):
        """从K桶移除节点"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            
    def get_nodes(self, count: int = None) -> List[Tuple[str, str, int]]:
        """获取节点列表"""
        nodes = []
        for node_id, (ip, port, _) in self.nodes.items():
            nodes.append((node_id, ip, port))
            if count and len(nodes) >= count:
                break
        return nodes
        
    def update_last_seen(self, node_id: str):
        """更新节点最后可见时间"""
        if node_id in self.nodes:
            ip, port, _ = self.nodes[node_id]
            self.nodes[node_id] = (ip, port, time.time())


class KademliaDHT:
    """Kademlia DHT实现"""
    
    def __init__(self, node_id: str = None, k: int = 20, alpha: int = 3):
        """
        初始化Kademlia DHT
        
        Args:
            node_id: 节点ID，None则自动生成
            k: 每个K桶大小
            alpha: 并发查询参数
        """
        self.k = k
        self.alpha = alpha
        self.node_id = node_id or self._generate_node_id()
        self.kbuckets = [KBucket(k) for _ in range(160)]  # 160位键空间
        self.data_store: Dict[str, Tuple[bytes, float]] = {}  # key -> (value, expiration)
        self.running = False
        self.socket = None
        self.listener_thread = None
        
    def _generate_node_id(self) -> str:
        """生成随机节点ID"""
        random_bytes = bytes([random.randint(0, 255) for _ in range(20)])
        return hashlib.sha1(random_bytes).hexdigest()
        
    def _distance(self, id1: str, id2: str) -> int:
        """计算两个节点ID之间的XOR距离"""
        bytes1 = bytes.fromhex(id1)
        bytes2 = bytes.fromhex(id2)
        
        # 计算XOR
        xor_bytes = bytes(a ^ b for a, b in zip(bytes1, bytes2))
        
        # 转换为整数
        return int.from_bytes(xor_bytes, 'big')
        
    def _get_kbucket_index(self, node_id: str) -> int:
        """获取节点ID对应的K桶索引"""
        distance = self._distance(self.node_id, node_id)
        
        if distance == 0:
            return 0
            
        # 找到最高有效位的位置
        index = 159  # 160位键空间
        while distance > 0:
            distance >>= 1
            index -= 1
            
        return max(0, index)
        
    def add_contact(self, node_id: str, ip: str, port: int) -> bool:
        """添加联系节点"""
        if node_id == self.node_id:
            return False  # 不添加自己
            
        # 验证节点ID格式（应该是40个字符的十六进制字符串）
        if len(node_id) != 40 or not all(c in '0123456789abcdefABCDEF' for c in node_id):
            # 如果不是标准格式，转换为标准格式
            node_id = hashlib.sha1(node_id.encode()).hexdigest()
            
        index = self._get_kbucket_index(node_id)
        return self.kbuckets[index].add_node(node_id, ip, port)
        
    def remove_contact(self, node_id: str):
        """移除联系节点"""
        index = self._get_kbucket_index(node_id)
        self.kbuckets[index].remove_node(node_id)
        
    def find_node(self, target_id: str) -> List[Tuple[str, str, int]]:
        """
        查找距离目标ID最近的节点
        
        Returns:
            距离最近的k个节点列表
        """
        # 如果target_id不是有效的十六进制，转换为十六进制
        if len(target_id) != 40 or not all(c in '0123456789abcdefABCDEF' for c in target_id):
            target_id = hashlib.sha1(target_id.encode()).hexdigest()
            
        # 获取所有已知节点
        all_nodes = []
        for kbucket in self.kbuckets:
            all_nodes.extend(kbucket.get_nodes())
            
        # 按距离排序
        sorted_nodes = sorted(
            all_nodes,
            key=lambda x: self._distance(target_id, x[0])
        )
        
        # 返回最近的k个节点
        return sorted_nodes[:self.k]
        
    def store_value(self, key: str, value: bytes, ttl: int = 86400):
        """
        存储键值对
        
        Args:
            key: 键
            value: 值
            ttl: 生存时间（秒）
        """
        expiration = time.time() + ttl
        self.data_store[key] = (value, expiration)
        
        # 同时存储到最近的节点
        key_hash = hashlib.sha1(key.encode()).hexdigest()
        closest_nodes = self.find_node(key_hash)
        
        # 这里应该实际发送存储请求到这些节点
        # 简化实现：仅记录日志
        print(f"存储键值对: {key} -> {len(value)}字节，复制到{len(closest_nodes)}个节点")
        
    def get_value(self, key: str) -> Optional[bytes]:
        """
        获取键对应的值
        
        Returns:
            值或None
        """
        if key in self.data_store:
            value, expiration = self.data_store[key]
            if time.time() < expiration:
                return value
            else:
                del self.data_store[key]  # 过期删除
                
        # 本地未找到，从网络查找
        key_hash = hashlib.sha1(key.encode()).hexdigest()
        closest_nodes = self.find_node(key_hash)
        
        # 这里应该实际发送查询请求到这些节点
        # 简化实现：返回None
        return None
        
    def start(self, ip: str = "0.0.0.0", port: int = 0):
        """启动DHT节点"""
        if self.running:
            return
            
        # 创建UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((ip, port))
        
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()
        
        actual_port = self.socket.getsockname()[1]
        print(f"Kademlia DHT节点启动: {self.node_id} 监听 {ip}:{actual_port}")
        
    def stop(self):
        """停止DHT节点"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.listener_thread:
            self.listener_thread.join(timeout=2)
            
    def _listen(self):
        """监听传入的消息"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                self._handle_message(data, addr)
            except (socket.error, OSError):
                if self.running:
                    print("DHT socket error")
                break
                
    def _handle_message(self, data: bytes, addr: Tuple[str, int]):
        """处理接收到的消息"""
        try:
            message = json.loads(data.decode('utf-8'))
            msg_type = message.get('type')
            
            if msg_type == 'ping':
                self._handle_ping(message, addr)
            elif msg_type == 'find_node':
                self._handle_find_node(message, addr)
            elif msg_type == 'store':
                self._handle_store(message, addr)
            elif msg_type == 'find_value':
                self._handle_find_value(message, addr)
                
        except Exception as e:
            print(f"处理DHT消息错误: {e}")
            
    def _handle_ping(self, message: dict, addr: Tuple[str, int]):
        """处理ping请求"""
        response = {
            'type': 'pong',
            'id': self.node_id,
            'from': message.get('id')
        }
        
        self._send_response(response, addr)
        
        # 添加/更新联系节点
        node_id = message.get('id')
        if node_id:
            self.add_contact(node_id, addr[0], addr[1])
            
    def _handle_find_node(self, message: dict, addr: Tuple[str, int]):
        """处理查找节点请求"""
        target_id = message.get('target')
        if not target_id:
            return
            
        closest_nodes = self.find_node(target_id)
        
        response = {
            'type': 'found_nodes',
            'id': self.node_id,
            'nodes': [
                {'id': nid, 'ip': ip, 'port': port}
                for nid, ip, port in closest_nodes
            ]
        }
        
        self._send_response(response, addr)
        
        # 添加/更新联系节点
        node_id = message.get('id')
        if node_id:
            self.add_contact(node_id, addr[0], addr[1])
            
    def _handle_store(self, message: dict, addr: Tuple[str, int]):
        """处理存储请求"""
        key = message.get('key')
        value = message.get('value')
        ttl = message.get('ttl', 86400)
        
        if key and value:
            self.store_value(key, value.encode(), ttl)
            
        response = {
            'type': 'store_ack',
            'id': self.node_id,
            'success': True
        }
        
        self._send_response(response, addr)
        
    def _handle_find_value(self, message: dict, addr: Tuple[str, int]):
        """处理查找值请求"""
        key = message.get('key')
        if not key:
            return
            
        value = self.get_value(key)
        
        if value:
            response = {
                'type': 'found_value',
                'id': self.node_id,
                'key': key,
                'value': value.decode()
            }
        else:
            # 未找到值，返回最近的节点
            key_hash = hashlib.sha1(key.encode()).hexdigest()
            closest_nodes = self.find_node(key_hash)
            
            response = {
                'type': 'found_nodes',
                'id': self.node_id,
                'nodes': [
                    {'id': nid, 'ip': ip, 'port': port}
                    for nid, ip, port in closest_nodes
                ]
            }
            
        self._send_response(response, addr)
        
    def _send_response(self, response: dict, addr: Tuple[str, int]):
        """发送响应"""
        try:
            data = json.dumps(response).encode('utf-8')
            self.socket.sendto(data, addr)
        except Exception as e:
            print(f"发送响应错误: {e}")
            
    def bootstrap(self, bootstrap_nodes: List[Tuple[str, str, int]]):
        """引导节点加入网络"""
        for node_id, ip, port in bootstrap_nodes:
            self.add_contact(node_id, ip, port)
            
            # 发送ping请求
            ping_msg = {
                'type': 'ping',
                'id': self.node_id
            }
            
            try:
                data = json.dumps(ping_msg).encode('utf-8')
                self.socket.sendto(data, (ip, port))
            except Exception as e:
                print(f"引导ping失败 {ip}:{port}: {e}")
                
    def get_network_info(self) -> dict:
        """获取网络信息"""
        total_nodes = 0
        for kbucket in self.kbuckets:
            total_nodes += len(kbucket.nodes)
            
        return {
            'node_id': self.node_id,
            'total_nodes': total_nodes,
            'data_items': len(self.data_store),
            'kbuckets': [
                len(kbucket.nodes) for kbucket in self.kbuckets[:10]  # 只显示前10个桶
            ]
        }


# 全局DHT实例
kademlia_dht = KademliaDHT()
