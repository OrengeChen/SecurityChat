"""
分布式哈希表（DHT）模块
模拟P2P网络中的节点发现和路由功能
"""
import hashlib
import json
from typing import Dict, List, Optional, Tuple
import time

class DHTNode:
    """DHT节点"""
    
    def __init__(self, node_id: str, address: str, port: int):
        self.node_id = node_id
        self.address = address
        self.port = port
        self.last_seen = time.time()
        self.buckets = {}  # 路由表桶
        self.data_store = {}  # 存储的键值对
    
    def update_last_seen(self):
        """更新最后活跃时间"""
        self.last_seen = time.time()
    
    def store(self, key: str, value: str):
        """存储键值对"""
        self.data_store[key] = {
            'value': value,
            'timestamp': time.time()
        }
    
    def get(self, key: str) -> Optional[str]:
        """获取键对应的值"""
        if key in self.data_store:
            return self.data_store[key]['value']
        return None
    
    def __repr__(self):
        return f"DHTNode(id={self.node_id[:8]}..., addr={self.address}:{self.port})"

class DHTNetwork:
    """DHT网络"""
    
    def __init__(self):
        self.nodes: Dict[str, DHTNode] = {}
        self.key_bits = 160  # SHA-1哈希长度
    
    @staticmethod
    def generate_node_id(address: str, port: int) -> str:
        """生成节点ID"""
        data = f"{address}:{port}:{time.time()}".encode('utf-8')
        return hashlib.sha1(data).hexdigest()
    
    def add_node(self, address: str, port: int) -> DHTNode:
        """添加新节点到网络"""
        node_id = self.generate_node_id(address, port)
        node = DHTNode(node_id, address, port)
        self.nodes[node_id] = node
        
        # 更新其他节点的路由表
        for existing_node in self.nodes.values():
            if existing_node.node_id != node_id:
                self._update_routing_table(existing_node, node)
        
        print(f"Node added: {node}")
        return node
    
    def remove_node(self, node_id: str):
        """从网络移除节点"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            print(f"Node removed: {node_id[:8]}...")
    
    def find_node(self, target_id: str) -> List[DHTNode]:
        """查找最接近目标ID的节点"""
        nodes = list(self.nodes.values())
        # 按节点ID与目标ID的XOR距离排序
        nodes.sort(key=lambda n: self._xor_distance(n.node_id, target_id))
        return nodes[:8]  # 返回最接近的8个节点
    
    def store_value(self, key: str, value: str):
        """在DHT中存储值"""
        key_hash = hashlib.sha1(key.encode('utf-8')).hexdigest()
        
        # 找到负责存储该键的节点
        responsible_nodes = self.find_node(key_hash)
        
        for node in responsible_nodes[:3]:  # 存储在3个节点上以实现冗余
            node.store(key_hash, value)
            print(f"Stored key {key_hash[:8]}... on node {node.node_id[:8]}...")
    
    def get_value(self, key: str) -> Optional[str]:
        """从DHT获取值"""
        key_hash = hashlib.sha1(key.encode('utf-8')).hexdigest()
        
        # 查找负责该键的节点
        responsible_nodes = self.find_node(key_hash)
        
        for node in responsible_nodes:
            value = node.get(key_hash)
            if value:
                print(f"Retrieved key {key_hash[:8]}... from node {node.node_id[:8]}...")
                return value
        
        return None
    
    def _xor_distance(self, id1: str, id2: str) -> int:
        """计算两个ID之间的XOR距离"""
        # 将十六进制字符串转换为整数进行XOR运算
        return int(id1, 16) ^ int(id2, 16)
    
    def _update_routing_table(self, node: DHTNode, new_node: DHTNode):
        """更新节点的路由表"""
        # 简化实现：将新节点添加到适当的桶中
        distance = self._xor_distance(node.node_id, new_node.node_id)
        bucket_index = self._get_bucket_index(distance)
        
        if bucket_index not in node.buckets:
            node.buckets[bucket_index] = []
        
        # 如果桶未满，添加新节点
        if len(node.buckets[bucket_index]) < 8:
            node.buckets[bucket_index].append(new_node.node_id)
    
    def _get_bucket_index(self, distance: int) -> int:
        """根据距离计算桶索引"""
        # 找到最高有效位的位置
        if distance == 0:
            return 0
        
        index = 0
        while distance > 0:
            distance >>= 1
            index += 1
        
        return min(index, self.key_bits - 1)
    
    def get_network_info(self) -> Dict:
        """获取网络信息"""
        return {
            'total_nodes': len(self.nodes),
            'nodes': [
                {
                    'id': node.node_id[:16],
                    'address': node.address,
                    'port': node.port,
                    'data_items': len(node.data_store)
                }
                for node in self.nodes.values()
            ]
        }

# 全局DHT网络实例
dht_network = DHTNetwork()
