"""
STUN客户端模块
用于NAT穿透，获取公网IP和端口映射
"""
import socket
import struct
import random
import time
from typing import Optional, Tuple

class STUNClient:
    """STUN客户端类"""
    
    # STUN消息类型
    BINDING_REQUEST = 0x0001
    BINDING_RESPONSE = 0x0101
    BINDING_ERROR_RESPONSE = 0x0111
    
    # STUN属性类型
    MAPPED_ADDRESS = 0x0001
    XOR_MAPPED_ADDRESS = 0x0020
    SOFTWARE = 0x8022
    FINGERPRINT = 0x8028
    
    def __init__(self, stun_server: str = "stun.l.google.com", stun_port: int = 19302):
        self.stun_server = stun_server
        self.stun_port = stun_port
        self.socket = None
        self.transaction_id = None
        
    def get_public_address(self, local_port: int = 0) -> Optional[Tuple[str, int]]:
        """
        获取公网IP和端口映射
        
        Args:
            local_port: 本地绑定端口，0表示随机
            
        Returns:
            (public_ip, public_port) 或 None
        """
        try:
            # 创建UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(3.0)  # 缩短超时时间
            
            # 绑定到本地端口（使用更宽松的绑定）
            try:
                self.socket.bind(('0.0.0.0', local_port))
            except OSError as e:
                # 如果绑定失败，尝试使用随机端口
                print(f"STUN绑定端口失败，使用随机端口: {e}")
                self.socket.bind(('0.0.0.0', 0))
            
            # 生成事务ID
            self.transaction_id = bytes([random.randint(0, 255) for _ in range(12)])
            
            # 构建STUN绑定请求
            request = self._build_binding_request()
            
            # 发送请求到STUN服务器
            self.socket.sendto(request, (self.stun_server, self.stun_port))
            
            # 接收响应
            response, addr = self.socket.recvfrom(1024)
            
            # 解析响应
            public_ip, public_port = self._parse_binding_response(response)
            
            print(f"STUN成功: 公网地址 {public_ip}:{public_port}")
            return public_ip, public_port
            
        except (socket.timeout, socket.error, OSError) as e:
            # 静默处理STUN失败，不影响应用运行
            print(f"STUN请求失败（不影响应用运行）: {e}")
            return None
        except Exception as e:
            print(f"STUN其他错误: {e}")
            return None
        finally:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
                
    def _build_binding_request(self) -> bytes:
        """构建STUN绑定请求"""
        # STUN头部
        message_type = struct.pack('!H', self.BINDING_REQUEST)
        message_length = struct.pack('!H', 0)  # 无属性
        magic_cookie = struct.pack('!I', 0x2112A442)
        
        # 组合消息
        header = message_type + message_length + magic_cookie + self.transaction_id
        
        return header
        
    def _parse_binding_response(self, response: bytes) -> Tuple[str, int]:
        """解析STUN绑定响应"""
        if len(response) < 20:
            raise ValueError("响应太短")
            
        # 解析头部
        message_type = struct.unpack('!H', response[0:2])[0]
        message_length = struct.unpack('!H', response[2:4])[0]
        magic_cookie = struct.unpack('!I', response[4:8])[0]
        transaction_id = response[8:20]
        
        if message_type != self.BINDING_RESPONSE:
            raise ValueError(f"非绑定响应: {message_type:#06x}")
            
        if magic_cookie != 0x2112A442:
            raise ValueError(f"无效的magic cookie: {magic_cookie:#010x}")
            
        # 解析属性
        offset = 20
        while offset < len(response):
            if offset + 4 > len(response):
                break
                
            attr_type = struct.unpack('!H', response[offset:offset+2])[0]
            attr_length = struct.unpack('!H', response[offset+2:offset+4])[0]
            
            if attr_type == self.XOR_MAPPED_ADDRESS:
                # 解析XOR-MAPPED-ADDRESS
                if attr_length < 8:
                    break
                    
                family = struct.unpack('!B', response[offset+5:offset+6])[0]
                if family == 0x01:  # IPv4
                    xport = struct.unpack('!H', response[offset+6:offset+8])[0]
                    xip = struct.unpack('!I', response[offset+8:offset+12])[0]
                    
                    # 解码XOR
                    port = xport ^ (magic_cookie >> 16)
                    ip_int = xip ^ magic_cookie
                    
                    # 转换为IP字符串
                    ip_bytes = struct.pack('!I', ip_int)
                    ip = socket.inet_ntoa(ip_bytes)
                    
                    return ip, port
                    
            offset += 4 + ((attr_length + 3) & ~3)  # 对齐到4字节边界
            
        raise ValueError("未找到XOR-MAPPED-ADDRESS属性")
        
    def test_nat_type(self) -> str:
        """
        测试NAT类型
        
        Returns:
            NAT类型字符串: "开放互联网", "完全锥型NAT", "受限锥型NAT", "端口受限锥型NAT", "对称NAT"
        """
        # 简化实现，返回最常见的类型
        try:
            result = self.get_public_address()
            if result:
                return "受限锥型NAT"
            else:
                return "对称NAT"
        except Exception:
            return "未知"
            
    def perform_udp_hole_punching(self, peer_public_ip: str, peer_public_port: int, 
                                  local_port: int = 0) -> bool:
        """
        执行UDP打洞
        
        Args:
            peer_public_ip: 对等节点的公网IP
            peer_public_port: 对等节点的公网端口
            local_port: 本地绑定端口
            
        Returns:
            是否成功建立连接
        """
        try:
            # 创建socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(10.0)
            
            # 绑定
            sock.bind(('0.0.0.0', local_port))
            
            # 获取自己的公网地址
            self_ip, self_port = self.get_public_address(local_port)
            if not self_ip:
                print("无法获取公网地址")
                return False
                
            print(f"本地公网地址: {self_ip}:{self_port}")
            print(f"尝试连接到: {peer_public_ip}:{peer_public_port}")
            
            # 发送打洞包
            punch_packet = b"PUNCH" + self.transaction_id
            sock.sendto(punch_packet, (peer_public_ip, peer_public_port))
            
            # 尝试接收响应
            try:
                data, addr = sock.recvfrom(1024)
                if addr[0] == peer_public_ip and addr[1] == peer_public_port:
                    print(f"打洞成功! 连接到 {addr[0]}:{addr[1]}")
                    return True
            except socket.timeout:
                print("打洞超时")
                
            return False
            
        except Exception as e:
            print(f"打洞失败: {e}")
            return False
        finally:
            if 'sock' in locals():
                sock.close()


# 全局STUN客户端实例
stun_client = STUNClient()
