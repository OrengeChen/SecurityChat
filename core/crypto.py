"""
加密模块
提供端到端加密功能，包括密钥生成、加密、解密等
"""
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os


class CryptoManager:
    """加密管理器"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key_pair(self):
        """生成ECDH密钥对"""
        private_key = ec.generate_private_key(
            ec.SECP256R1(),  # 使用P-256曲线
            self.backend
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def serialize_public_key(self, public_key):
        """序列化公钥为PEM格式"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def deserialize_public_key(self, pem_string):
        """从PEM字符串反序列化公钥"""
        public_key = serialization.load_pem_public_key(
            pem_string.encode('utf-8'),
            backend=self.backend
        )
        return public_key
    
    def derive_shared_secret(self, private_key, peer_public_key):
        """派生共享密钥"""
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # 使用HKDF派生加密密钥
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'p2p-chat-key',
            backend=self.backend
        ).derive(shared_key)
        
        return derived_key
    
    def encrypt_message(self, key, message):
        """使用AES-GCM加密消息"""
        # 生成IV
        iv = os.urandom(12)
        
        # 创建加密器
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # 加密
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        
        # 返回IV + 密文 + tag
        encrypted_data = iv + ciphertext + encryptor.tag
        
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_message(self, key, encrypted_data):
        """解密消息"""
        # 在实际应用中，这里应该使用AES-GCM解密
        # 这里返回模拟解密结果
        try:
            data = base64.b64decode(encrypted_data)
            iv = data[:12]
            ciphertext = data[12:-16]
            tag = data[-16:]
            
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"解密失败: {str(e)}")
    
    def sign_message(self, private_key, message):
        """使用私钥签名消息"""
        signature = private_key.sign(
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, public_key, message, signature):
        """验证签名"""
        try:
            sig_bytes = base64.b64decode(signature)
            public_key.verify(
                sig_bytes,
                message.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False
            
    def get_public_key_fingerprint(self, public_key_pem: str) -> str:
        """获取公钥指纹"""
        # 计算SHA256哈希
        hash_obj = hashlib.sha256(public_key_pem.encode())
        # 转换为Base64
        fingerprint = base64.b64encode(hash_obj.digest()).decode('utf-8')
        # 取前16个字符作为简化指纹
        return fingerprint[:32]
        
    def verify_public_key_fingerprint(self, public_key_pem: str, expected_fingerprint: str) -> bool:
        """验证公钥指纹"""
        actual_fingerprint = self.get_public_key_fingerprint(public_key_pem)
        return actual_fingerprint == expected_fingerprint
        
    def generate_session_key(self) -> bytes:
        """生成随机会话密钥"""
        return os.urandom(32)
        
    def encrypt_with_session_key(self, session_key: bytes, message: str) -> str:
        """使用会话密钥加密消息"""
        return self.encrypt_message(session_key, message)
        
    def decrypt_with_session_key(self, session_key: bytes, encrypted_data: str) -> str:
        """使用会话密钥解密消息"""
        return self.decrypt_message(session_key, encrypted_data)

# 全局加密管理器实例
crypto_manager = CryptoManager()
