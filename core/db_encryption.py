"""
数据库加密模块
对SQLite数据库文件进行加密保护
"""
import sqlite3
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64


class DatabaseEncryptor:
    """数据库加密器"""
    
    def __init__(self, db_path: str, encryption_key: bytes = None):
        """
        初始化数据库加密器
        
        Args:
            db_path: 数据库文件路径
            encryption_key: 加密密钥，None则自动生成
        """
        self.db_path = db_path
        self.encryption_key = encryption_key or self._generate_key()
        self.backend = default_backend()
        
    def _generate_key(self) -> bytes:
        """生成加密密钥"""
        # 使用SHA256哈希生成32字节密钥
        random_data = os.urandom(32)
        return hashlib.sha256(random_data).digest()
        
    def encrypt_database(self):
        """加密整个数据库文件"""
        try:
            # 读取数据库文件
            with open(self.db_path, 'rb') as f:
                db_data = f.read()
                
            # 生成IV
            iv = os.urandom(12)
            
            # 创建加密器
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # 加密数据
            ciphertext = encryptor.update(db_data) + encryptor.finalize()
            
            # 组合IV + 密文 + tag
            encrypted_data = iv + ciphertext + encryptor.tag
            
            # 写入加密文件
            encrypted_path = self.db_path + '.enc'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
                
            print(f"数据库加密完成: {encrypted_path}")
            return True
            
        except Exception as e:
            print(f"数据库加密失败: {e}")
            return False
            
    def decrypt_database(self, output_path: str = None):
        """解密数据库文件"""
        try:
            encrypted_path = self.db_path + '.enc'
            if not os.path.exists(encrypted_path):
                print(f"加密文件不存在: {encrypted_path}")
                return False
                
            # 读取加密文件
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
                
            # 提取IV、密文和tag
            iv = encrypted_data[:12]
            ciphertext = encrypted_data[12:-16]
            tag = encrypted_data[-16:]
            
            # 创建解密器
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # 解密数据
            db_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # 写入解密文件
            output_path = output_path or self.db_path
            with open(output_path, 'wb') as f:
                f.write(db_data)
                
            print(f"数据库解密完成: {output_path}")
            return True
            
        except Exception as e:
            print(f"数据库解密失败: {e}")
            return False
            
    def encrypt_field(self, plaintext: str) -> str:
        """加密数据库字段"""
        try:
            # 生成IV
            iv = os.urandom(12)
            
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            encrypted_data = iv + ciphertext + encryptor.tag
            
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            print(f"字段加密失败: {e}")
            return plaintext
            
    def decrypt_field(self, encrypted_text: str) -> str:
        """解密切数据库字段"""
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            
            iv = encrypted_data[:12]
            ciphertext = encrypted_data[12:-16]
            tag = encrypted_data[-16:]
            
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
            
        except Exception as e:
            print(f"字段解密失败: {e}")
            return encrypted_text
            
    def get_key_hash(self) -> str:
        """获取密钥哈希（用于验证）"""
        return hashlib.sha256(self.encryption_key).hexdigest()
        
    def save_key_to_file(self, key_file: str):
        """保存密钥到文件"""
        try:
            with open(key_file, 'wb') as f:
                f.write(self.encryption_key)
            print(f"密钥保存到: {key_file}")
            return True
        except Exception as e:
            print(f"保存密钥失败: {e}")
            return False
            
    def load_key_from_file(self, key_file: str):
        """从文件加载密钥"""
        try:
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
            print(f"密钥从文件加载: {key_file}")
            return True
        except Exception as e:
            print(f"加载密钥失败: {e}")
            return False


class EncryptedSQLiteConnection:
    """加密的SQLite连接"""
    
    def __init__(self, db_path: str, encryption_key: bytes = None):
        self.db_path = db_path
        self.encryptor = DatabaseEncryptor(db_path, encryption_key)
        self.connection = None
        
    def connect(self):
        """连接到数据库（自动解密）"""
        # 如果存在加密文件，先解密
        encrypted_path = self.db_path + '.enc'
        if os.path.exists(encrypted_path):
            self.encryptor.decrypt_database()
            
        self.connection = sqlite3.connect(self.db_path)
        return self.connection
        
    def close(self, encrypt: bool = True):
        """关闭连接（可选加密）"""
        if self.connection:
            self.connection.close()
            
        if encrypt:
            self.encryptor.encrypt_database()
            # 删除明文数据库文件
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
                
    def execute(self, sql: str, params=()):
        """执行SQL语句"""
        if not self.connection:
            self.connect()
            
        cursor = self.connection.cursor()
        cursor.execute(sql, params)
        return cursor
        
    def commit(self):
        """提交事务"""
        if self.connection:
            self.connection.commit()


# 全局数据库加密器实例
db_encryptor = DatabaseEncryptor('p2p_chat.db')


def encrypt_sensitive_fields(data: dict) -> dict:
    """加密敏感字段"""
    encrypted_data = data.copy()
    
    # 需要加密的字段
    sensitive_fields = ['private_key', 'encrypted_content', 'signature']
    
    for field in sensitive_fields:
        if field in encrypted_data and encrypted_data[field]:
            encrypted_data[field] = db_encryptor.encrypt_field(encrypted_data[field])
            
    return encrypted_data


def decrypt_sensitive_fields(data: dict) -> dict:
    """解密切敏感字段"""
    decrypted_data = data.copy()
    
    # 需要解密的字段
    sensitive_fields = ['private_key', 'encrypted_content', 'signature']
    
    for field in sensitive_fields:
        if field in decrypted_data and decrypted_data[field]:
            try:
                decrypted_data[field] = db_encryptor.decrypt_field(decrypted_data[field])
            except:
                # 如果解密失败，保持原样
                pass
                
    return decrypted_data


def init_encrypted_database():
    """初始化加密数据库"""
    # 检查是否需要加密
    db_path = 'p2p_chat.db'
    encrypted_path = db_path + '.enc'
    
    if os.path.exists(db_path) and not os.path.exists(encrypted_path):
        print("开始加密数据库...")
        db_encryptor.encrypt_database()
        print("数据库加密完成")
    elif os.path.exists(encrypted_path):
        print("数据库已加密")
    else:
        print("数据库文件不存在，将创建新数据库")
