"""
文件加密模块
提供文件加密和解密功能
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .crypto import crypto_manager


class FileEncryptionManager:
    """文件加密管理器"""
    
    def __init__(self):
        self.backend = default_backend()
        self.chunk_size = 64 * 1024  # 64KB chunks
    
    def encrypt_file(self, key, file_path, output_path=None):
        """
        加密文件
        
        Args:
            key: 加密密钥
            file_path: 输入文件路径
            output_path: 输出文件路径（可选）
            
        Returns:
            dict: 包含加密文件信息和元数据
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        # 获取文件信息
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        # 生成文件特定的IV
        iv = os.urandom(12)
        
        # 派生文件加密密钥
        file_key = self._derive_file_key(key, iv, file_name)
        
        # 加密文件
        if output_path is None:
            output_path = file_path + '.enc'
        
        encrypted_size = 0
        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # 写入文件头：IV + 原始文件名长度 + 原始文件名
            f_out.write(iv)
            
            # 加密并写入文件名
            encrypted_name = crypto_manager.encrypt_message(key, file_name)
            name_length = len(encrypted_name).to_bytes(4, 'big')
            f_out.write(name_length)
            f_out.write(encrypted_name.encode('utf-8'))
            
            # 加密文件内容
            cipher = Cipher(
                algorithms.AES(file_key),
                modes.GCM(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            while True:
                chunk = f_in.read(self.chunk_size)
                if not chunk:
                    break
                
                encrypted_chunk = encryptor.update(chunk)
                f_out.write(encrypted_chunk)
                encrypted_size += len(encrypted_chunk)
            
            # 写入最后的tag
            f_out.write(encryptor.finalize())
            f_out.write(encryptor.tag)
        
        return {
            'original_name': file_name,
            'encrypted_path': output_path,
            'original_size': file_size,
            'encrypted_size': encrypted_size + len(iv) + 4 + len(encrypted_name) + 16,  # IV + 长度 + 文件名 + tag
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_name': encrypted_name
        }
    
    def decrypt_file(self, key, encrypted_path, output_path=None):
        """
        解密文件
        
        Args:
            key: 加密密钥
            encrypted_path: 加密文件路径
            output_path: 输出文件路径（可选）
            
        Returns:
            dict: 包含解密文件信息
        """
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError(f"加密文件不存在: {encrypted_path}")
        
        with open(encrypted_path, 'rb') as f_in:
            # 读取IV
            iv = f_in.read(12)
            
            # 读取文件名长度
            name_length_bytes = f_in.read(4)
            if len(name_length_bytes) != 4:
                raise ValueError("无效的加密文件格式")
            name_length = int.from_bytes(name_length_bytes, 'big')
            
            # 读取加密的文件名
            encrypted_name_bytes = f_in.read(name_length)
            encrypted_name = encrypted_name_bytes.decode('utf-8')
            
            # 解密文件名
            try:
                original_name = crypto_manager.decrypt_message(key, encrypted_name)
            except Exception as e:
                raise ValueError(f"文件名解密失败: {str(e)}")
            
            # 派生文件加密密钥
            file_key = self._derive_file_key(key, iv, original_name)
            
            # 确定输出路径
            if output_path is None:
                output_path = os.path.join(
                    os.path.dirname(encrypted_path),
                    original_name
                )
            
            # 解密文件内容
            cipher = Cipher(
                algorithms.AES(file_key),
                modes.GCM(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # 读取文件内容（不包括最后的tag）
            file_content = f_in.read()
            if len(file_content) < 16:
                raise ValueError("无效的加密文件格式")
            
            # 分离内容和tag
            ciphertext = file_content[:-16]
            tag = file_content[-16:]
            
            # 创建解密器（带tag）
            cipher_with_tag = Cipher(
                algorithms.AES(file_key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor_with_tag = cipher_with_tag.decryptor()
            
            # 解密并写入文件
            decrypted_size = 0
            with open(output_path, 'wb') as f_out:
                # 处理大文件，分块解密
                for i in range(0, len(ciphertext), self.chunk_size):
                    chunk = ciphertext[i:i + self.chunk_size]
                    decrypted_chunk = decryptor_with_tag.update(chunk)
                    f_out.write(decrypted_chunk)
                    decrypted_size += len(decrypted_chunk)
                
                f_out.write(decryptor_with_tag.finalize())
        
        return {
            'original_name': original_name,
            'decrypted_path': output_path,
            'decrypted_size': decrypted_size
        }
    
    def encrypt_file_data(self, key, file_data, file_name):
        """
        加密文件数据（内存中）
        
        Args:
            key: 加密密钥
            file_data: 文件二进制数据
            file_name: 文件名
            
        Returns:
            dict: 包含加密数据和元数据
        """
        # 生成IV
        iv = os.urandom(12)
        
        # 派生文件加密密钥
        file_key = self._derive_file_key(key, iv, file_name)
        
        # 加密文件名
        encrypted_name = crypto_manager.encrypt_message(key, file_name)
        
        # 加密文件内容
        cipher = Cipher(
            algorithms.AES(file_key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        encrypted_content = encryptor.update(file_data) + encryptor.finalize()
        
        # 构建加密数据包：IV + 文件名长度 + 加密文件名 + 加密内容 + tag
        name_length = len(encrypted_name).to_bytes(4, 'big')
        encrypted_package = (
            iv +
            name_length +
            encrypted_name.encode('utf-8') +
            encrypted_content +
            encryptor.tag
        )
        
        return {
            'encrypted_data': base64.b64encode(encrypted_package).decode('utf-8'),
            'original_name': file_name,
            'original_size': len(file_data),
            'encrypted_size': len(encrypted_package),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
    
    def decrypt_file_data(self, key, encrypted_data_b64):
        """
        解密文件数据（内存中）
        
        Args:
            key: 加密密钥
            encrypted_data_b64: base64编码的加密数据
            
        Returns:
            dict: 包含解密数据和文件名
        """
        # 解码base64数据
        encrypted_package = base64.b64decode(encrypted_data_b64)
        
        # 解析数据包
        iv = encrypted_package[:12]
        
        name_length = int.from_bytes(encrypted_package[12:16], 'big')
        encrypted_name = encrypted_package[16:16 + name_length].decode('utf-8')
        
        # 解密文件名
        original_name = crypto_manager.decrypt_message(key, encrypted_name)
        
        # 派生文件加密密钥
        file_key = self._derive_file_key(key, iv, original_name)
        
        # 分离内容和tag
        content_start = 16 + name_length
        ciphertext = encrypted_package[content_start:-16]
        tag = encrypted_package[-16:]
        
        # 解密内容
        cipher = Cipher(
            algorithms.AES(file_key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        return {
            'file_data': decrypted_data,
            'file_name': original_name,
            'original_size': len(decrypted_data)
        }
    
    def _derive_file_key(self, master_key, iv, file_name):
        """派生文件特定的加密密钥"""
        # 使用HKDF从主密钥派生文件密钥
        info = f"file-key:{file_name}:{base64.b64encode(iv).decode('utf-8')}".encode('utf-8')
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=self.backend
        )
        
        return hkdf.derive(master_key)
    
    def get_file_info(self, file_path):
        """获取文件信息"""
        if not os.path.exists(file_path):
            return None
        
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_extension = os.path.splitext(file_name)[1].lower()
        
        # 根据文件扩展名确定文件类型
        file_types = {
            '.txt': 'text',
            '.pdf': 'document',
            '.doc': 'document',
            '.docx': 'document',
            '.jpg': 'image',
            '.jpeg': 'image',
            '.png': 'image',
            '.gif': 'image',
            '.mp3': 'audio',
            '.mp4': 'video',
            '.avi': 'video',
            '.zip': 'archive',
            '.rar': 'archive'
        }
        
        file_type = file_types.get(file_extension, 'unknown')
        
        return {
            'name': file_name,
            'size': file_size,
            'type': file_type,
            'extension': file_extension
        }


# 全局文件加密管理器实例
file_encryption_manager = FileEncryptionManager()
