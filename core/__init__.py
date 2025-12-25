"""
P2P聊天系统核心模块
包含加密、DHT、数据库、P2P连接等核心功能
"""

from .crypto import crypto_manager, CryptoManager
from .dht import dht_network, DHTNetwork, DHTNode
from .kademlia_dht import kademlia_dht, KademliaDHT, KBucket
from .stun_client import stun_client, STUNClient
from .database import (
    DatabaseManager, User, Message, Room, KeyPair,
    get_db, init_database, create_tables
)
from .p2p_connection import p2p_manager, P2PConnection
from .async_p2p import async_p2p, AsyncP2PConnection, P2PProtocol
from .db_encryption import (
    db_encryptor, DatabaseEncryptor, EncryptedSQLiteConnection,
    encrypt_sensitive_fields, decrypt_sensitive_fields, init_encrypted_database
)
from .advanced_protection import (
    advanced_protection, AdvancedProtectionManager,
    PaddingManager, MessageSigner, SessionKeyManager,
    AntiReplayManager, EphemeralMessageManager
)
from .real_p2p_chat import (
    p2p_chat_manager, P2PChatManager, P2PChatSession,
    direct_p2p_messenger, DirectP2PMessenger
)

__all__ = [
    'crypto_manager',
    'CryptoManager',
    'dht_network',
    'DHTNetwork',
    'DHTNode',
    'kademlia_dht',
    'KademliaDHT',
    'KBucket',
    'stun_client',
    'STUNClient',
    'DatabaseManager',
    'User',
    'Message',
    'Room',
    'KeyPair',
    'get_db',
    'init_database',
    'create_tables',
    'p2p_manager',
    'P2PConnection',
    'async_p2p',
    'AsyncP2PConnection',
    'P2PProtocol',
    'db_encryptor',
    'DatabaseEncryptor',
    'EncryptedSQLiteConnection',
    'encrypt_sensitive_fields',
    'decrypt_sensitive_fields',
    'init_encrypted_database',
    'advanced_protection',
    'AdvancedProtectionManager',
    'PaddingManager',
    'MessageSigner',
    'SessionKeyManager',
    'AntiReplayManager',
    'EphemeralMessageManager',
    'p2p_chat_manager',
    'P2PChatManager',
    'P2PChatSession',
    'direct_p2p_messenger',
    'DirectP2PMessenger'
]
