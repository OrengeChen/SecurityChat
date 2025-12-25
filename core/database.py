"""
数据库模块
使用SQLAlchemy进行数据持久化
"""
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# 数据库配置
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./p2p_chat.db')

# 创建数据库引擎
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith('sqlite') else {})

# 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 声明基类
Base = declarative_base()

class User(Base):
    """用户表"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    public_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_online = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<User(username='{self.username}', online={self.is_online})>"

class Message(Base):
    """消息表"""
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, index=True)
    receiver_id = Column(Integer, index=True)
    room_id = Column(String(50), index=True)
    content = Column(Text, nullable=False)
    encrypted_content = Column(Text)  # 加密后的内容
    signature = Column(Text)  # 消息签名
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    is_delivered = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<Message(sender={self.sender_id}, room={self.room_id}, time={self.timestamp})>"

class Room(Base):
    """聊天室表"""
    __tablename__ = "rooms"
    
    id = Column(String(50), primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    created_by = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_public = Column(Boolean, default=True)
    max_users = Column(Integer, default=100)
    
    def __repr__(self):
        return f"<Room(name='{self.name}', public={self.is_public})>"

class KeyPair(Base):
    """密钥对表"""
    __tablename__ = "key_pairs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    private_key = Column(Text, nullable=False)  # 加密存储的私钥
    public_key = Column(Text, nullable=False)
    algorithm = Column(String(50), default='ECDH-P256')
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    def __repr__(self):
        return f"<KeyPair(user={self.user_id}, algorithm={self.algorithm})>"

# 创建所有表
def create_tables():
    """创建数据库表"""
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully")

def get_db():
    """获取数据库会话"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_database():
    """初始化数据库"""
    create_tables()
    
    # 添加示例数据（可选）
    db = SessionLocal()
    try:
        # 检查是否有默认房间
        from .dht import dht_network
        
        default_rooms = [
            Room(id='general', name='General Chat', description='General discussion room', is_public=True),
            Room(id='tech', name='Technology', description='Technology related discussions', is_public=True),
            Room(id='random', name='Random', description='Random chat room', is_public=True)
        ]
        
        for room in default_rooms:
            if not db.query(Room).filter(Room.id == room.id).first():
                db.add(room)
        
        db.commit()
        print("Default rooms created")
        
        # 初始化DHT网络节点
        dht_network.add_node('127.0.0.1', 5000)
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()

# 数据库工具函数
class DatabaseManager:
    """数据库管理器"""
    
    @staticmethod
    def create_user(db, username: str, public_key: str):
        """创建新用户"""
        user = User(username=username, public_key=public_key, is_online=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    
    @staticmethod
    def get_user_by_username(db, username: str):
        """根据用户名获取用户"""
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def update_user_online_status(db, user_id: int, is_online: bool):
        """更新用户在线状态"""
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.is_online = is_online
            user.last_seen = datetime.utcnow()
            db.commit()
            return True
        return False
    
    @staticmethod
    def save_message(db, sender_id: int, receiver_id: int, room_id: str, 
                    content: str, encrypted_content: str = None, signature: str = None):
        """保存消息"""
        message = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            room_id=room_id,
            content=content,
            encrypted_content=encrypted_content,
            signature=signature
        )
        db.add(message)
        db.commit()
        db.refresh(message)
        return message
    
    @staticmethod
    def get_room_messages(db, room_id: str, limit: int = 100):
        """获取聊天室消息"""
        return db.query(Message).filter(
            Message.room_id == room_id
        ).order_by(Message.timestamp.desc()).limit(limit).all()

# 初始化数据库
if __name__ == "__main__":
    init_database()
