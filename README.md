Security Chat - P2P加密聊天系统

一个基于Python的端到端加密P2P即时聊天系统，采用真正的分布式架构，实现点对点通信，无需中心服务器中转消息。

特性

安全特性
- 端到端加密：使用ECDH密钥交换 + AES-GCM加密
- 前向保密：每次会话使用新的加密密钥
- 消息完整性：数字签名验证消息来源和完整性
- 防重放攻击：时间戳和序列号保护
- 阅后即焚：支持自毁消息功能
- 等长填充：防止流量分析攻击

网络特性
- 真正的P2P架构：不依赖中心服务器中转消息
- NAT穿透：自动UDP打洞建立直接连接
- DHT网络：分布式哈希表实现节点发现
- 混合通信：WebSocket信令 + UDP直接传输
- 自适应网络：自动选择最佳通信路径

聊天功能
- 公共聊天室：多用户实时群聊
- 私密P2P聊天：端到端加密一对一通信
- 文件传输：加密文件传输支持
- 表情支持：丰富的表情符号
- 实时状态：在线用户列表和状态更新
- 消息历史：本地消息存储和检索

界面设计
- 现代化UI：Aurora Chat风格设计
- 玻璃态效果：毛玻璃视觉效果
- 响应式布局：适配不同设备屏幕
- 实时动画：流畅的过渡和反馈
- 直观操作：简洁的用户交互设计

项目结构

SecurityChat/
├── app.py                    # 主Flask应用
├── requirements.txt          # Python依赖包
├── README.md                # 项目说明文档
├── templates/               # HTML模板
│   └── index.html          # 前端界面
├── core/                    # 核心功能模块
│   ├── __init__.py         # 模块初始化
│   ├── crypto.py           # 加密模块
│   ├── p2p_connection.py   # P2P连接管理
│   ├── database.py         # 数据库管理
│   ├── dht.py              # DHT网络实现
│   ├── kademlia_dht.py     # Kademlia DHT
│   ├── stun_client.py      # STUN客户端
│   ├── async_p2p.py        # 异步P2P通信
│   ├── real_p2p_chat.py    # 真实P2P聊天
│   ├── advanced_protection.py # 高级防护
│   ├── db_encryption.py    # 数据库加密
│   └── file_encryption.py  # 文件加密
├── test_output/            # 测试输出目录
└── p2p_chat.db            # SQLite数据库文件

快速开始

环境要求
- Python 3.8+
- pip 包管理器
- 网络访问权限
- 5000端口可用

安装步骤

1. 克隆项目
   git clone https://github.com/OrengeChen/SecurityChat.git
   cd SecurityChat

2. 创建虚拟环境（推荐）
   python -m venv .venv
   
   # Windows
   .venv\Scripts\activate
   
   # Linux/Mac
   source .venv/bin/activate

3. 安装依赖
   pip install -r requirements.txt

4. 启动服务器
   python app.py

5. 访问应用
   打开浏览器访问：http://localhost:5000

测试聊天

1. 打开第一个浏览器标签页，访问 http://localhost:5000
2. 使用用户名"用户1"登录
3. 打开第二个浏览器标签页，访问 http://localhost:5000
4. 使用用户名"用户2"登录
5. 在用户1的界面中，从在线用户列表选择"用户2"，点击"建立P2P连接"
6. 用户2会收到连接请求，点击"接受"
7. 双方建立P2P连接后，可以进行私密加密聊天

技术架构

后端技术栈
- Flask: Web框架和API服务
- Flask-SocketIO: WebSocket实时通信
- cryptography: 加密算法实现
- PyNaCl: 加密库
- Kademlia: DHT网络协议
- SQLAlchemy: 数据库ORM
- eventlet: 异步网络库

前端技术栈
- HTML5 + CSS3: 页面结构和样式
- Tailwind CSS: 现代化UI框架
- Font Awesome: 图标库
- Socket.IO客户端: WebSocket通信
- Vanilla JavaScript: 原生交互逻辑

加密协议
1. 密钥交换: ECDH (P-256椭圆曲线)
2. 对称加密: AES-GCM (256位密钥)
3. 消息认证: HMAC-SHA256
4. 密钥派生: HKDF
5. 数字签名: ECDSA

API接口

RESTful API
- GET /api/health - 服务健康检查
- GET /api/rooms - 获取聊天室列表
- GET /api/p2p/info - 获取P2P节点信息
- POST /api/p2p/connect - 连接到P2P节点
- POST /api/p2p/chat/encrypt - 加密P2P消息
- POST /api/p2p/chat/decrypt - 解密P2P消息

WebSocket事件
- connect/disconnect - 连接管理
- register - 用户注册
- message - 公共聊天消息
- p2p_message - P2P私密消息
- p2p_connect - P2P连接请求
- p2p_accept - P2P连接接受/拒绝
- send_file - 文件传输
- send_emoji - 表情发送

安全机制

加密流程
1. 客户端启动: 生成ECDH密钥对
2. 连接建立: 交换公钥，计算共享密钥
3. 会话密钥: 使用HKDF派生会话密钥
4. 消息加密: AES-GCM加密消息内容
5. 消息传输: 加密消息通过P2P通道传输
6. 消息解密: 接收方使用会话密钥解密

防护措施
- 等长填充: 所有消息填充到固定长度
- 消息签名: ECDSA验证消息完整性
- 防重放攻击: 消息ID和序列号检查
- 密钥轮换: 定期更换会话密钥
- 会话管理: 安全的会话状态维护

网络架构

P2P连接建立
1. 信令阶段: 通过WebSocket服务器交换连接信息
2. NAT穿透: 使用STUN获取公网地址，UDP打洞
3. 直接连接: 建立端到端UDP连接
4. 加密通道: 在直接连接上建立加密通信

DHT网络
- 节点发现: 通过DHT网络发现其他在线节点
- 数据存储: 分布式存储用户信息和网络状态
- 路由优化: Kademlia算法优化节点查找

性能指标

测试环境
- CPU: Intel Core i5
- 内存: 8GB
- 网络: 局域网
- 系统: Windows 11

性能数据
- 连接时间: < 2秒
- 消息延迟: < 100ms (局域网)
- 并发用户: 支持100+并发连接
- 内存使用: < 100MB (10用户)
- 加密开销: < 5ms/消息

开发指南

代码规范
- 遵循PEP 8 Python代码规范
- 使用类型提示(Type Hints)
- 模块化设计，高内聚低耦合
- 完整的代码注释和文档

扩展功能
1. 添加新功能模块:
   - 在core/目录下创建新模块
   - 在主应用app.py中注册路由和事件
   - 在前端templates/index.html中添加界面

2. 修改加密算法:
   - 编辑core/crypto.py文件
   - 保持接口兼容性
   - 更新测试用例

3. 自定义UI:
   - 修改templates/index.html中的HTML/CSS
   - 更新JavaScript交互逻辑
   - 保持响应式设计

调试方法
# 启用调试模式
socketio.run(app, host='0.0.0.0', port=5000, debug=True)

# 查看日志
import logging
logging.basicConfig(level=logging.DEBUG)

配置文件

环境变量
# 服务器端口
PORT=5000

# 加密密钥（生产环境需要修改）
SECRET_KEY=your-secret-key-here

# 数据库路径
DATABASE_URL=sqlite:///p2p_chat.db

安全配置
- 修改app.py中的SECRET_KEY
- 配置HTTPS证书（生产环境）
- 设置防火墙规则
- 定期更新依赖包

贡献指南

提交问题
1. 在GitHub Issues中描述问题
2. 提供复现步骤和环境信息
3. 附上相关日志和截图

提交代码
1. Fork项目仓库
2. 创建功能分支
3. 提交清晰的提交信息
4. 创建Pull Request

开发流程
# 1. 克隆仓库
git clone https://github.com/OrengeChen/SecurityChat.git

# 2. 创建分支
git checkout -b feature/your-feature

# 3. 提交更改
git add .
git commit -m "Add: your feature description"

# 4. 推送到远程
git push origin feature/your-feature

# 5. 创建Pull Request

许可证

本项目采用MIT许可证 - 查看LICENSE文件了解详情。

致谢

- Flask团队: 优秀的Python Web框架
- Socket.IO: 强大的实时通信库
- cryptography: Python加密库
- Kademlia: DHT网络协议
- 所有贡献者: 感谢你们的支持和贡献

联系方式

- 项目作者: OrengeChen
- GitHub: https://github.com/OrengeChen
- 项目地址: https://github.com/OrengeChen/SecurityChat
- 问题反馈: GitHub Issues

未来规划

短期目标
- 添加消息撤回功能
- 支持群组聊天
- 添加消息已读回执
- 优化移动端体验

长期目标
- 支持视频通话
- 添加区块链身份验证
- 跨平台客户端
- 分布式存储系统

如果这个项目对你有帮助，请给个Star！

安全聊天，保护隐私，从你我做起
