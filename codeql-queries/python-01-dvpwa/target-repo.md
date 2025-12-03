# DVPWA 项目说明

## 项目简介

DVPWA (Damn Vulnerable Python Web Application) 是一个故意存在安全漏洞的 Python Web 应用程序。它专门用于学习和练习 Web 应用程序安全测试，包含了各种常见的 Python Web 安全漏洞。

- **项目地址**: https://github.com/anxolerd/dvpwa
- **编程语言**: Python 3
- **Web 框架**: Flask
- **数据库**: SQLite
- **项目规模**: 约 5,000+ 行代码
- **漏洞类型**: 15+ 种常见 Web 安全漏洞

## 已知漏洞列表

### SQL 注入漏洞

1. **经典 SQL 注入**
   - 位置: `dvpwa/sqli/views.py`
   - 类型: 字符串格式化构建 SQL 查询
   - 影响: 数据泄露、认证绕过

2. **盲注 SQL 注入**
   - 位置: `dvpwa/sqli/views.py` (blind_sqli 函数)
   - 类型: 布尔型盲注和时间延迟盲注
   - 影响: 数据库信息泄露

3. **Union SQL 注入**
   - 位置: `dvpwa/sqli/views.py` (union_sqli 函数)
   - 类型: UNION 查询注入
   - 影响: 数据库结构泄露

### 命令注入漏洞

1. **操作系统命令注入**
   - 位置: `dvpwa/cmdi/views.py`
   - 类型: 用户输入直接传递给 `os.system()`
   - 影响: 远程代码执行

2. **subprocess 命令注入**
   - 位置: `dvpwa/cmdi/views.py` (subprocess_injection 函数)
   - 类型: 不安全的 subprocess 调用
   - 影响: 系统命令执行

### 文件操作漏洞

1. **路径遍历**
   - 位置: `dvpwa/lfi/views.py`
   - 类型: 不安全的文件路径拼接
   - 影响: 任意文件读取

2. **文件包含**
   - 位置: `dvpwa/lfi/views.py` (local_file_inclusion 函数)
   - 类型: 本地文件包含
   - 影响: 代码执行、信息泄露

### 其他安全漏洞

1. **跨站脚本攻击 (XSS)**
   - 位置: `dvpwa/xss/views.py`
   - 类型: 反射型和存储型 XSS
   - 影响: 客户端代码执行

2. **跨站请求伪造 (CSRF)**
   - 位置: `dvpwa/csrf/views.py`
   - 类型: 缺乏 CSRF 令牌验证
   - 影响: 未授权操作

3. **不安全的反序列化**
   - 位置: `dvpwa/pickle/views.py`
   - 类型: pickle 反序列化漏洞
   - 影响: 远程代码执行

4. **XML 外部实体注入 (XXE)**
   - 位置: `dvpwa/xxe/views.py`
   - 类型: 不安全的 XML 解析
   - 影响: 文件读取、SSRF

## 项目结构

```
dvpwa/
├── app.py                          # 主应用程序文件
├── dvpwa/                          # 主应用模块
│   ├── __init__.py                # Flask 应用初始化
│   ├── sqli/                      # SQL 注入相关
│   │   ├── __init__.py
│   │   └── views.py               # SQL 注入漏洞
│   ├── cmdi/                      # 命令注入相关
│   │   ├── __init__.py
│   │   └── views.py               # 命令注入漏洞
│   ├── lfi/                       # 文件包含相关
│   │   ├── __init__.py
│   │   └── views.py               # 路径遍历/文件包含
│   ├── xss/                       # XSS 相关
│   │   ├── __init__.py
│   │   └── views.py               # XSS 漏洞
│   ├── csrf/                      # CSRF 相关
│   │   ├── __init__.py
│   │   └── views.py               # CSRF 漏洞
│   ├── pickle/                    # 反序列化相关
│   │   ├── __init__.py
│   │   └── views.py               # pickle 反序列化
│   └── xxe/                       # XXE 相关
│       ├── __init__.py
│       └── views.py               # XXE 漏洞
├── templates/                     # Jinja2 模板
├── static/                        # 静态资源
├── requirements.txt               # Python 依赖
└── README.md                      # 项目说明
```

## 技术栈详情

### 核心技术

- **Python 3**: 编程语言
- **Flask**: 轻量级 Web 框架
- **Jinja2**: 模板引擎
- **SQLite**: 数据库
- **Werkzeug**: WSGI 工具库

### 依赖库

- **Flask-SQLAlchemy**: ORM 支持
- **requests**: HTTP 客户端
- **lxml**: XML 处理
- **pickle**: 序列化/反序列化

## 构建要求

- **Python**: 3.6 或更高版本
- **pip**: Python 包管理器
- **内存**: 至少 1GB RAM
- **磁盘**: 约 100MB 空间

## 克隆和构建

```bash
# 克隆项目
git clone https://github.com/anxolerd/dvpwa.git
cd dvpwa

# 创建虚拟环境（推荐）
python3 -m venv venv
source venv/bin/activate  # macOS/Linux

# 安装依赖
pip install -r requirements.txt

# 初始化数据库（可选）
python app.py init-db

# 启动应用（可选，用于验证漏洞）
python app.py
```

## CodeQL 分析重点

在使用 CodeQL 分析 DVPWA 时，重点关注以下目录：

1. **SQL 注入检测**
   - `dvpwa/sqli/views.py`
   - 查找字符串格式化构建 SQL 查询的模式

2. **命令注入检测**
   - `dvpwa/cmdi/views.py`
   - 查找用户输入传递给 `os.system()` 或 `subprocess` 的模式

3. **文件操作漏洞**
   - `dvpwa/lfi/views.py`
   - 查找不安全的文件路径操作

4. **反序列化漏洞**
   - `dvpwa/pickle/views.py`
   - 查找不安全的 pickle 操作

## 预期分析结果

使用本教程的 CodeQL 查询，您应该能够发现：

- **SQL 注入**: 8-12 个实例
- **命令注入**: 4-6 个实例
- **路径遍历**: 3-5 个实例
- **XSS**: 6-8 个实例
- **反序列化**: 2-3 个实例

## 漏洞验证方法

### SQL 注入验证

```bash
# 访问 SQL 注入页面
curl "http://localhost:5000/sqli/user?id=1' OR '1'='1"

# 盲注测试
curl "http://localhost:5000/sqli/blind?id=1' AND (SELECT COUNT(*) FROM users) > 0--"
```

### 命令注入验证

```bash
# 命令注入测试
curl -X POST "http://localhost:5000/cmdi/ping" \
  -d "host=127.0.0.1; cat /etc/passwd"

# subprocess 注入
curl -X POST "http://localhost:5000/cmdi/subprocess" \
  -d "command=ls -la"
```

### 路径遍历验证

```bash
# 路径遍历测试
curl "http://localhost:5000/lfi/read?file=../../../etc/passwd"

# 文件包含测试
curl "http://localhost:5000/lfi/include?file=/etc/passwd"
```

## 学习价值

DVPWA 项目特别适合 CodeQL 学习，因为：

1. **代码简洁**: 漏洞代码清晰易懂，便于学习
2. **漏洞典型**: 包含最常见的 Python Web 漏洞类型
3. **结构清晰**: 每种漏洞类型都有独立的模块
4. **实用性强**: 漏洞模式与真实项目相似
5. **易于扩展**: 可以轻松添加新的漏洞类型进行练习

## Python 特有的安全问题

### 1. 字符串格式化注入

```python
# 危险模式
query = "SELECT * FROM users WHERE id = %s" % user_id
cursor.execute(query)

# 安全模式
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### 2. pickle 反序列化

```python
# 危险模式
import pickle
data = pickle.loads(user_input)  # 可能执行恶意代码

# 安全模式
import json
data = json.loads(user_input)  # 只能反序列化基本数据类型
```

### 3. eval() 代码注入

```python
# 危险模式
result = eval(user_expression)  # 直接执行用户代码

# 安全模式
import ast
result = ast.literal_eval(user_expression)  # 只能执行字面量表达式
```

## 注意事项

- DVPWA 是一个**故意存在漏洞**的应用程序，请勿在生产环境中部署
- 建议在隔离的测试环境中进行分析
- 某些漏洞可能需要特定的输入格式才能触发
- 分析结果可能包含一些预期的"漏洞"，这是项目的设计目标
- Python 的动态特性可能导致一些误报，需要人工验证

## 扩展学习

完成 DVPWA 分析后，可以尝试分析其他 Python 项目：

1. **Django 项目**: 学习 Django 特有的安全问题
2. **FastAPI 项目**: 现代 Python Web 框架的安全分析
3. **真实开源项目**: 在 GitHub 上寻找有已知漏洞的 Python 项目
