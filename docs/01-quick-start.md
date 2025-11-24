# CodeQL 快速入门

> 5分钟了解 CodeQL 并运行您的第一个查询

## 什么是 CodeQL？

**CodeQL** 是 GitHub 开发的代码分析引擎，它将代码视为数据，让您可以编写查询来发现代码中的漏洞、错误和模式。

### 核心特性
- 🔍 **代码即数据**：将源代码转换为可查询的数据库
- 📝 **声明式查询**：使用类似 SQL 的 QL 语言编写逻辑查询  
- 🌐 **多语言支持**：支持 Python、Java、JavaScript、Go、C/C++、C#、Ruby、Swift、Rust
- 🔒 **安全导向**：专门设计用于发现安全漏洞
- 🚀 **大规模分析**：可以在数千个代码库中进行变体分析

## 5分钟体验

### 步骤 1：安装 CodeQL CLI

```bash
# 下载最新版本（Linux/macOS）
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip
export PATH=$PATH:$(pwd)/codeql

# 验证安装
codeql --version
```

### 推荐的目录结构

在开始之前，让我们先了解推荐的目录组织方式：

```
~/codeql-projects/          # 推荐的工作目录
├── codeql/                 # CodeQL 标准库（克隆的官方仓库）
│   ├── python/
│   │   └── ql/
│   │       ├── lib/        # Python 库文件
│   │       └── src/        # Python 查询文件
│   │           └── Security/
│   │               └── CWE-089/
│   │                   └── SqlInjection.ql
│   ├── java/
│   ├── javascript/
│   └── ...
└── my-projects/            # 您要分析的项目
    └── test-project/
        ├── app.py
        └── python-db/      # 创建的数据库（自动生成）
```

**路径关系说明：**
- `codeql/` 仓库包含所有语言的标准查询和库
- 您的项目放在 `codeql/` 同级或其他位置
- 查询文件路径：`codeql/python/ql/src/Security/CWE-089/SqlInjection.ql`

### 步骤 2：克隆 CodeQL 仓库

```bash
# 创建工作目录
mkdir -p ~/codeql-projects
cd ~/codeql-projects

# 克隆 CodeQL 标准库仓库
git clone https://github.com/github/codeql.git
```

### 步骤 3：创建数据库

以一个简单的 Python 项目为例：

```bash
# 返回工作目录，在 codeql 仓库外创建测试项目
cd ~/codeql-projects
mkdir -p my-projects/test-project
cd my-projects/test-project
cat > app.py << 'EOF'
import sqlite3

def unsafe_query(user_input):
    # 不安全的 SQL 查询
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    conn = sqlite3.connect('test.db')
    return conn.execute(query).fetchall()

def safe_query(user_input):
    # 安全的参数化查询
    query = "SELECT * FROM users WHERE name = ?"
    conn = sqlite3.connect('test.db')
    return conn.execute(query, (user_input,)).fetchall()
EOF

# 创建 CodeQL 数据库
codeql database create python-db --language=python --source-root=.
```

### 步骤 4：运行您的第一个查询

```bash
# 当前目录：~/codeql-projects/my-projects/test-project
# 运行 SQL 注入检测查询

# 方法 1：使用相对路径（推荐理解路径关系）
codeql database analyze python-db \
  ~/codeql-projects/codeql/python/ql/src/Security/CWE-089/SqlInjection.ql \
  --format=table

# 方法 2：如果当前在 test-project 目录，使用相对路径
# codeql database analyze python-db \
#   ../../codeql/python/ql/src/Security/CWE-089/SqlInjection.ql \
#   --format=table

# 您应该看到类似这样的输出：
# | app.py:5:13:5:66 | This SQL query depends on a user-provided value |
```

**路径说明：**
- `python-db`：当前目录下创建的数据库
- `~/codeql-projects/codeql/python/ql/src/Security/CWE-089/SqlInjection.ql`：CodeQL 仓库中的查询文件
- 相对路径 `../../codeql/...` 表示：向上两级到 `codeql-projects`，然后进入 `codeql/python/...`

🎉 **恭喜！** 您刚刚运行了第一个 CodeQL 查询，成功检测到了 SQL 注入漏洞！

## 完整的目录结构

执行完上述步骤后，您的目录结构应该如下：

```
~/codeql-projects/
├── codeql/                          # CodeQL 官方仓库
│   ├── python/
│   │   └── ql/
│   │       ├── lib/                 # Python 分析库
│   │       │   └── semmle/
│   │       │       └── python/
│   │       └── src/                 # 预定义查询
│   │           ├── Security/
│   │           │   ├── CWE-089/
│   │           │   │   └── SqlInjection.ql  ← 我们使用的查询
│   │           │   ├── CWE-078/
│   │           │   └── ...
│   │           └── Quality/
│   ├── java/
│   ├── javascript/
│   ├── go/
│   └── ...
│
└── my-projects/                     # 您的项目目录
    └── test-project/                # 测试项目
        ├── app.py                   # 源代码
        └── python-db/               # CodeQL 数据库（自动创建）
            ├── db-python/
            ├── log/
            ├── src/
            └── codeql-database.yml
```

**关键点：**
1. **CodeQL 仓库** (`codeql/`)：包含所有语言的查询和库，不要在这里创建您的项目
2. **您的项目** (`my-projects/`)：与 `codeql/` 平级，便于管理
3. **数据库目录** (`python-db/`)：由 CodeQL 自动创建，包含代码的结构化表示
4. **查询文件路径**：`codeql/python/ql/src/Security/CWE-089/SqlInjection.ql`

## 理解结果

查询结果告诉我们：
- **位置**：`app.py:5:13:5:66` - 第5行，第13-66个字符
- **问题**：SQL 查询依赖于用户提供的值（可能导致 SQL 注入）
- **原因**：`user_input` 直接拼接到 SQL 字符串中，没有适当的清理

## 下一步

现在您已经体验了 CodeQL 的基本功能，建议继续学习：

1. **[环境搭建](02-setup.md)** - 配置完整的开发环境
2. **[CodeQL 基础](03-basics.md)** - 深入了解核心概念
3. **[查询编写](04-writing-queries.md)** - 学习编写自己的查询

## 常用命令速查

```bash
# 创建数据库
codeql database create <db-name> --language=<lang> --source-root=.

# 运行单个查询（使用绝对路径或相对路径）
codeql query run <path-to-query.ql> --database=<db-name>
# 示例：codeql query run ~/codeql-projects/codeql/python/ql/src/Security/CWE-089/SqlInjection.ql --database=python-db

# 运行查询套件
codeql database analyze <db-name> <path-to-suite.qls> --format=sarif-latest --output=results.sarif

# 升级数据库（当 CodeQL 版本更新时）
codeql database upgrade <db-name>
```

## 支持的语言

| 语言 | 提取器 | 主要用途 |
|------|--------|----------|
| Python | `python` | Web应用、数据科学、自动化脚本 |
| Java/Kotlin | `java` | 企业应用、Android 开发 |
| JavaScript/TypeScript | `javascript` | 前端、Node.js 后端 |
| Go | `go` | 云原生、微服务 |
| C/C++ | `cpp` | 系统编程、嵌入式 |
| C# | `csharp` | .NET 应用 |
| Ruby | `ruby` | Web 应用（Rails） |
| Swift | `swift` | iOS/macOS 应用 |
| Rust | `rust` | 系统编程、WebAssembly |

---

**准备好深入学习了吗？** 继续阅读 [环境搭建](02-setup.md) 来配置完整的开发环境！
