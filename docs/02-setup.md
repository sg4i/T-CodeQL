# 开发环境搭建

> 配置完整的 CodeQL 开发环境，包括 CLI 工具、VS Code 扩展和相关依赖

## 必需工具

### 1. CodeQL CLI

CodeQL 命令行工具是核心组件，用于创建数据库和运行查询。

#### 安装方法

**Linux/macOS:**
```bash
# 下载最新版本
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip
sudo mv codeql /usr/local/bin/
export PATH=$PATH:/usr/local/bin/codeql

# 或者添加到 ~/.bashrc 或 ~/.zshrc
echo 'export PATH=$PATH:/usr/local/bin/codeql' >> ~/.bashrc
```

**Windows:**
```powershell
# 使用 PowerShell
Invoke-WebRequest -Uri "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-win64.zip" -OutFile "codeql-win64.zip"
Expand-Archive -Path "codeql-win64.zip" -DestinationPath "C:\codeql"
$env:PATH += ";C:\codeql\codeql"

# 永久添加到 PATH
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\codeql\codeql", "User")
```

**验证安装:**
```bash
codeql --version
# 输出类似：CodeQL command-line toolchain release 2.15.3
```

### 2. Visual Studio Code

VS Code 是推荐的 CodeQL 开发环境。

#### 安装 CodeQL 扩展

1. 打开 VS Code
2. 进入扩展市场 (Ctrl+Shift+X)
3. 搜索 "CodeQL"
4. 安装 "CodeQL" 扩展（发布者：GitHub）

#### 配置 VS Code

创建或编辑 `.vscode/settings.json`：

```json
{
  "codeql.cli.executablePath": "/usr/local/bin/codeql/codeql",
  "codeql.runningQueries.numberOfThreads": 4,
  "codeql.runningQueries.memory": 8192,
  "codeql.runningQueries.timeout": 600,
  "codeql.runningQueries.debug": false,
  "codeql.runningQueries.autoSave": true,
  "codeql.variantAnalysis.controllerRepo": "your-org/codeql-queries"
}
```

**配置说明:**
- `executablePath`: CodeQL CLI 的路径
- `numberOfThreads`: 查询运行时使用的线程数
- `memory`: 分配给查询的内存（MB）
- `timeout`: 查询超时时间（秒）
- `debug`: 是否启用调试模式

### 3. Git

用于克隆 CodeQL 仓库和管理查询代码。

```bash
# 安装 Git（如果尚未安装）
# Ubuntu/Debian
sudo apt install git

# macOS
brew install git

# Windows - 下载安装包
# https://git-scm.com/download/win
```

## 获取 CodeQL 仓库

### 克隆官方仓库

```bash
# 克隆完整仓库（约 2GB）
git clone https://github.com/github/codeql.git
cd codeql

# 或者只克隆最新提交（节省空间）
git clone --depth 1 https://github.com/github/codeql.git
```

### 仓库结构概览

```
codeql/
├── python/          # Python 语言支持
├── java/            # Java/Kotlin 语言支持  
├── javascript/      # JavaScript/TypeScript 语言支持
├── go/              # Go 语言支持
├── cpp/             # C/C++ 语言支持
├── csharp/          # C# 语言支持
├── ruby/            # Ruby 语言支持
├── swift/           # Swift 语言支持
├── rust/            # Rust 语言支持
├── shared/          # 跨语言共享库
├── docs/            # 官方文档
└── misc/            # 工具和脚本
```

## 语言特定依赖

### Python

```bash
# 确保 Python 3.6+ 已安装
python3 --version

# 安装常用包（用于测试）
pip install flask django requests sqlalchemy
```

### Java

```bash
# 安装 JDK 8+
# Ubuntu/Debian
sudo apt install openjdk-11-jdk

# macOS
brew install openjdk@11

# 验证安装
java -version
javac -version
```

### JavaScript/Node.js

```bash
# 安装 Node.js 14+
# 使用 nvm（推荐）
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install node
nvm use node

# 或直接安装
# Ubuntu/Debian
sudo apt install nodejs npm

# macOS
brew install node

# 验证安装
node --version
npm --version
```

### Go

```bash
# 安装 Go 1.18+
# 下载安装包：https://golang.org/dl/

# 或使用包管理器
# Ubuntu/Debian
sudo apt install golang-go

# macOS
brew install go

# 验证安装
go version
```

### C/C++

```bash
# 安装构建工具
# Ubuntu/Debian
sudo apt install build-essential cmake

# macOS
xcode-select --install
brew install cmake

# Windows
# 安装 Visual Studio Build Tools 或 MinGW
```

## 配置工作空间

### 创建 CodeQL 工作空间

```bash
mkdir ~/codeql-workspace
cd ~/codeql-workspace

# 创建目录结构
mkdir -p {queries,databases,results}

# 创建 codeql-workspace.yml
cat > codeql-workspace.yml << 'EOF'
provide:
  - "queries/**/*.ql"
  - "queries/**/*.qll"
dependencies:
  codeql/python-all: ~/codeql/python/ql/lib
  codeql/java-all: ~/codeql/java/ql/lib
  codeql/javascript-all: ~/codeql/javascript/ql/lib
EOF
```

### VS Code 工作空间配置

创建 `.vscode/codeql-workspace.code-workspace`：

```json
{
  "folders": [
    {
      "name": "CodeQL Queries",
      "path": "./queries"
    },
    {
      "name": "CodeQL Standard Library",
      "path": "~/codeql"
    }
  ],
  "settings": {
    "codeql.cli.executablePath": "/usr/local/bin/codeql/codeql",
    "files.associations": {
      "*.ql": "ql",
      "*.qll": "ql"
    }
  }
}
```

## 验证安装

### 创建测试数据库

```bash
# 创建简单的 Python 测试项目
mkdir test-python && cd test-python
cat > test.py << 'EOF'
def hello(name):
    print(f"Hello, {name}!")

if __name__ == "__main__":
    hello("CodeQL")
EOF

# 创建数据库
codeql database create test-db --language=python --source-root=.
```

### 运行测试查询

```bash
# 运行简单查询
codeql query run ~/codeql/python/ql/examples/snippets/call.ql --database=test-db

# 应该看到输出显示找到的函数调用
```

### VS Code 集成测试

1. 打开 VS Code
2. 打开 CodeQL 工作空间
3. 创建新查询文件 `test.ql`：

```ql
/**
 * @name Test query
 * @description A simple test query
 * @kind problem
 * @id test/hello
 */

import python

from Function f
where f.getName() = "hello"
select f, "Found function: " + f.getName()
```

4. 右键选择 "CodeQL: Run Query"
5. 选择之前创建的测试数据库
6. 查看结果面板中的输出

## 性能优化

### 系统要求

**最低配置:**
- CPU: 4 核心
- 内存: 8GB RAM
- 存储: 50GB 可用空间

**推荐配置:**
- CPU: 8+ 核心
- 内存: 16GB+ RAM
- 存储: SSD，100GB+ 可用空间

### 优化设置

```bash
# 设置环境变量
export CODEQL_THREADS=8
export CODEQL_RAM=8192

# 或在查询时指定
codeql database analyze db/ query.ql \
  --threads=8 \
  --ram=8192
```

### 缓存配置

```bash
# 设置缓存目录
export CODEQL_DIST_CACHE_DIR=~/.codeql/cache

# 清理缓存（如果需要）
rm -rf ~/.codeql/cache
```

## 常见问题解决

### 问题 1: CodeQL CLI 找不到

**症状:** `command not found: codeql`

**解决:**
```bash
# 检查 PATH
echo $PATH

# 重新添加到 PATH
export PATH=$PATH:/path/to/codeql

# 永久添加
echo 'export PATH=$PATH:/path/to/codeql' >> ~/.bashrc
source ~/.bashrc
```

### 问题 2: VS Code 扩展无法连接 CLI

**症状:** "Cannot find CodeQL CLI"

**解决:**
1. 检查 `settings.json` 中的 `codeql.cli.executablePath`
2. 确保路径正确且可执行
3. 重启 VS Code

### 问题 3: 数据库创建失败

**症状:** "Extraction failed"

**解决:**
```bash
# 检查日志
codeql database create db/ --language=python --source-root=. --verbose

# 查看详细日志
cat db/log/database-create-*.log
```

**常见原因:**
- 缺少语言特定依赖
- 源代码路径错误
- 权限问题

### 问题 4: 查询运行缓慢

**解决:**
```bash
# 增加线程数和内存
codeql query run query.ql --database=db/ --threads=8 --ram=8192

# 使用缓存
codeql query run query.ql --database=db/ --additional-packs=~/.codeql/cache
```

## 下一步

环境搭建完成后，建议继续学习：

1. **[CodeQL 基础](03-basics.md)** - 了解核心概念和 QL 语言
2. **[查询编写](04-writing-queries.md)** - 学习编写您的第一个查询
3. **[开发工具](11-tools.md)** - 深入了解工具链的高级功能

---

**环境配置完成！** 🎉 现在您可以开始编写和运行 CodeQL 查询了。
