# CodeQL 环境配置指南

本指南将帮助您在 macOS 系统上安装和配置 CodeQL，为后续的安全漏洞检测教程做好准备。

## 前置要求

- 稳定的网络连接
- 基本的命令行操作知识

## 步骤一：安装 CodeQL CLI (for mac)

### 方法一：使用 Homebrew（推荐）

```bash
# 安装 Homebrew（如果尚未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装 CodeQL
brew install --cask codeql
```

### 方法二：手动下载安装

1. 访问 [CodeQL 发布页面](https://github.com/github/codeql-cli-binaries/releases)
2. 下载最新版本的 `codeql-osx64.zip`
3. 解压到合适的目录（例如：`/usr/local/codeql`）
4. 将 CodeQL 添加到 PATH：

```bash
# 编辑 ~/.zshrc 文件
echo 'export PATH="/usr/local/codeql:$PATH"' >> ~/.zshrc

# 重新加载配置
source ~/.zshrc
```

### 验证安装

```bash
# 检查 CodeQL 版本
codeql version

# 应该看到类似输出：
# CodeQL command-line toolchain release 2.15.3.
```

## 步骤二：下载 CodeQL 标准库

CodeQL 需要标准库来分析不同编程语言的代码：

```bash
# 创建工作目录
mkdir -p ~/codeql-workspace
cd ~/codeql-workspace

# 克隆 CodeQL 标准库
git clone https://github.com/github/codeql.git codeql-repo
```

## 步骤三：安装和配置 VS Code

### 安装 VS Code

1. 访问 [VS Code 官网](https://code.visualstudio.com/)
2. 下载并安装 macOS 版本

### 安装 CodeQL 扩展

1. 打开 VS Code
2. 按 `Cmd+Shift+X` 打开扩展面板
3. 搜索 "CodeQL"
4. 安装 GitHub 官方的 CodeQL 扩展

### 配置 CodeQL 扩展

1. 按 `Cmd+,` 打开设置
2. 搜索 "codeql"
3. 配置以下设置：
   - **CodeQL CLI Executable Path**: `/usr/local/bin/codeql`（或您的 CodeQL 安装路径）
   - **CodeQL Distribution Path**: `~/codeql-workspace/codeql-repo`

## 步骤四：验证完整安装

创建一个测试查询来验证环境配置：

```bash
# 创建测试目录
mkdir -p ~/codeql-test
cd ~/codeql-test

# 创建简单的 Java 测试文件
cat > Test.java << 'EOF'
public class Test {
    public static void main(String[] args) {
        System.out.println("Hello CodeQL!");
    }
}
EOF

# 创建 CodeQL 数据库, 单文件没有Maven/Gradle等构建，使用javac
codeql database create test-db --language=java --source-root=. --command='bash -c "javac -d build/classes $(find . -name \"*.java\")"'

# 验证数据库创建成功, 如果看到数据库目录包含多个文件，说明环境配置成功！
ls test-db/

# 分析，使用 绝对路径查询
codeql database analyze test-db \
  --format=sarif-latest \
  --output=java-results.sarif \
  --search-path=~/codeql-workspace/codeql-repo \
  ~/codeql-workspace/codeql-repo/java/ql/src/codeql-suites/java-security-extended.qls

codeql database interpret-results test-db --format=csv -o result.csv --search-path ~/codeql-workspace/codeql-repo
```

## 常用 CodeQL 命令

### 数据库操作

```bash
# 创建数据库
codeql database create <database-name> --language=<language> --source-root=<source-directory>

# 查看数据库信息
codeql database info <database-name>

# 升级数据库
codeql database upgrade <database-name>
```

### 查询操作

```bash
# 运行查询
codeql query run <query-file> --database=<database-name>

# 运行查询套件
codeql database analyze <database-name> <query-suite> --format=<format> --output=<output-file>

# 查看可用的查询套件
codeql resolve queries <language>
```

### 结果操作

```bash
# 查看结果
codeql bqrs decode <results-file> --format=table

# 转换结果格式
codeql bqrs decode <results-file> --format=csv --output=<output-file>
```

## 支持的编程语言

CodeQL 支持以下编程语言：

- **Java/Kotlin**: 需要 Maven 或 Gradle 构建系统
- **JavaScript/TypeScript**: 支持 Node.js 项目
- **Python**: 支持 Python 2.7 和 3.x
- **C/C++**: 需要编译环境（gcc, clang）
- **C#**: 需要 .NET 环境
- **Go**: 需要 Go 编译器
- **Ruby**: 支持 Ruby 2.x 和 3.x

## 故障排除

### 常见问题

1. **CodeQL 命令未找到**
   - 检查 PATH 环境变量
   - 重新安装 CodeQL

2. **数据库创建失败**
   - 检查源代码目录是否存在
   - 确认编程语言检测正确
   - 查看详细错误信息：`codeql database create --verbose`

3. **VS Code 扩展无法连接**
   - 检查 CodeQL CLI 路径配置
   - 重启 VS Code
   - 查看输出面板的错误信息

### 获取帮助

```bash
# 查看帮助信息
codeql --help

# 查看特定命令的帮助
codeql database create --help

# 查看版本信息
codeql version --format=json
```

## 下一步

环境配置完成后，您可以继续学习：

1. [Java 安全漏洞检测教程](../02-Java教程/java-tutorial.md)
2. [JavaScript 安全漏洞检测教程](../03-JavaScript教程/javascript-tutorial.md)
3. [Python 安全漏洞检测教程](../04-Python教程/python-tutorial.md)
4. [C/C++ 安全漏洞检测教程](../05-C-CPP教程/cpp-tutorial.md)

## 参考资源

- [CodeQL 官方文档](https://codeql.github.com/docs/)
- [CodeQL 查询帮助](https://codeql.github.com/codeql-query-help/)
- [GitHub Security Lab](https://securitylab.github.com/)
- [CodeQL 学习资源](https://github.com/github/securitylab/tree/main/CodeQL_Queries)
