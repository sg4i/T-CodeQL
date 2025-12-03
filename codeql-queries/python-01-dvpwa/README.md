# Python 安全漏洞检测教程 - DVPWA 项目分析

本教程将指导您使用 CodeQL 分析 DVPWA (Damn Vulnerable Python Web Application) 项目，学习如何检测 Python 应用程序中的常见安全漏洞。

## 前置准备

### 环境要求

- python环境
- git clone https://github.com/anxolerd/dvpwa.git

### 目标仓库介绍

DVPWA 是一个故意存在漏洞的 Python Flask Web 应用程序，包含 15+ 种常见安全漏洞。详细信息请参考 [目标仓库说明](./target-repo.md)。


## 创建 CodeQL 数据库

```bash
# codeql 可不用安装Python依赖项 
# https://github.blog/changelog/2023-07-11-code-scanning-with-codeql-no-longer-installs-python-dependencies-automatically-for-new-users/
# https://github.blog/changelog/2024-01-23-codeql-2-16-python-dependency-installation-disabled-new-queries-and-bug-fixes/
# 安装项目依赖
# pip install -r requirements.txt

# 创建 CodeQL 数据库
codeql database create dvpwa-db \
  --language=python \
  --source-root=. \
  --exclude-dir=venv \
  --exclude-dir=__pycache__

# 验证数据库创建成功
codeql database  print-baseline dvpwa-db
```

**重要说明**:
- Python 项目通常不需要构建命令
- `--exclude-dir` 排除虚拟环境和缓存目录
- CodeQL 会自动检测 Python 源文件


## 运行查询

### 4.1 运行 SQL 注入查询

```bash
# 运行 SQL 注入检测查询
codeql query run queries/sql-injection.ql \
  --database=dvpwa-db \
  --output=sql-injection-results.bqrs

# 查看结果
codeql bqrs decode sql-injection-results.bqrs --format=csv

# 保存为 CSV 格式
codeql bqrs decode sql-injection-results.bqrs \
  --format=csv \
  --output=sql-injection-results.csv
```

### 4.2 运行命令注入查询

```bash
# 运行命令注入检测查询
codeql query run queries/command-injection.ql \
  --database=dvpwa-db \
  --output=command-injection-results.bqrs

# 查看结果
codeql bqrs decode command-injection-results.bqrs --format=csv
```

## 验证结果

### 5.1 分析 SQL 注入结果

预期会发现以下类型的 SQL 注入漏洞：

1. **字符串格式化 SQL 注入**
   ```python
   # 在 dvpwa/sqli/views.py 中
   query = "SELECT * FROM users WHERE id = %s" % user_id
   cursor.execute(query)
   ```

2. **字符串拼接 SQL 注入**
   ```python
   # 在 dvpwa/sqli/views.py 中
   query = "SELECT * FROM users WHERE name = '" + username + "'"
   ```

### 5.2 验证具体的 SQL 注入漏洞

```bash
# 查找 SQL 注入相关文件
find dvpwa -name "*.py" -path "*/sqli/*" | head -5

# 查看具体的漏洞代码
grep -n "%" dvpwa/sqli/views.py | grep -i select
grep -n "execute" dvpwa/sqli/views.py
```

### 5.3 分析命令注入结果

预期会发现：

1. **os.system() 命令注入**
   ```python
   # 在 dvpwa/cmdi/views.py 中
   import os
   result = os.system("ping " + host)
   ```

2. **subprocess 命令注入**
   ```python
   # 在 dvpwa/cmdi/views.py 中
   import subprocess
   subprocess.call("ls " + directory, shell=True)
   ```

## 步骤六：深入分析

### 6.1 查看漏洞详情

```bash
# 查看 SQL 注入模块
cat dvpwa/sqli/views.py

# 查看命令注入模块
cat dvpwa/cmdi/views.py

# 查看文件包含漏洞
cat dvpwa/lfi/views.py
```

### 6.2 理解 Python 特有的安全问题

#### SQL 注入在 Python 中的表现

```python
# 危险模式 1：字符串格式化
query = "SELECT * FROM users WHERE id = %s" % user_id
cursor.execute(query)

# 危险模式 2：f-string 格式化
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# 危险模式 3：字符串拼接
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)

# 安全模式：参数化查询
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

#### 命令注入的危害

```python
# 危险模式 1：os.system()
os.system("ping " + host)  # host = "127.0.0.1; cat /etc/passwd"

# 危险模式 2：subprocess with shell=True
subprocess.call("ping " + host, shell=True)

# 安全模式：参数列表
subprocess.call(["ping", host])
```

### 6.3 验证漏洞影响

启动应用程序进行手动验证：

```bash
# 启动 DVPWA
python app.py

# 在浏览器中访问 http://localhost:5000
# 测试 SQL 注入：访问 /sqli/user?id=1' OR '1'='1
# 测试命令注入：在 ping 功能中输入 127.0.0.1; ls -la
```

## 步骤七：进阶技巧

### 7.1 自定义 pickle 反序列化查询

创建检测 pickle 反序列化漏洞的查询：

```ql
/**
 * 检测 Python pickle 反序列化漏洞
 */
import python

from CallNode call, ControlFlowNode arg
where
  call.getFunction().(AttrNode).getName() = "loads" and
  call.getFunction().(AttrNode).getObject().(NameNode).getId() = "pickle" and
  arg = call.getAnArg() and
  arg.pointsTo().isExternal()
select call, "Unsafe pickle deserialization of external data"
```

### 7.2 检测 Flask 特有的漏洞

```ql
/**
 * 检测 Flask 应用中的安全问题
 */
import python

from CallNode call, ControlFlowNode arg
where
  // render_template_string 可能导致 SSTI
  call.getFunction().(NameNode).getId() = "render_template_string" and
  arg = call.getAnArg() and
  arg.pointsTo().isExternal()
select call, "Potential Server-Side Template Injection (SSTI)"
```

### 7.3 检测路径遍历漏洞

```ql
/**
 * 检测路径遍历漏洞
 */
import python
import semmle.python.security.dataflow.PathInjectionQuery

from PathInjectionFlow flow, DataFlow::PathNode source, DataFlow::PathNode sink
where flow.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Path injection vulnerability"
```

### 7.4 性能优化

```bash
# 限制分析范围到特定目录
codeql database create dvpwa-sqli-only \
  --language=python \
  --source-root=dvpwa/sqli

# 使用多线程加速分析
codeql query run queries/sql-injection.ql \
  --database=dvpwa-db \
  --threads=4

# 生成 SARIF 格式结果
codeql database analyze dvpwa-db \
  python-security-and-quality.qls \
  --format=sarif-latest \
  --output=dvpwa-results.sarif
```

## 常见问题排除

### 数据库创建失败

```bash
# 检查 Python 版本
python --version

# 检查当前目录
pwd
ls -la

# 尝试简化的数据库创建
codeql database create dvpwa-simple \
  --language=python \
  --source-root=dvpwa
```

### 查询执行错误

```bash
# 检查查询语法
codeql query format queries/sql-injection.ql

# 验证查询
codeql query compile queries/sql-injection.ql

# 查看详细错误信息
codeql query run queries/sql-injection.ql \
  --database=dvpwa-db \
  --verbose
```

### Python 特有的问题

- python版本问题

CodeQL优先查找codeql-config.yml或lgtm.yml（已弃用）中的python_version配置，未找到则启动自动检测

- **编码问题**
   - 确保 Python 文件使用 UTF-8 编码
   - 检查文件中是否有特殊字符

## 学习成果验证

完成本教程后，您应该能够：

- [ ] 成功创建 DVPWA 项目的 CodeQL 数据库
- [ ] 运行自定义的 SQL 注入检测查询
- [ ] 运行自定义的命令注入检测查询
- [ ] 分析和验证 Python 特有的安全漏洞
- [ ] 理解 Python Web 应用程序的常见安全问题
- [ ] 使用 CodeQL 检测 Flask 应用程序的安全漏洞

## 实战练习

### 练习 1：检测更多 Python 漏洞

尝试编写查询检测：
- eval() 代码注入
- 不安全的 YAML 加载
- 弱随机数生成

### 练习 2：分析 Django 项目

找一个 Django 项目，尝试：
- 检测 Django ORM 中的 SQL 注入
- 查找 Django 模板中的 XSS
- 分析 Django 中间件的安全问题

### 练习 3：检测 API 安全问题

分析 Python API 项目：
- JWT 令牌验证绕过
- API 参数注入
- 权限控制缺陷

## 下一步

1. 尝试分析其他 Python 框架的项目（Django、FastAPI 等）
2. 学习 [C/C++ 安全漏洞检测教程](../05-C-CPP教程/cpp-tutorial.md)
3. 在自己的 Python 项目中应用 CodeQL
4. 探索 CodeQL 对 Python 异步编程的支持

## 参考资源

- [CodeQL Python 库文档](https://codeql.github.com/codeql-standard-libraries/python/)
- [Python 安全查询示例](https://github.com/github/codeql/tree/main/python/ql/src/Security)
- [OWASP Python 安全指南](https://owasp.org/www-project-python-security/)
- [Flask 安全最佳实践](https://flask.palletsprojects.com/en/2.0.x/security/)
- [Python 安全编程指南](https://python-security.readthedocs.io/)


