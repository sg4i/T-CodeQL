# 最佳实践

> 查询优化、性能调优、调试技巧和代码规范的完整指南

## 查询编写最佳实践

### 1. 查询结构优化

#### 提前过滤原则

```ql
// ❌ 不好：后用强限制条件
from Method m, Parameter p
where 
  p = m.getAParameter() and
  m.getName() = "execute" and
  m.getDeclaringType().hasQualifiedName("java.sql", "Statement")
select m, p

// ✅ 好：先用强限制条件
from Method m, Parameter p
where 
  m.getName() = "execute" and
  m.getDeclaringType().hasQualifiedName("java.sql", "Statement") and
  p = m.getAParameter()
select m, p
```

#### 避免笛卡尔积

```ql
// ❌ 不好：可能产生大量无关组合
from Function f, Variable v
where someCondition(f, v)
select f, v

// ✅ 好：通过关系连接
from Function f, Variable v
where 
  v.getScope() = f and  // 建立明确关系
  someCondition(f, v)
select f, v

// ✅ 更好：使用 exists 限制作用域
from Function f
where exists(Variable v |
  v.getScope() = f and
  someCondition(f, v)
)
select f
```

#### 使用索引友好的条件

```ql
// ✅ 好：使用索引
where f.getName() = "specific_name"

// ❌ 不好：无法使用索引
where f.getName().matches("%name%")

// ✅ 折中：前缀匹配
where f.getName().matches("prefix_%")
```

### 2. 性能优化技巧

#### 缓存昂贵的计算

```ql
// ✅ 使用 cached 标注
cached
predicate isComplexFunction(Function f) {
  count(Stmt s | s.getScope() = f) > 50 or
  count(CallNode c | c.getScope() = f) > 20 or
  exists(LoopStmt loop | loop.getParent+() = f)
}

// ✅ 缓存常用的类型检查
cached
predicate isWebFunction(Function f) {
  exists(Decorator d |
    d = f.getADecorator() and
    d.getName().regexpMatch(".*route.*")
  )
}

// 使用缓存的谓词
from Function f
where 
  isWebFunction(f) and
  isComplexFunction(f)
select f, "复杂的 Web 函数"
```

#### 优化递归查询

```ql
// ❌ 不好：无限制的递归
predicate calls(Function caller, Function callee) {
  directCall(caller, callee) or
  exists(Function intermediate |
    calls(caller, intermediate) and
    calls(intermediate, callee)
  )
}

// ✅ 好：限制递归深度
predicate calls(Function caller, Function callee) {
  callsWithin(caller, callee, 10)  // 最大深度 10
}

predicate callsWithin(Function caller, Function callee, int depth) {
  depth > 0 and
  (
    directCall(caller, callee) or
    exists(Function intermediate |
      directCall(caller, intermediate) and
      callsWithin(intermediate, callee, depth - 1)
    )
  )
}
```

#### 使用适当的聚合函数

```ql
// ✅ 使用 strictcount 避免空集合
from Function f
where strictcount(Parameter p | p = f.getAParameter()) > 5
select f, "函数参数过多"

// ✅ 使用 any() 获取任意一个
from Class c
where exists(Method m | m = c.getAMethod() and m.isPublic())
select c, any(Method m | m = c.getAMethod() and m.isPublic())

// ✅ 使用条件聚合
from Function f
select f, count(Parameter p | p = f.getAParameter() and p.getType() instanceof RefType)
```

### 3. 数据流查询优化

#### 高效的数据流配置

```ql
module OptimizedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // ✅ 使用具体的源定义
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "request" and
      call.getFunction().(Attribute).getName() = "args" and
      call.getArg(0).asExpr().(StrConst).getText() = "user_input" and
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // ✅ 限制在特定的危险函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "eval" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  // ✅ 使用屏障减少搜索空间
  predicate isBarrier(DataFlow::Node node) {
    // 在函数边界设置屏障（如果不需要跨函数分析）
    node.asExpr() instanceof Parameter
  }
  
  // ✅ 限制额外的污点步骤
  predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 只添加必要的传播步骤
    exists(BinOp binop |
      binop.getOp() instanceof Add and
      fromNode.asExpr() = binop.getLeft() and
      toNode.asExpr() = binop and
      // 限制：只在字符串拼接时传播
      binop.getLeft().getType().getName() = "str"
    )
  }
}
```

#### 部分流分析调试

```ql
/**
 * @name 数据流调试 - 部分流
 * @description 使用部分流分析调试数据流查询
 * @kind problem
 * @id debug/partial-flow
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.PartialFlow

module DebugConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asCfgNode().(CallNode).getFunction().(NameNode).getId() = "get_user_input"
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "dangerous_operation" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module PartialFlowDebug = PartialFlow<DebugConfig>;

from PartialFlowDebug::PartialPathNode source, PartialFlowDebug::PartialPathNode node, int dist
where
  PartialFlowDebug::partialFlow(source, node, dist) and
  dist > 0
select node, source, dist, "部分流：距离源 " + dist + " 步，到达 " + node.toString()
order by dist desc
```

## 代码质量和规范

### 1. 查询元数据规范

#### 完整的元数据模板

```ql
/**
 * @name 查询的简短描述性名称
 * @description 查询的详细描述，解释它在寻找什么问题以及为什么重要。
 *              可以包含多行描述。
 * @kind problem | path-problem | metric | table
 * @problem.severity error | warning | recommendation
 * @security-severity 0.0-10.0  // CVSS 评分
 * @precision very-high | high | medium | low
 * @id 语言前缀/描述性-标识符
 * @tags security | correctness | maintainability | performance
 *       external/cwe/cwe-XXX
 *       external/owasp/owasp-aXX
 *       framework-name
 * @scope for-testing-only  // 仅用于测试查询
 */
```

#### 元数据最佳实践

```ql
/**
 * ✅ 好的元数据示例
 * @name SQL injection in database query
 * @description Building a SQL query from user-controlled sources is vulnerable 
 *              to insertion of malicious SQL code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/owasp-a03
 */

/**
 * ❌ 不好的元数据示例
 * @name Bad query
 * @description Finds bad stuff
 * @kind problem
 * @id bad-query
 */
```

### 2. 命名规范

#### 类和谓词命名

```ql
// ✅ 类名：PascalCase
class HttpRequestHandler extends ... { }
class SqlInjectionSink extends ... { }

// ✅ 谓词名：camelCase
predicate isPublicMethod(Method m) { ... }
predicate hasSecurityAnnotation(Function f) { ... }

// ✅ 结果谓词：以 get 开头
string getMethodName() { result = this.name }
Type getAParameter() { ... }
Type getParameter(int i) { ... }

// ✅ 布尔谓词：以 is 或 has 开头
predicate isPublic() { ... }
predicate hasAnnotation(string name) { ... }

// ✅ 新类型谓词：以 T 开头
newtype TSecurityLevel = 
  | TLow() 
  | TMedium() 
  | THigh()
```

#### 变量命名

```ql
// ✅ 描述性的变量名
from HttpServletRequest request, String userInput, SqlStatement stmt
where 
  userInput = request.getParameter("id") and
  stmt.execute(userInput)
select stmt, "SQL injection vulnerability"

// ❌ 不描述性的变量名
from A a, B b, C c
where someCondition(a, b, c)
select a, b, c
```

### 3. 文档编写规范

#### 查询帮助文档 (.qhelp)

```xml
<!DOCTYPE qhelp PUBLIC "-//Semmle//qhelp//EN" "qhelp.dtd">
<qhelp>
<overview>
<p>
简洁地描述这个查询检测什么问题。解释为什么这是一个问题，
可能的影响是什么。
</p>
</overview>

<recommendation>
<p>
提供具体的修复建议。告诉开发者应该如何修复这个问题。
可以包含多个建议。
</p>
<ul>
<li>建议1：具体的修复步骤</li>
<li>建议2：替代方案</li>
</ul>
</recommendation>

<example>
<p>
以下代码展示了有问题的模式：
</p>
<sample src="examples/bad.py" />

<p>
修复后的代码：
</p>
<sample src="examples/good.py" />
</example>

<references>
<li>CWE-XXX: <a href="https://cwe.mitre.org/data/definitions/XXX.html">漏洞名称</a></li>
<li>OWASP: <a href="https://owasp.org/www-community/attacks/Attack_Name">攻击类型</a></li>
<li>Framework Documentation: <a href="https://example.com/docs">相关文档</a></li>
</references>
</qhelp>
```

#### 代码注释规范

```ql
/**
 * 获取函数的所有安全相关注解
 * 
 * 这个谓词检查函数上的注解，返回那些与安全相关的注解。
 * 安全相关的注解包括：@PreAuthorize, @Secured, @RolesAllowed 等。
 * 
 * @return 安全相关的注解
 */
Annotation getASecurityAnnotation() {
  result = this.getAnAnnotation() and
  result.getType().hasName([
    "PreAuthorize", "Secured", "RolesAllowed", 
    "DenyAll", "PermitAll"
  ])
}

// ✅ 复杂逻辑的注释
predicate isVulnerablePattern(CallNode call) {
  // 检查是否为字符串拼接的 SQL 查询
  exists(BinOp concat |
    concat.getOp() instanceof Add and
    concat.getAChild*() = call.getArg(0) and
    // 确保至少有一个操作数是字符串字面量（SQL 片段）
    exists(StrConst sqlFragment |
      sqlFragment = concat.getAnOperand() and
      sqlFragment.getText().regexpMatch("(?i).*(SELECT|INSERT|UPDATE|DELETE).*")
    )
  )
}
```

## 测试和验证

### 1. 单元测试最佳实践

#### 测试目录结构

```
test/
├── Security/
│   └── CWE-089/
│       └── SqlInjection/
│           ├── test.py              # 测试代码
│           ├── SqlInjection.qlref   # 查询引用
│           ├── SqlInjection.expected # 期望结果
│           └── options              # 测试选项（可选）
```

#### 测试代码编写

```python
# test.py - 全面的测试用例
import sqlite3
from flask import Flask, request

app = Flask(__name__)

def test_sql_injection_basic():
    """基础 SQL 注入测试"""
    # BAD: 直接字符串拼接
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"  # $ hasValueFlow
    conn = sqlite3.connect('test.db')
    conn.execute(query)

def test_sql_injection_format():
    """格式化字符串 SQL 注入"""
    # BAD: 使用 % 格式化
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = '%s'" % user_id  # $ hasValueFlow
    conn = sqlite3.connect('test.db')
    conn.execute(query)

def test_sql_injection_f_string():
    """f-string SQL 注入"""
    # BAD: 使用 f-string
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # $ hasValueFlow
    conn = sqlite3.connect('test.db')
    conn.execute(query)

def test_safe_parameterized_query():
    """安全的参数化查询"""
    # GOOD: 参数化查询
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = ?"
    conn = sqlite3.connect('test.db')
    conn.execute(query, (user_id,))  # 不应该被检测到

def test_safe_with_validation():
    """带验证的安全查询"""
    # GOOD: 输入验证
    user_id = request.args.get('id')
    if user_id.isdigit():  # 验证输入
        query = "SELECT * FROM users WHERE id = " + user_id
        conn = sqlite3.connect('test.db')
        conn.execute(query)  # 不应该被检测到
```

#### 期望结果文件

```
# SqlInjection.expected
| test.py:11:5:11:25 | This SQL query depends on a $@ | test.py:10:15:10:38 | user-provided value |
| test.py:18:5:18:25 | This SQL query depends on a $@ | test.py:17:15:17:38 | user-provided value |
| test.py:25:5:25:25 | This SQL query depends on a $@ | test.py:24:15:24:38 | user-provided value |
```

### 2. 测试策略

#### 边界条件测试

```python
# 测试边界条件和特殊情况
def test_edge_cases():
    # 空字符串
    query = "SELECT * FROM users WHERE name = '" + "" + "'"
    
    # 多层嵌套
    def get_user_input():
        return request.args.get('input')
    
    def process_input(data):
        return data.upper()
    
    user_data = get_user_input()
    processed = process_input(user_data)
    query = "SELECT * FROM users WHERE name = '" + processed + "'"  # 应该被检测到
    
    # 条件分支
    user_type = request.args.get('type')
    if user_type == 'admin':
        query = "SELECT * FROM users WHERE role = 'admin'"  # 安全
    else:
        query = "SELECT * FROM users WHERE role = '" + user_type + "'"  # 不安全
```

#### 假阳性和假阴性测试

```python
def test_false_positives():
    """测试假阳性情况"""
    # 这些不应该被检测为漏洞
    
    # 硬编码字符串
    query = "SELECT * FROM users WHERE status = 'active'"
    conn.execute(query)
    
    # 常量
    ADMIN_ROLE = "admin"
    query = "SELECT * FROM users WHERE role = '" + ADMIN_ROLE + "'"
    conn.execute(query)
    
    # 经过验证的输入
    user_id = request.args.get('id')
    if user_id in ['1', '2', '3']:  # 白名单验证
        query = "SELECT * FROM users WHERE id = " + user_id
        conn.execute(query)

def test_false_negatives():
    """测试假阴性情况"""
    # 这些应该被检测为漏洞但可能被遗漏
    
    # 间接赋值
    user_input = request.args.get('search')
    search_term = user_input
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    conn.execute(query)
    
    # 通过函数传递
    def build_query(term):
        return "SELECT * FROM users WHERE name = '" + term + "'"
    
    user_name = request.args.get('name')
    sql = build_query(user_name)
    conn.execute(sql)
```

### 3. 回归测试

#### 自动化测试脚本

```bash
#!/bin/bash
# run_regression_tests.sh

set -e

CODEQL_HOME="/usr/local/bin/codeql"
TEST_DIR="test"
RESULTS_DIR="test-results"

echo "Running CodeQL regression tests..."

# 清理之前的结果
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

# 运行所有测试
find "$TEST_DIR" -name "*.qlref" | while read -r test_file; do
    test_name=$(basename "$(dirname "$test_file")")
    echo "Running test: $test_name"
    
    # 运行测试
    if $CODEQL_HOME test run "$(dirname "$test_file")" > "$RESULTS_DIR/$test_name.log" 2>&1; then
        echo "✅ $test_name: PASSED"
    else
        echo "❌ $test_name: FAILED"
        cat "$RESULTS_DIR/$test_name.log"
        exit 1
    fi
done

echo "All tests passed! ✅"
```

#### 持续集成测试

```yaml
# .github/workflows/test-queries.yml
name: Test CodeQL Queries

on:
  push:
    paths:
      - 'queries/**'
      - 'test/**'
  pull_request:
    paths:
      - 'queries/**'
      - 'test/**'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: python
    
    - name: Run Query Tests
      run: |
        codeql test run test/ --threads=4
    
    - name: Check Query Formatting
      run: |
        find queries/ -name "*.ql" -exec codeql query format {} --check-only \;
    
    - name: Compile Queries
      run: |
        find queries/ -name "*.ql" -exec codeql query compile {} \;
```

## 调试技巧

### 1. 查询调试策略

#### 逐步构建查询

```ql
// 第一步：验证基础数据
from Function f
select f, f.getName(), f.getLocation()

// 第二步：添加条件
from Function f
where f.getName().matches("*dangerous*")
select f, f.getName(), f.getLocation()

// 第三步：添加更多逻辑
from Function f, CallNode call
where 
  f.getName().matches("*dangerous*") and
  call.getScope() = f
select f, call, "Found call in dangerous function"

// 第四步：完整查询
from Function f, CallNode call
where 
  f.getName().matches("*dangerous*") and
  call.getScope() = f and
  call.getFunction().(NameNode).getId() = "eval"
select call, "Dangerous eval call in function " + f.getName()
```

#### 使用 select 语句调试

```ql
// 调试数据流查询
from DataFlow::Node source, DataFlow::Node sink
where 
  source.asCfgNode().(CallNode).getFunction().(NameNode).getId() = "input" and
  sink.asCfgNode().(CallNode).getFunction().(NameNode).getId() = "eval"
select source, sink, 
  "Source: " + source.toString() + 
  " | Sink: " + sink.toString() +
  " | Local flow: " + (if DataFlow::localFlow(source, sink) then "YES" else "NO")
```

#### 检查中间结果

```ql
// 创建调试谓词
predicate debugInfo(string category, string info) {
  category = "sources" and
  exists(DataFlow::Node source |
    isSource(source) and
    info = source.toString()
  )
  or
  category = "sinks" and
  exists(DataFlow::Node sink |
    isSink(sink) and
    info = sink.toString()
  )
  or
  category = "flows" and
  exists(DataFlow::Node source, DataFlow::Node sink |
    isSource(source) and isSink(sink) and
    DataFlow::localFlow(source, sink) and
    info = source.toString() + " -> " + sink.toString()
  )
}

from string category, string info
where debugInfo(category, info)
select category, info
```

### 2. 性能调试

#### 查询性能分析

```bash
# 生成性能报告
codeql query run query.ql \
  --database=db \
  --tuple-counting \
  --evaluator-log=performance.log

# 分析性能瓶颈
grep -E "(Evaluation|ms)" performance.log | head -20

# 查看最耗时的谓词
grep "Evaluation completed" performance.log | \
  sort -k4 -nr | head -10
```

#### 内存使用分析

```bash
# 监控内存使用
codeql query run query.ql \
  --database=db \
  --ram=8192 \
  --verbose 2>&1 | grep -i memory

# 使用系统工具监控
htop &  # 或 top
codeql query run query.ql --database=db
```

### 3. 常见错误和解决方案

#### 类型错误

```ql
// ❌ 错误：类型不匹配
from Expr e
where e.getType() = "string"  // 错误：getType() 返回 Type，不是 string
select e

// ✅ 正确：使用正确的类型检查
from Expr e
where e.getType().getName() = "str"
select e

// ✅ 或者使用 instanceof
from Expr e
where e.getType() instanceof StringType
select e
```

#### 空结果集问题

```ql
// 调试：检查每个条件
from Function f
where 
  f.getName() = "target_function"  // 检查这个条件
select f, "Found target function"

from Function f
where 
  f.getName() = "target_function" and
  f.getDeclaringType().hasName("TargetClass")  // 检查这个条件
select f, "Found target function in target class"

// 使用 exists 验证数据存在
from Function f
where exists(Function target | target.getName() = "target_function")
select f, "Target function exists in database"
```

#### 递归查询问题

```ql
// ❌ 可能导致无限递归
predicate transitiveCall(Function caller, Function callee) {
  directCall(caller, callee) or
  exists(Function intermediate |
    transitiveCall(caller, intermediate) and
    transitiveCall(intermediate, callee)
  )
}

// ✅ 限制递归深度
predicate transitiveCallBounded(Function caller, Function callee) {
  transitiveCallWithin(caller, callee, 10)
}

predicate transitiveCallWithin(Function caller, Function callee, int depth) {
  depth > 0 and
  (
    directCall(caller, callee) or
    exists(Function intermediate |
      directCall(caller, intermediate) and
      transitiveCallWithin(intermediate, callee, depth - 1)
    )
  )
}
```

## 部署和维护

### 1. 查询包管理

#### 创建查询包

```yaml
# qlpack.yml
name: my-org/security-queries
version: 1.0.0
description: Custom security queries for our organization
license: MIT
dependencies:
  codeql/python-all: "*"
  codeql/javascript-all: "*"
groups:
  - python
  - javascript
```

#### 版本控制策略

```bash
# 语义化版本控制
# 1.0.0 - 初始版本
# 1.0.1 - 补丁版本（bug 修复）
# 1.1.0 - 次要版本（新功能）
# 2.0.0 - 主要版本（破坏性变更）

# 发布新版本
git tag v1.1.0
git push origin v1.1.0
codeql pack publish
```

### 2. 查询质量保证

#### 代码审查清单

- [ ] **元数据完整**：包含所有必需的元数据字段
- [ ] **命名规范**：遵循命名约定
- [ ] **性能优化**：使用了适当的优化技巧
- [ ] **测试覆盖**：包含全面的测试用例
- [ ] **文档完整**：有 .qhelp 文件和代码注释
- [ ] **假阳性检查**：验证了假阳性情况
- [ ] **边界测试**：测试了边界条件

#### 自动化质量检查

```bash
#!/bin/bash
# quality_check.sh

echo "Running CodeQL query quality checks..."

# 1. 格式检查
echo "Checking query formatting..."
find queries/ -name "*.ql" | while read -r query; do
    if ! codeql query format "$query" --check-only; then
        echo "❌ Format check failed for $query"
        exit 1
    fi
done

# 2. 编译检查
echo "Checking query compilation..."
find queries/ -name "*.ql" | while read -r query; do
    if ! codeql query compile "$query" --check-only; then
        echo "❌ Compilation failed for $query"
        exit 1
    fi
done

# 3. 元数据检查
echo "Checking query metadata..."
find queries/ -name "*.ql" | while read -r query; do
    if ! grep -q "@name" "$query"; then
        echo "❌ Missing @name in $query"
        exit 1
    fi
    if ! grep -q "@description" "$query"; then
        echo "❌ Missing @description in $query"
        exit 1
    fi
    if ! grep -q "@id" "$query"; then
        echo "❌ Missing @id in $query"
        exit 1
    fi
done

# 4. 测试检查
echo "Checking tests..."
find queries/ -name "*.ql" | while read -r query; do
    query_name=$(basename "$query" .ql)
    test_dir="test/$(dirname "${query#queries/}")/$query_name"
    if [ ! -d "$test_dir" ]; then
        echo "⚠️  No test directory for $query"
    fi
done

echo "✅ All quality checks passed!"
```

### 3. 监控和维护

#### 查询性能监控

```python
#!/usr/bin/env python3
# monitor_query_performance.py

import json
import time
import subprocess
import sys

def run_query_with_timing(query_path, database_path):
    """运行查询并记录性能指标"""
    start_time = time.time()
    
    try:
        result = subprocess.run([
            'codeql', 'query', 'run', query_path,
            '--database', database_path,
            '--tuple-counting'
        ], capture_output=True, text=True, timeout=600)
        
        end_time = time.time()
        duration = end_time - start_time
        
        return {
            'query': query_path,
            'duration': duration,
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr
        }
    except subprocess.TimeoutExpired:
        return {
            'query': query_path,
            'duration': 600,
            'success': False,
            'error': 'Query timeout'
        }

def main():
    queries = [
        'queries/security/sql-injection.ql',
        'queries/security/xss.ql',
        'queries/security/command-injection.ql'
    ]
    
    database = 'test-db'
    results = []
    
    for query in queries:
        print(f"Running {query}...")
        result = run_query_with_timing(query, database)
        results.append(result)
        
        if result['success']:
            print(f"✅ {query}: {result['duration']:.2f}s")
        else:
            print(f"❌ {query}: FAILED - {result['error']}")
    
    # 保存结果
    with open('performance_report.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    # 生成摘要
    total_queries = len(results)
    successful_queries = sum(1 for r in results if r['success'])
    avg_duration = sum(r['duration'] for r in results if r['success']) / successful_queries if successful_queries > 0 else 0
    
    print(f"\nSummary:")
    print(f"Total queries: {total_queries}")
    print(f"Successful: {successful_queries}")
    print(f"Failed: {total_queries - successful_queries}")
    print(f"Average duration: {avg_duration:.2f}s")

if __name__ == "__main__":
    main()
```

## 下一步

掌握了最佳实践后，建议继续学习：

1. **[贡献指南](13-contributing.md)** - 如何为 CodeQL 项目贡献代码
2. **[学习资源](15-learning-resources.md)** - 深入学习的资源汇总
3. 开始编写自己的高质量查询并分享给社区

---

**最佳实践掌握完毕！** 🏆 现在您可以编写高质量、高性能的 CodeQL 查询了。
