# Python 场景应用

> Python 代码分析完整指南：从 Web 应用到数据科学，掌握 Python 特定的 CodeQL 查询技巧

## Python 语言支持概览

### 目录结构

```
python/
├── ql/
│   ├── lib/                    # Python 核心库
│   │   ├── semmle/python/     # 标准库实现
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   ├── web/           # Web 框架支持
│   │   │   ├── Concepts.qll   # 通用概念
│   │   │   └── ApiGraphs.qll  # API 建模
│   │   ├── qlpack.yml         # 库包配置
│   │   └── python.qll         # 主入口文件
│   ├── src/                    # 查询源码
│   │   ├── Security/          # 安全查询
│   │   │   ├── CWE-089/      # SQL 注入
│   │   │   ├── CWE-078/      # 命令注入
│   │   │   ├── CWE-079/      # XSS
│   │   │   ├── CWE-094/      # 代码注入
│   │   │   └── CWE-022/      # 路径遍历
│   │   ├── Quality/           # 代码质量查询
│   │   └── codeql-suites/     # 预定义查询套件
│   ├── test/                   # 测试用例
│   └── examples/               # 示例查询
└── extractor/                  # Python 提取器
```

### 支持的 Python 版本

- **Python 2.7**（已弃用，但仍支持）
- **Python 3.6+**（推荐）
- **PyPy**（部分支持）

### 框架支持

CodeQL 对 Python 生态有广泛的框架支持：

| 框架类型 | 支持的框架 | 位置 |
|----------|------------|------|
| **Web 框架** | Flask, Django, FastAPI, Tornado | `semmle/python/web/` |
| **数据库** | SQLAlchemy, Django ORM, PyMongo | `semmle/python/frameworks/` |
| **HTTP 客户端** | requests, urllib, httpx | `semmle/python/frameworks/` |
| **模板引擎** | Jinja2, Django Templates | `semmle/python/web/` |
| **序列化** | pickle, json, yaml | `semmle/python/frameworks/` |

## Python 核心类和概念

### 基本语法元素

```ql
import python

// 模块
from Module m
select m.getName(), m.getFile()

// 函数
from Function f
select f.getName(), f.getQualifiedName(), f.getAParameter()

// 类
from Class c
select c.getName(), c.getAMethod(), c.getASuperclass()

// 变量
from Variable v
select v.getName(), v.getScope(), v.getAUse()

// 调用
from CallNode call
select call.getFunction(), call.getArg(0), call.getAKeyword()

// 字符串常量
from StrConst s
select s.getText(), s.getValue(), s.getLocation()
```

### Python 特定类

```ql
import python

// 装饰器
from Decorator d
select d.getName(), d.getDecorated()

// 导入语句
from Import imp, ImportMember im
where im = imp.getAName()
select imp, im.getName(), im.getModule()

// 异常处理
from TryStmt try, ExceptStmt except
where except = try.getAHandler()
select try, except.getType(), except.getName()

// 列表推导
from ListComp lc
select lc.getElt(), lc.getAGenerator()

// with 语句
from With with
select with.getContextExpr(), with.getOptionalVars()
```

## Web 应用安全分析

### Flask 应用分析

#### 1. Flask 路由检测

```ql
/**
 * @name Flask 路由分析
 * @description 分析 Flask 应用的路由定义
 * @kind problem
 * @id py/flask-route-analysis
 */

import python
import semmle.python.web.flask.Flask

from FlaskRoute route
select route.getFunction(), 
       "Flask 路由: " + route.getUrl() + " [" + route.getHttpMethod() + "]"
```

#### 2. Flask SSTI 检测

```ql
/**
 * @name Flask 服务端模板注入
 * @description 检测 Flask 应用中的服务端模板注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @id py/flask-ssti
 * @tags security
 *       external/cwe/cwe-094
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.web.flask.Flask
import DataFlow::PathGraph

module FlaskSSTIConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Flask 请求参数
    exists(FlaskRequestData request |
      source.asCfgNode() = request.asCfgNode()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 模板渲染函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in [
        "render_template_string", "Template"
      ] and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // Jinja2 直接使用
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "jinja2" and
      call.getFunction().(Attribute).getName() = "Template" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module FlaskSSTIFlow = TaintTracking::Global<FlaskSSTIConfig>;

from FlaskSSTIFlow::PathNode source, FlaskSSTIFlow::PathNode sink
where FlaskSSTIFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "模板注入：用户输入 $@ 直接用于模板渲染", 
  source.getNode(), "Flask 请求"
```

#### 3. Flask 配置安全检查

```ql
/**
 * @name Flask 不安全配置
 * @description 检测 Flask 应用的不安全配置
 * @kind problem
 * @problem.severity warning
 * @id py/flask-insecure-config
 */

import python

from AssignStmt assign, StrConst value
where
  // app.config 或 app.debug 设置
  exists(Attribute attr |
    attr = assign.getATarget() and
    (
      (attr.getObject().(Name).getId() = "app" and 
       attr.getName() in ["debug", "testing"]) or
      (attr.getObject().(Attribute).getObject().(Name).getId() = "app" and
       attr.getObject().(Attribute).getName() = "config" and
       attr.getName() = "DEBUG")
    )
  ) and
  
  // 设置为 True
  assign.getValue() = value and
  value.getText() = "True"

select assign, "Flask 应用启用了调试模式，生产环境中不安全"
```

### Django 应用分析

#### 1. Django SQL 注入检测

```ql
/**
 * @name Django SQL 注入
 * @description 检测 Django 应用中的 SQL 注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @id py/django-sql-injection
 */

import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.web.django.Django
import DataFlow::PathGraph

module DjangoSqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Django 请求参数
    exists(DjangoRequestData request |
      source.asCfgNode() = request.asCfgNode()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Django ORM 原始查询
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["raw", "extra"] and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // 直接 SQL 执行
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "execute" and
      call.getFunction().(Attribute).getObject().(Name).getId() = "cursor" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // Django 的参数化查询
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["raw", "extra"] and
      call.getNumArg() >= 2 and
      node.asCfgNode() = call.getArg(0)
    )
  }
}

module DjangoSqlInjectionFlow = TaintTracking::Global<DjangoSqlInjectionConfig>;

from DjangoSqlInjectionFlow::PathNode source, DjangoSqlInjectionFlow::PathNode sink
where DjangoSqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "Django SQL 查询包含用户输入 $@", source.getNode(), "HTTP 请求"
```

#### 2. Django CSRF 保护检查

```ql
/**
 * @name Django CSRF 保护缺失
 * @description 检测缺少 CSRF 保护的 Django 视图
 * @kind problem
 * @problem.severity error
 * @id py/django-missing-csrf
 */

import python
import semmle.python.web.django.Django

from DjangoView view
where
  // POST/PUT/DELETE 方法
  view.getHttpMethod() in ["POST", "PUT", "DELETE"] and
  
  // 没有 CSRF 保护装饰器
  not exists(Decorator d |
    d = view.getFunction().getADecorator() and
    d.getName() in ["csrf_protect", "requires_csrf_token"]
  ) and
  
  // 没有 csrf_exempt 装饰器（明确豁免）
  not exists(Decorator d |
    d = view.getFunction().getADecorator() and
    d.getName() = "csrf_exempt"
  )

select view.getFunction(), 
  "Django 视图缺少 CSRF 保护：" + view.getHttpMethod() + " " + view.getUrl()
```

## 数据科学和机器学习

### Pandas 数据处理安全

```ql
/**
 * @name Pandas eval 注入
 * @description 检测 Pandas eval/query 中的代码注入风险
 * @kind path-problem
 * @problem.severity error
 * @id py/pandas-eval-injection
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module PandasEvalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 用户输入
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["input", "raw_input"] or
      (call.getFunction().(Attribute).getObject().(Name).getId() = "request" and
       call.getFunction().(Attribute).getName() in ["args", "form", "json"])
    |
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Pandas eval/query 方法
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["eval", "query"] and
      call.getFunction().(Attribute).getObject().asExpr().getAFlowNode().pointsTo().getClass().getName() in [
        "DataFrame", "Series"
      ] and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module PandasEvalFlow = TaintTracking::Global<PandasEvalConfig>;

from PandasEvalFlow::PathNode source, PandasEvalFlow::PathNode sink
where PandasEvalFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "Pandas eval/query 使用了用户输入 $@，可能导致代码注入", 
  source.getNode(), "用户数据"
```

### NumPy 安全检查

```ql
/**
 * @name NumPy 不安全的加载
 * @description 检测 NumPy 不安全的文件加载操作
 * @kind problem
 * @problem.severity warning
 * @id py/numpy-unsafe-load
 */

import python

from CallNode call
where
  // numpy.load 调用
  call.getFunction().(Attribute).getObject().(Name).getId() = "np" and
  call.getFunction().(Attribute).getName() = "load" and
  
  // 没有设置 allow_pickle=False
  not exists(Keyword kw |
    kw = call.getAKeyword() and
    kw.getArg() = "allow_pickle" and
    kw.getValue().(NameConstant).getValue() = "False"
  )

select call, "NumPy load 操作允许 pickle，可能导致代码执行风险"
```

## Python 特定安全模式

### 1. Pickle 反序列化漏洞

```ql
/**
 * @name 不安全的 Pickle 反序列化
 * @description 检测不安全的 pickle 反序列化操作
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id py/unsafe-pickle-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module PickleDeserializationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 网络输入或文件输入
    exists(CallNode call |
      (
        // HTTP 请求
        call.getFunction().(Attribute).getObject().(Name).getId() = "request" and
        call.getFunction().(Attribute).getName() in ["data", "json", "form"]
      ) or (
        // 文件读取
        call.getFunction().(NameNode).getId() = "open" and
        call.getArg(1).asExpr().(StrConst).getText().matches("%rb%")
      )
    |
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // pickle 反序列化函数
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "pickle" and
      call.getFunction().(Attribute).getName() in ["load", "loads"] and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module PickleFlow = TaintTracking::Global<PickleDeserializationConfig>;

from PickleFlow::PathNode source, PickleFlow::PathNode sink
where PickleFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "不安全的 pickle 反序列化，数据来源于 $@", 
  source.getNode(), "外部输入"
```

### 2. 动态导入安全检查

```ql
/**
 * @name 动态导入安全风险
 * @description 检测可能被用户控制的动态导入
 * @kind path-problem
 * @problem.severity error
 * @id py/dynamic-import-risk
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module DynamicImportConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 用户输入
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["input", "raw_input"] or
      (call.getFunction().(Attribute).getObject().(Name).getId() = "request" and
       call.getFunction().(Attribute).getName() in ["args", "form", "json"])
    |
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 动态导入函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["__import__", "importlib.import_module"] and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module DynamicImportFlow = TaintTracking::Global<DynamicImportConfig>;

from DynamicImportFlow::PathNode source, DynamicImportFlow::PathNode sink
where DynamicImportFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "动态导入使用了用户输入 $@，可能导致任意代码执行", 
  source.getNode(), "用户数据"
```

### 3. 格式化字符串漏洞

```ql
/**
 * @name 格式化字符串漏洞
 * @description 检测可能的格式化字符串攻击
 * @kind path-problem
 * @problem.severity warning
 * @id py/format-string-vulnerability
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module FormatStringConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 用户输入
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["input", "raw_input"] or
      (call.getFunction().(Attribute).getObject().(Name).getId() = "request" and
       call.getFunction().(Attribute).getName() in ["args", "form", "json"])
    |
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 格式化字符串操作
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "format" and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    exists(BinOp binop |
      binop.getOp() instanceof Mod and
      sink.asExpr() = binop.getLeft()
    )
  }
}

module FormatStringFlow = TaintTracking::Global<FormatStringConfig>;

from FormatStringFlow::PathNode source, FormatStringFlow::PathNode sink
where FormatStringFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "格式化字符串使用了用户输入 $@，可能泄露敏感信息", 
  source.getNode(), "用户数据"
```

## 代码质量检查

### 1. 未使用的导入

```ql
/**
 * @name 未使用的导入
 * @description 查找未使用的导入语句
 * @kind problem
 * @problem.severity recommendation
 * @id py/unused-import
 */

import python

from Import imp, ImportMember im
where
  im = imp.getAName() and
  not exists(Name use |
    use.getId() = im.getName() and
    use.getScope() = im.getScope() and
    use != im and
    not use.getParentNode*() = imp
  ) and
  // 排除 __all__ 中使用的导入
  not exists(List all, StrConst s |
    all.getParentNode().(AssignStmt).getATarget().(Name).getId() = "__all__" and
    s = all.getAnElt() and
    s.getText() = im.getName()
  )

select im, "未使用的导入: " + im.getName()
```

### 2. 复杂函数检测

```ql
/**
 * @name 过于复杂的函数
 * @description 检测圈复杂度过高的函数
 * @kind problem
 * @problem.severity recommendation
 * @id py/complex-function
 */

import python

from Function f, int complexity
where
  complexity = count(Stmt s |
    s.getScope() = f and
    s instanceof If or s instanceof For or s instanceof While or
    s instanceof TryStmt or s instanceof With
  ) and
  complexity > 10 and
  not f.getName().matches("test_%")  // 排除测试函数

select f, "函数 '" + f.getName() + "' 过于复杂，圈复杂度为 " + complexity
```

### 3. 长参数列表

```ql
/**
 * @name 参数过多的函数
 * @description 检测参数数量过多的函数
 * @kind problem
 * @problem.severity recommendation
 * @id py/too-many-parameters
 */

import python

from Function f, int paramCount
where
  paramCount = count(f.getAParameter()) and
  paramCount > 7 and
  not f.isMethod()  // 方法的 self 参数不计入

select f, "函数 '" + f.getName() + "' 有 " + paramCount + " 个参数，考虑重构"
```

## 性能相关检查

### 1. 低效的字符串拼接

```ql
/**
 * @name 低效的字符串拼接
 * @description 检测在循环中使用 += 拼接字符串的低效模式
 * @kind problem
 * @problem.severity recommendation
 * @id py/inefficient-string-concatenation
 */

import python

from For loop, AugAssignStmt augassign
where
  augassign.getParent+() = loop and
  augassign.getOp() instanceof Add and
  augassign.getTarget().(Name).getVariable().getType().getName() = "str"

select augassign, "在循环中使用 += 拼接字符串效率低下，考虑使用 join()"
```

### 2. 不必要的列表推导

```ql
/**
 * @name 可优化的列表推导
 * @description 检测可以用生成器表达式替代的列表推导
 * @kind problem
 * @problem.severity recommendation
 * @id py/unnecessary-list-comprehension
 */

import python

from ListComp lc, CallNode call
where
  call.getArg(0) = lc and
  call.getFunction().(NameNode).getId() in ["sum", "max", "min", "any", "all"]

select lc, "列表推导可以用生成器表达式替代，节省内存"
```

## 测试和示例

### 创建测试用例

**测试目录结构：**
```
test/
├── Security/
│   └── CWE-089/
│       └── SqlInjection/
│           ├── test.py
│           ├── SqlInjection.qlref
│           └── SqlInjection.expected
```

**test.py:**
```python
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/bad')
def bad_query():
    # 应该被检测到的 SQL 注入
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    conn = sqlite3.connect('db.sqlite')
    return conn.execute(query).fetchall()

@app.route('/good')  
def good_query():
    # 不应该被检测到（参数化查询）
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = ?"
    conn = sqlite3.connect('db.sqlite')
    return conn.execute(query, (user_id,)).fetchall()
```

### 运行 Python 查询

```bash
# 创建 Python 数据库
codeql database create python-db --language=python --source-root=.

# 运行单个查询
codeql query run python/ql/src/Security/CWE-089/SqlInjection.ql \
  --database=python-db

# 运行 Python 安全套件
codeql database analyze python-db \
  python/ql/src/codeql-suites/python-security-and-quality.qls \
  --format=sarif-latest --output=results.sarif
```

## 最佳实践

### 1. 利用 Python 特定的 API

```ql
import python
import semmle.python.ApiGraphs

// 使用 API 图追踪框架使用
from API::Node request
where request = API::moduleImport("flask").getMember("request")
select request.getMember("args").getACall()
```

### 2. 处理 Python 的动态特性

```ql
// 处理动态属性访问
from Attribute attr
where attr.getName() = "dangerous_method"
select attr, "可能的危险方法调用"

// 处理 getattr 调用
from CallNode call
where 
  call.getFunction().(NameNode).getId() = "getattr" and
  call.getArg(1).asExpr().(StrConst).getText() = "dangerous_method"
select call, "通过 getattr 调用危险方法"
```

### 3. 框架特定的优化

```ql
// 专门针对 Django 的查询优化
import semmle.python.web.django.Django

from DjangoView view
where view.getHttpMethod() = "POST"
select view, "Django POST 视图"
```

## 下一步

掌握了 Python 场景应用后，建议继续学习：

1. **[Java 场景](08-java.md)** - 学习 Java 企业级应用分析
2. **[JavaScript 场景](09-javascript.md)** - 前端和 Node.js 安全分析
3. **[最佳实践](12-best-practices.md)** - 查询优化和调试技巧

---

**Python 场景掌握完毕！** 🐍 现在您可以分析各种 Python 应用的安全问题了。
