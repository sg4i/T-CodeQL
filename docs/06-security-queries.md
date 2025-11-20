# 安全查询实战

> 编写实用的安全检测查询，从经典漏洞到新兴威胁的完整覆盖

## 安全查询概览

### OWASP Top 10 覆盖

| 排名 | 漏洞类型 | CWE | CodeQL 查询 | 支持语言 |
|------|----------|-----|-------------|----------|
| A01 | 访问控制失效 | CWE-200, CWE-284 | 权限检查缺失 | 所有 |
| A02 | 加密失效 | CWE-327, CWE-326 | 弱加密算法 | 所有 |
| A03 | 注入攻击 | CWE-089, CWE-078 | SQL/命令注入 | 所有 |
| A04 | 不安全设计 | CWE-209, CWE-256 | 信息泄露 | 所有 |
| A05 | 安全配置错误 | CWE-16, CWE-611 | 配置检查 | 所有 |
| A06 | 易受攻击组件 | CWE-1104 | 依赖检查 | 部分 |
| A07 | 身份认证失效 | CWE-287, CWE-384 | 认证绕过 | 所有 |
| A08 | 软件数据完整性失效 | CWE-502 | 反序列化 | 所有 |
| A09 | 安全日志监控失效 | CWE-778 | 日志检查 | 所有 |
| A10 | 服务端请求伪造 | CWE-918 | SSRF 检测 | 所有 |

## 注入攻击检测

### 1. SQL 注入全面检测

```ql
/**
 * @name 高级 SQL 注入检测
 * @description 检测各种形式的 SQL 注入漏洞，包括盲注和二阶注入
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id security/sql-injection-comprehensive
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/owasp-a03
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Web 框架输入
    exists(Attribute attr |
      attr.getObject().(Name).getId() in ["request", "req", "ctx"] and
      attr.getName() in ["args", "form", "json", "data", "params", "query", "body"] and
      source.asExpr() = attr
    )
    or
    // 文件输入
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["read", "readline", "readlines"] and
      source.asCfgNode() = call
    )
    or
    // 环境变量
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "os" and
      call.getFunction().(Attribute).getName() in ["getenv", "environ"] and
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 数据库执行方法
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in [
        "execute", "executemany", "query", "raw", "exec", "exec_driver_sql"
      ] and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // ORM 原始查询
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["raw", "extra"] and
      call.getFunction().(Attribute).getObject().asExpr().getAFlowNode().pointsTo().getClass().getName() in [
        "QuerySet", "Manager", "Model"
      ] and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // 存储过程调用
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "callproc" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 参数化查询
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["execute", "executemany"] and
      call.getNumArg() >= 2 and
      node.asCfgNode() = call.getArg(0)
    )
    or
    // SQL 转义函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId().regexpMatch(".*(?i)(escape|quote|sanitize).*") and
      node.asCfgNode() = call
    )
    or
    // 类型转换为数字
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["int", "float", "decimal.Decimal"] and
      node.asCfgNode() = call
    )
  }
  
  predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 字符串拼接
    exists(BinOp binop |
      binop.getOp() instanceof Add and
      (fromNode.asExpr() = binop.getLeft() or fromNode.asExpr() = binop.getRight()) and
      toNode.asExpr() = binop
    )
    or
    // 字符串格式化
    exists(BinOp binop |
      binop.getOp() instanceof Mod and
      fromNode.asExpr() = binop.getRight() and
      toNode.asExpr() = binop
    )
    or
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "format" and
      fromNode.asCfgNode() = call.getArg(_) and
      toNode.asCfgNode() = call
    )
    or
    // f-string 格式化
    exists(FormattedValue fv |
      fromNode.asExpr() = fv.getValue() and
      toNode.asExpr() = fv.getParentNode()
    )
  }
}

module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "SQL 查询包含未经验证的用户输入 $@，可能导致 SQL 注入攻击", 
  source.getNode(), "数据源"
```

### 2. NoSQL 注入检测

```ql
/**
 * @name NoSQL 注入检测
 * @description 检测 MongoDB 等 NoSQL 数据库的注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id security/nosql-injection
 * @tags security
 *       external/cwe/cwe-943
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module NoSqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Web 输入源
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["args", "form", "json"] and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // MongoDB 查询操作
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in [
        "find", "find_one", "update", "update_one", "update_many",
        "delete_one", "delete_many", "aggregate", "count_documents"
      ] and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // PyMongo 原始查询
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "command" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 类型验证
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["isinstance", "type"] and
      node.asCfgNode() = call.getArg(0)
    )
  }
}

module NoSqlInjectionFlow = TaintTracking::Global<NoSqlInjectionConfig>;

from NoSqlInjectionFlow::PathNode source, NoSqlInjectionFlow::PathNode sink
where NoSqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "NoSQL 查询包含用户输入 $@，可能导致 NoSQL 注入", 
  source.getNode(), "用户数据"
```

### 3. 命令注入深度检测

```ql
/**
 * @name 高级命令注入检测
 * @description 检测各种形式的系统命令注入，包括间接调用
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id security/command-injection-advanced
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/owasp-a03
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module CommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 各种用户输入源
    exists(Attribute attr |
      attr.getObject().(Name).getId() in ["request", "req"] and
      attr.getName() in ["args", "form", "json", "data", "files"] and
      source.asExpr() = attr
    )
    or
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["input", "raw_input"] and
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 直接命令执行
    exists(CallNode call |
      (
        // os 模块
        (call.getFunction().(Attribute).getObject().(Name).getId() = "os" and
         call.getFunction().(Attribute).getName() in ["system", "popen", "execv", "execl", "execvp", "execlp"]) or
        
        // subprocess 模块
        (call.getFunction().(Attribute).getObject().(Name).getId() = "subprocess" and
         call.getFunction().(Attribute).getName() in ["call", "run", "Popen", "check_output", "check_call"]) or
         
        // 其他危险函数
        call.getFunction().(NameNode).getId() in ["exec", "eval", "compile"]
      ) and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // 通过 shell 参数的间接执行
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["call", "run", "Popen"] and
      exists(Keyword kw |
        kw = call.getAKeyword() and
        kw.getArg() = "shell" and
        kw.getValue().(NameConstant).getValue() = "True"
      ) and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 命令转义
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["quote", "escape"] and
      call.getFunction().(Attribute).getObject().(Name).getId() in ["shlex", "pipes"] and
      node.asCfgNode() = call
    )
    or
    // 使用列表形式（相对安全）
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["call", "run", "Popen"] and
      call.getArg(0).asExpr() instanceof List and
      node.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 字符串拼接传播污点
    exists(BinOp binop |
      binop.getOp() instanceof Add and
      (fromNode.asExpr() = binop.getLeft() or fromNode.asExpr() = binop.getRight()) and
      toNode.asExpr() = binop
    )
    or
    // 通过 join 方法
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "join" and
      fromNode.asCfgNode() = call.getArg(0) and
      toNode.asCfgNode() = call
    )
  }
}

module CommandInjectionFlow = TaintTracking::Global<CommandInjectionConfig>;

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "系统命令执行包含用户输入 $@，可能导致命令注入攻击", 
  source.getNode(), "用户输入"
```

## 跨站脚本攻击 (XSS)

### 1. 反射型 XSS 检测

```ql
/**
 * @name 反射型 XSS 检测
 * @description 检测用户输入直接输出到 HTML 响应的 XSS 漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @id security/reflected-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/owasp-a03
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module ReflectedXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // HTTP 请求参数
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["args", "form", "values"] and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // HTML 响应输出
    exists(CallNode call |
      (
        // Flask render_template_string
        call.getFunction().(NameNode).getId() = "render_template_string" or
        
        // Django HttpResponse
        (call.getFunction().(NameNode).getId() = "HttpResponse" and
         call.getFunction().(Attribute).getObject().(Name).getId() = "django.http") or
         
        // 直接字符串返回
        call.getFunction().(NameNode).getId() in ["make_response", "jsonify"]
      ) and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // HTML 转义函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId().regexpMatch(".*(?i)(escape|sanitize).*") and
      node.asCfgNode() = call
    )
    or
    // Jinja2 自动转义
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "render_template" and
      node.asCfgNode() = call.getArg(_)
    )
  }
}

module ReflectedXssFlow = TaintTracking::Global<ReflectedXssConfig>;

from ReflectedXssFlow::PathNode source, ReflectedXssFlow::PathNode sink
where ReflectedXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "用户输入 $@ 直接输出到 HTML 响应，可能导致反射型 XSS", 
  source.getNode(), "HTTP 参数"
```

### 2. 存储型 XSS 检测

```ql
/**
 * @name 存储型 XSS 检测
 * @description 检测存储到数据库后输出的 XSS 漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @id security/stored-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module StoredXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 数据库读取
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in [
        "fetchone", "fetchall", "fetchmany", "execute"
      ] and
      source.asCfgNode() = call
    )
    or
    // ORM 查询结果
    exists(Attribute attr |
      attr.getName() in ["objects", "query"] and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // HTML 模板渲染
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in [
        "render_template", "render_template_string"
      ] and
      sink.asCfgNode() = call.getArg(_)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // HTML 转义
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["escape", "html.escape"] and
      node.asCfgNode() = call
    )
  }
}

module StoredXssFlow = TaintTracking::Global<StoredXssConfig>;

from StoredXssFlow::PathNode source, StoredXssFlow::PathNode sink
where StoredXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "数据库数据 $@ 未经转义输出到 HTML，可能导致存储型 XSS", 
  source.getNode(), "数据库查询"
```

## 访问控制和权限

### 1. 权限检查缺失

```ql
/**
 * @name 权限检查缺失
 * @description 检测缺少权限验证的敏感操作
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @id security/missing-authorization
 * @tags security
 *       external/cwe/cwe-284
 *       external/owasp/owasp-a01
 */

import python

predicate isSensitiveOperation(Function f) {
  // 敏感操作函数名模式
  f.getName().regexpMatch("(?i).*(delete|remove|admin|modify|update|create|edit).*") or
  
  // 包含敏感操作的函数
  exists(CallNode call |
    call.getScope() = f and
    call.getFunction().(Attribute).getName() in [
      "delete", "remove", "drop", "truncate", "update", "insert"
    ]
  )
}

predicate hasAuthorizationCheck(Function f) {
  // 权限检查装饰器
  exists(Decorator d |
    d = f.getADecorator() and
    d.getName().regexpMatch("(?i).*(auth|permission|login|require).*")
  ) or
  
  // 函数内权限检查
  exists(CallNode call |
    call.getScope() = f and
    call.getFunction().(NameNode).getId().regexpMatch("(?i).*(check|verify|validate).*(auth|permission|role).*")
  ) or
  
  // 条件权限检查
  exists(If ifstmt, Attribute attr |
    ifstmt.getParent+() = f and
    attr.getParent+() = ifstmt.getTest() and
    attr.getName().regexpMatch("(?i).*(auth|permission|role|admin).*")
  )
}

from Function f
where 
  isSensitiveOperation(f) and
  not hasAuthorizationCheck(f) and
  // 排除测试函数
  not f.getName().matches("test_%") and
  not f.getScope().(Class).getName().matches("Test%")

select f, "敏感操作函数 '" + f.getName() + "' 缺少权限检查"
```

### 2. 不安全的直接对象引用

```ql
/**
 * @name 不安全的直接对象引用
 * @description 检测直接使用用户输入访问对象的安全风险
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.0
 * @id security/insecure-direct-object-reference
 * @tags security
 *       external/cwe/cwe-639
 *       external/owasp/owasp-a01
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module IdorConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // URL 路径参数
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["args", "form", "view_args"] and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 数据库查询中的 ID 参数
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["get", "filter", "get_object_or_404"] and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // 文件路径访问
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "open" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 权限检查
    exists(CallNode call |
      call.getFunction().(NameNode).getId().regexpMatch("(?i).*(check|verify).*(owner|permission).*") and
      node.asCfgNode() = call.getArg(0)
    )
  }
}

module IdorFlow = TaintTracking::Global<IdorConfig>;

from IdorFlow::PathNode source, IdorFlow::PathNode sink
where IdorFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "直接使用用户输入 $@ 访问对象，可能导致越权访问", 
  source.getNode(), "用户参数"
```

## 加密和密码学

### 1. 弱加密算法检测

```ql
/**
 * @name 弱加密算法使用
 * @description 检测使用已知不安全的加密算法
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @id security/weak-cryptographic-algorithm
 * @tags security
 *       external/cwe/cwe-327
 *       external/owasp/owasp-a02
 */

import python

from CallNode call, string algorithm
where
  (
    // hashlib 弱哈希算法
    (call.getFunction().(Attribute).getObject().(Name).getId() = "hashlib" and
     call.getFunction().(Attribute).getName() = algorithm and
     algorithm in ["md5", "sha1"]) or
    
    // Crypto 弱加密算法
    (call.getFunction().(Attribute).getObject().(Name).getId() in ["Crypto", "cryptography"] and
     call.getFunction().(Attribute).getName() = algorithm and
     algorithm in ["DES", "3DES", "RC4", "MD5", "SHA1"]) or
     
    // 直接调用弱算法
    (call.getFunction().(NameNode).getId() = algorithm and
     algorithm in ["md5", "sha1"])
  )

select call, "使用了不安全的加密算法: " + algorithm + "，建议使用 SHA-256 或更强的算法"
```

### 2. 硬编码密钥检测

```ql
/**
 * @name 硬编码加密密钥
 * @description 检测代码中硬编码的加密密钥和密码
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @id security/hardcoded-cryptographic-key
 * @tags security
 *       external/cwe/cwe-798
 *       external/owasp/owasp-a02
 */

import python

from AssignStmt assign, StrConst secret, string varName
where
  // 变量名包含密钥相关词汇
  exists(Name target |
    target = assign.getATarget() and
    varName = target.getId() and
    varName.regexpMatch("(?i).*(key|secret|password|token|api_key|private_key|secret_key).*")
  ) and
  
  // 赋值为字符串常量
  secret = assign.getValue() and
  
  // 字符串长度合理（可能是密钥）
  secret.getText().length() > 8 and
  secret.getText().length() < 200 and
  
  // 不是明显的占位符或示例
  not secret.getText().regexpMatch("(?i).*(example|test|dummy|placeholder|your_.*_here|xxx|todo|fixme).*") and
  
  // 包含字母和数字（像真实密钥）
  secret.getText().regexpMatch(".*[a-zA-Z].*[0-9].*") and
  
  // 不是常见的配置值
  not secret.getText() in ["localhost", "127.0.0.1", "utf-8", "application/json"]

select assign, "发现硬编码的密钥 '" + varName + "'，应使用环境变量或密钥管理系统"
```

### 3. 不安全的随机数生成

```ql
/**
 * @name 不安全的随机数生成
 * @description 检测在安全上下文中使用不安全的随机数生成器
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @id security/insecure-random-generator
 * @tags security
 *       external/cwe/cwe-338
 *       external/owasp/owasp-a02
 */

import python

predicate isSecurityContext(Function f) {
  f.getName().regexpMatch("(?i).*(auth|login|session|token|key|crypto|password|secret|nonce|salt).*") or
  exists(CallNode call |
    call.getScope() = f and
    call.getFunction().(NameNode).getId().regexpMatch("(?i).*(encrypt|decrypt|sign|verify|hash).*")
  )
}

from CallNode call, string module, string function
where
  // 使用了不安全的随机数函数
  (
    (call.getFunction().(Attribute).getObject().(Name).getId() = module and
     call.getFunction().(Attribute).getName() = function and
     module = "random" and function in ["random", "randint", "choice", "shuffle"]) or
    
    (call.getFunction().(NameNode).getId() = function and
     function in ["random", "randint"])
  ) and
  
  // 在安全相关的上下文中
  isSecurityContext(call.getScope().(Function))

select call, "在安全上下文中使用了不安全的随机数生成器 " + module + "." + function + 
  "，应使用 secrets 模块或 os.urandom()"
```

## 反序列化漏洞

### 1. 不安全的 Pickle 反序列化

```ql
/**
 * @name 不安全的 Pickle 反序列化
 * @description 检测可能导致远程代码执行的 pickle 反序列化
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id security/unsafe-pickle-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       external/owasp/owasp-a08
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module PickleDeserializationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 网络输入
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["data", "json", "form", "files"] and
      source.asExpr() = attr
    )
    or
    // 文件输入
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "open" and
      exists(StrConst mode |
        mode = call.getArg(1) and
        mode.getText().matches("%rb%")
      ) and
      source.asCfgNode() = call
    )
    or
    // 网络套接字
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["recv", "recvfrom"] and
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
    or
    // cPickle (Python 2)
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "cPickle" and
      call.getFunction().(Attribute).getName() in ["load", "loads"] and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // dill 库
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "dill" and
      call.getFunction().(Attribute).getName() in ["load", "loads"] and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module PickleFlow = TaintTracking::Global<PickleDeserializationConfig>;

from PickleFlow::PathNode source, PickleFlow::PathNode sink
where PickleFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "不安全的 pickle 反序列化，数据来源于 $@，可能导致远程代码执行", 
  source.getNode(), "外部输入"
```

### 2. YAML 反序列化漏洞

```ql
/**
 * @name 不安全的 YAML 反序列化
 * @description 检测使用不安全的 YAML 加载器可能导致的代码执行
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id security/unsafe-yaml-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module YamlDeserializationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 外部输入源
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["data", "json", "form"] and
      source.asExpr() = attr
    )
    or
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "open" and
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 不安全的 YAML 加载
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "yaml" and
      call.getFunction().(Attribute).getName() in ["load", "load_all"] and
      // 没有指定安全的 Loader
      not exists(Keyword kw |
        kw = call.getAKeyword() and
        kw.getArg() = "Loader" and
        kw.getValue().(Attribute).getName() = "SafeLoader"
      ) and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module YamlFlow = TaintTracking::Global<YamlDeserializationConfig>;

from YamlFlow::PathNode source, YamlFlow::PathNode sink
where YamlFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "不安全的 YAML 反序列化，数据来源于 $@，应使用 SafeLoader", 
  source.getNode(), "外部输入"
```

## 服务端请求伪造 (SSRF)

```ql
/**
 * @name 服务端请求伪造 (SSRF)
 * @description 检测可能导致 SSRF 攻击的 HTTP 请求
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id security/server-side-request-forgery
 * @tags security
 *       external/cwe/cwe-918
 *       external/owasp/owasp-a10
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module SsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // HTTP 请求参数
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["args", "form", "json"] and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // HTTP 客户端请求
    exists(CallNode call |
      (
        // requests 库
        (call.getFunction().(Attribute).getObject().(Name).getId() = "requests" and
         call.getFunction().(Attribute).getName() in ["get", "post", "put", "delete", "request"]) or
        
        // urllib
        (call.getFunction().(Attribute).getObject().(Name).getId() in ["urllib", "urllib2"] and
         call.getFunction().(Attribute).getName() in ["urlopen", "Request"]) or
         
        // httpx
        (call.getFunction().(Attribute).getObject().(Name).getId() = "httpx" and
         call.getFunction().(Attribute).getName() in ["get", "post", "put", "delete"])
      ) and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // URL 验证
    exists(CallNode call |
      call.getFunction().(NameNode).getId().regexpMatch("(?i).*(validate|check).*(url|domain).*") and
      node.asCfgNode() = call.getArg(0)
    )
    or
    // 白名单检查
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "startswith" and
      call.getArg(0).asExpr().(StrConst).getText().regexpMatch("https?://[a-zA-Z0-9.-]+\\.(com|org|net).*") and
      node.asCfgNode() = call.getQualifier()
    )
  }
}

module SsrfFlow = TaintTracking::Global<SsrfConfig>;

from SsrfFlow::PathNode source, SsrfFlow::PathNode sink
where SsrfFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "HTTP 请求使用了用户输入的 URL $@，可能导致 SSRF 攻击", 
  source.getNode(), "用户参数"
```

## 信息泄露检测

### 1. 敏感信息日志记录

```ql
/**
 * @name 敏感信息日志记录
 * @description 检测可能记录敏感信息的日志语句
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @id security/sensitive-info-logging
 * @tags security
 *       external/cwe/cwe-532
 *       external/owasp/owasp-a09
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module SensitiveLoggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 敏感变量
    exists(Name name |
      name.getId().regexpMatch("(?i).*(password|secret|token|key|credential|auth).*") and
      source.asExpr() = name
    )
    or
    // 敏感属性访问
    exists(Attribute attr |
      attr.getName().regexpMatch("(?i).*(password|secret|token|key).*") and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 日志记录函数
    exists(CallNode call |
      (
        // logging 模块
        (call.getFunction().(Attribute).getObject().(Name).getId() = "logging" and
         call.getFunction().(Attribute).getName() in ["debug", "info", "warning", "error", "critical"]) or
        
        // logger 实例
        (call.getFunction().(Attribute).getName() in ["debug", "info", "warning", "error", "critical"]) or
        
        // print 语句
        call.getFunction().(NameNode).getId() = "print"
      ) and
      sink.asCfgNode() = call.getArg(_)
    )
  }
}

module SensitiveLoggingFlow = TaintTracking::Global<SensitiveLoggingConfig>;

from SensitiveLoggingFlow::PathNode source, SensitiveLoggingFlow::PathNode sink
where SensitiveLoggingFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "日志记录可能包含敏感信息 $@", 
  source.getNode(), "敏感数据"
```

### 2. 错误信息泄露

```ql
/**
 * @name 详细错误信息泄露
 * @description 检测可能泄露系统信息的详细错误消息
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @id security/verbose-error-messages
 * @tags security
 *       external/cwe/cwe-209
 *       external/owasp/owasp-a04
 */

import python

from TryStmt try, ExceptStmt except, CallNode call
where
  except = try.getAHandler() and
  call.getParent+() = except and
  (
    // 直接返回异常信息
    (call.getFunction().(NameNode).getId() in ["str", "repr"] and
     call.getArg(0).(Name).getId() = except.getName()) or
    
    // 打印异常堆栈
    (call.getFunction().(Attribute).getObject().(Name).getId() = "traceback" and
     call.getFunction().(Attribute).getName() in ["print_exc", "format_exc"]) or
     
    // 返回异常详情
    (call.getFunction().(NameNode).getId() = "jsonify" and
     exists(Keyword kw |
       kw = call.getAKeyword() and
       kw.getValue().(Name).getId() = except.getName()
     ))
  )

select call, "异常处理可能泄露敏感的系统信息，建议返回通用错误消息"
```

## 下一步

掌握了安全查询实战后，建议继续学习：

1. **[Java 场景](08-java.md)** - Java 企业级应用安全分析
2. **[JavaScript 场景](09-javascript.md)** - 前端和 Node.js 安全检测
3. **[最佳实践](12-best-practices.md)** - 查询优化和性能调优

---

**安全查询实战完成！** 🛡️ 现在您可以编写专业级的安全检测查询了。
