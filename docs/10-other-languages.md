# 其他语言支持

> Go、C/C++、C#、Ruby、Swift、Rust 等语言的 CodeQL 分析指南

## 支持的语言概览

| 语言 | 成熟度 | 主要用途 | 特色功能 |
|------|--------|----------|----------|
| **Go** | 🟢 完全支持 | 云原生、微服务、系统编程 | 并发安全、内存安全 |
| **C/C++** | 🟢 完全支持 | 系统编程、嵌入式、高性能 | 内存漏洞、缓冲区溢出 |
| **C#** | 🟢 完全支持 | .NET 应用、企业软件 | ASP.NET、Entity Framework |
| **Ruby** | 🟢 完全支持 | Web 应用、脚本 | Rails 框架、动态特性 |
| **Swift** | 🟡 基础支持 | iOS/macOS 应用 | 内存安全、并发 |
| **Rust** | 🟡 新增支持 | 系统编程、WebAssembly | 内存安全、零成本抽象 |

## Go 语言分析

### 目录结构

```
go/
├── ql/
│   ├── lib/
│   │   ├── semmle/go/
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   ├── frameworks/    # 框架支持
│   │   │   │   ├── Gin.qll        # Gin 框架
│   │   │   │   ├── Echo.qll       # Echo 框架
│   │   │   │   └── Gorilla.qll    # Gorilla 工具包
│   │   │   └── Concepts.qll   # 通用概念
│   │   └── go.qll
│   ├── src/Security/          # 安全查询
│   └── examples/              # 示例查询
└── extractor/                 # Go 提取器
```

### Go 核心类

```ql
import go

// 函数
from Function f
select f.getName(), f.getNumParameter(), f.getBody()

// 结构体
from StructType s
select s.getName(), s.getNumField()

// 接口
from InterfaceType i
select i.getName(), i.getNumMethod()

// Goroutine
from GoStmt go
select go.getCall()

// Channel 操作
from SendStmt send
select send.getChannel(), send.getValue()

from RecvStmt recv
select recv.getChannel()
```

### 1. Go SQL 注入检测

```ql
/**
 * @name Go SQL 注入检测
 * @description 检测 Go 应用中的 SQL 注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       go
 */

import go
import semmle.go.security.SqlInjection
import SqlInjection::Flow::PathGraph

from SqlInjection::Flow::PathNode source, SqlInjection::Flow::PathNode sink
where SqlInjection::Flow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "Go SQL 查询包含用户输入 $@，可能导致 SQL 注入", 
  source.getNode(), "用户数据"
```

### 2. Goroutine 泄露检测

```ql
/**
 * @name Goroutine 泄露检测
 * @description 检测可能导致 Goroutine 泄露的代码模式
 * @kind problem
 * @problem.severity warning
 * @id go/goroutine-leak
 * @tags reliability
 *       performance
 *       go
 */

import go

predicate hasExitCondition(GoStmt goStmt) {
  exists(Function f |
    f = goStmt.getCall().getTarget() and
    (
      // 有 return 语句
      exists(ReturnStmt ret | ret.getParent+() = f) or
      
      // 有 channel 接收操作（可能阻塞直到信号）
      exists(RecvStmt recv | recv.getParent+() = f) or
      
      // 有 select 语句（可能有退出条件）
      exists(SelectStmt sel | sel.getParent+() = f) or
      
      // 有 context.Done() 检查
      exists(CallExpr call |
        call.getParent+() = f and
        call.getTarget().hasQualifiedName("context", "Context", "Done")
      )
    )
  )
}

from GoStmt goStmt
where 
  not hasExitCondition(goStmt) and
  // 排除明显的一次性任务
  not exists(CallExpr call |
    call = goStmt.getCall() and
    call.getTarget().getName().regexpMatch("(?i).*(once|single|immediate).*")
  )

select goStmt, "Goroutine 可能没有退出条件，可能导致泄露"
```

### 3. 不安全的并发访问

```ql
/**
 * @name 不安全的并发访问
 * @description 检测可能的竞态条件
 * @kind problem
 * @problem.severity error
 * @security-severity 7.0
 * @id go/unsafe-concurrent-access
 * @tags security
 *       concurrency
 *       external/cwe/cwe-362
 *       go
 */

import go

predicate isSharedVariable(Variable v) {
  // 全局变量
  v.isGlobal() or
  
  // 结构体字段（可能被多个 Goroutine 访问）
  exists(Field f | f.getVariable() = v and f.getDeclaringType().getName() != "")
}

predicate hasProperSynchronization(Write write) {
  exists(CallExpr mutex |
    // 使用了 mutex.Lock()
    mutex.getTarget().hasQualifiedName("sync", "Mutex", "Lock") and
    mutex.getParent+() = write.getParent+()
  ) or
  
  exists(CallExpr rwmutex |
    // 使用了 RWMutex
    rwmutex.getTarget().hasQualifiedName("sync", "RWMutex", ["Lock", "RLock"]) and
    rwmutex.getParent+() = write.getParent+()
  ) or
  
  exists(SendStmt send |
    // 通过 channel 同步
    send.getParent+() = write.getParent+()
  )
}

from Write write1, Write write2, Variable v
where
  write1.writesVariable(v) and
  write2.writesVariable(v) and
  write1 != write2 and
  isSharedVariable(v) and
  
  // 在不同的 Goroutine 中
  exists(GoStmt go1, GoStmt go2 |
    write1.getParent+() = go1.getCall().getTarget().getBody() and
    write2.getParent+() = go2.getCall().getTarget().getBody() and
    go1 != go2
  ) and
  
  // 没有适当的同步
  not hasProperSynchronization(write1) and
  not hasProperSynchronization(write2)

select write1, "变量 '" + v.getName() + "' 可能存在竞态条件，与 $@ 同时访问", 
  write2, "这里"
```

### 4. Context 取消检查

```ql
/**
 * @name 缺少 Context 取消检查
 * @description 检测长时间运行的函数缺少 Context 取消检查
 * @kind problem
 * @problem.severity warning
 * @id go/missing-context-cancellation
 * @tags reliability
 *       performance
 *       go
 */

import go

predicate hasContextParameter(Function f) {
  exists(Parameter p |
    p = f.getAParameter() and
    p.getType().hasQualifiedName("context", "Context")
  )
}

predicate hasContextCheck(Function f) {
  exists(CallExpr call |
    call.getParent+() = f.getBody() and
    call.getTarget().hasQualifiedName("context", "Context", "Done")
  ) or
  
  exists(SelectStmt sel, CommClause clause |
    sel.getParent+() = f.getBody() and
    clause = sel.getACommClause() and
    exists(RecvStmt recv |
      recv = clause.getComm() and
      recv.getChannel().(CallExpr).getTarget().hasQualifiedName("context", "Context", "Done")
    )
  )
}

predicate isLongRunning(Function f) {
  // 包含循环
  exists(LoopStmt loop | loop.getParent+() = f.getBody()) or
  
  // 包含网络调用
  exists(CallExpr call |
    call.getParent+() = f.getBody() and
    call.getTarget().getPackage().getPath().matches("net/%")
  ) or
  
  // 包含数据库操作
  exists(CallExpr call |
    call.getParent+() = f.getBody() and
    call.getTarget().getPackage().getPath().matches("database/%")
  )
}

from Function f
where
  hasContextParameter(f) and
  isLongRunning(f) and
  not hasContextCheck(f)

select f, "长时间运行的函数缺少 Context 取消检查"
```

## C/C++ 语言分析

### 目录结构

```
cpp/
├── ql/
│   ├── lib/
│   │   ├── semmle/code/cpp/
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   ├── Memory.qll     # 内存管理
│   │   │   └── Concepts.qll   # 通用概念
│   │   └── cpp.qll
│   ├── src/Security/          # 安全查询
│   │   ├── CWE-119/          # 缓冲区溢出
│   │   ├── CWE-416/          # Use After Free
│   │   └── CWE-476/          # 空指针解引用
│   └── examples/              # 示例查询
└── extractor/                 # C/C++ 提取器
```

### 1. 缓冲区溢出检测

```ql
/**
 * @name 潜在的缓冲区溢出
 * @description 检测可能导致缓冲区溢出的数组访问
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @id cpp/potential-buffer-overflow
 * @tags security
 *       external/cwe/cwe-119
 *       cpp
 */

import cpp

from ArrayExpr access, Variable array
where
  access.getArrayBase() = array.getAnAccess() and
  
  // 数组访问使用了用户输入的索引
  exists(FunctionCall input |
    input.getTarget().hasName(["scanf", "gets", "fgets", "read"]) and
    access.getArrayOffset().getAChild*() = input.getAnArgument()
  ) and
  
  // 没有边界检查
  not exists(IfStmt check |
    check.getCondition().getAChild*() = access.getArrayOffset() and
    check.getThen().getAChild*() = access
  )

select access, "数组访问可能超出边界，索引来自用户输入"
```

### 2. Use-After-Free 检测

```ql
/**
 * @name Use After Free
 * @description 检测释放后使用的内存访问
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @id cpp/use-after-free
 * @tags security
 *       external/cwe/cwe-416
 *       cpp
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow

from FunctionCall free, VariableAccess use, Variable v
where
  // free 调用
  free.getTarget().hasName(["free", "delete"]) and
  free.getArgument(0) = v.getAnAccess() and
  
  // 后续使用
  use = v.getAnAccess() and
  use != free.getArgument(0) and
  
  // 控制流：free 在 use 之前
  exists(ControlFlowNode freeNode, ControlFlowNode useNode |
    freeNode.getASuccessor+() = useNode and
    freeNode.getAstNode() = free and
    useNode.getAstNode() = use
  ) and
  
  // 没有重新分配
  not exists(AssignExpr assign |
    assign.getLValue() = v.getAnAccess() and
    exists(ControlFlowNode assignNode, ControlFlowNode freeNode, ControlFlowNode useNode |
      freeNode.getASuccessor+() = assignNode and
      assignNode.getASuccessor+() = useNode and
      freeNode.getAstNode() = free and
      assignNode.getAstNode() = assign and
      useNode.getAstNode() = use
    )
  )

select use, "使用已释放的内存，在 $@ 处释放", free, "这里"
```

### 3. 空指针解引用

```ql
/**
 * @name 空指针解引用
 * @description 检测可能的空指针解引用
 * @kind problem
 * @problem.severity error
 * @id cpp/null-pointer-dereference
 * @tags reliability
 *       external/cwe/cwe-476
 *       cpp
 */

import cpp

predicate mayBeNull(Expr expr) {
  // 函数返回值可能为 null
  exists(FunctionCall call |
    call = expr and
    call.getTarget().hasName(["malloc", "calloc", "realloc", "fopen", "strchr"])
  ) or
  
  // 显式 null 赋值
  expr.(Literal).getValue() = "0" or
  expr.(Literal).getValue() = "NULL" or
  
  // 条件表达式的一个分支为 null
  exists(ConditionalExpr cond |
    cond = expr and
    (mayBeNull(cond.getThen()) or mayBeNull(cond.getElse()))
  )
}

predicate hasNullCheck(VariableAccess access) {
  exists(IfStmt check |
    check.getCondition().getAChild*() = access and
    check.getThen().getAChild*() = access.getParent+()
  )
}

from PointerDereferenceExpr deref, VariableAccess ptr
where
  ptr = deref.getOperand() and
  mayBeNull(ptr.getTarget().getAnAssignedValue()) and
  not hasNullCheck(ptr)

select deref, "可能的空指针解引用"
```

## C# 语言分析

### 目录结构

```
csharp/
├── ql/
│   ├── lib/
│   │   ├── semmle/code/csharp/
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   ├── frameworks/    # 框架支持
│   │   │   │   ├── AspNetCore.qll # ASP.NET Core
│   │   │   │   ├── EntityFramework.qll # EF
│   │   │   │   └── WPF.qll    # WPF
│   │   │   └── Concepts.qll   # 通用概念
│   │   └── csharp.qll
│   ├── src/Security/          # 安全查询
│   └── examples/              # 示例查询
└── extractor/                 # C# 提取器
```

### 1. ASP.NET Core SQL 注入

```ql
/**
 * @name ASP.NET Core SQL 注入
 * @description 检测 ASP.NET Core 应用中的 SQL 注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id csharp/aspnet-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       aspnet
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.frameworks.AspNetCore
import DataFlow::PathGraph

class AspNetSqlInjectionConfig extends TaintTracking::Configuration {
  AspNetSqlInjectionConfig() { this = "AspNetSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // ASP.NET Core 控制器参数
    exists(AspNetCoreController controller, Method action, Parameter param |
      action = controller.getAnAction() and
      param = action.getAParameter() and
      source.asParameter() = param
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // SQL 执行方法
    exists(MethodCall call |
      call.getTarget().hasName("ExecuteReader") and
      call.getTarget().getDeclaringType().hasName("SqlCommand") and
      sink.asExpr() = call.getQualifier().(PropertyAccess).getQualifier()
    )
    or
    // Entity Framework 原生 SQL
    exists(MethodCall call |
      call.getTarget().hasName("FromSqlRaw") and
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // 参数化查询
    exists(MethodCall call |
      call.getTarget().hasName("AddWithValue") and
      node.asExpr() = call.getQualifier()
    )
  }
}

from AspNetSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "ASP.NET Core SQL 查询包含用户输入 $@", 
  source.getNode(), "控制器参数"
```

### 2. 反序列化漏洞检测

```ql
/**
 * @name 不安全的 .NET 反序列化
 * @description 检测可能导致远程代码执行的反序列化操作
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id csharp/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       deserialization
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import DataFlow::PathGraph

class UnsafeDeserializationConfig extends TaintTracking::Configuration {
  UnsafeDeserializationConfig() { this = "UnsafeDeserializationConfig" }

  override predicate isSource(DataFlow::Node source) {
    // HTTP 请求数据
    exists(PropertyAccess prop |
      prop.getTarget().hasName(["Body", "Form", "Query"]) and
      prop.getQualifier().getType().hasName("HttpRequest") and
      source.asExpr() = prop
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // 危险的反序列化方法
    exists(MethodCall call |
      (
        // BinaryFormatter
        (call.getTarget().hasName("Deserialize") and
         call.getTarget().getDeclaringType().hasName("BinaryFormatter")) or
        
        // JavaScriptSerializer
        (call.getTarget().hasName("Deserialize") and
         call.getTarget().getDeclaringType().hasName("JavaScriptSerializer")) or
         
        // DataContractJsonSerializer (不安全使用)
        (call.getTarget().hasName("ReadObject") and
         call.getTarget().getDeclaringType().hasName("DataContractJsonSerializer"))
      ) and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

from UnsafeDeserializationConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "不安全的反序列化，数据来源于 $@", 
  source.getNode(), "HTTP 请求"
```

## Ruby 语言分析

### 目录结构

```
ruby/
├── ql/
│   ├── lib/
│   │   ├── codeql/ruby/
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   ├── frameworks/    # 框架支持
│   │   │   │   ├── Rails.qll      # Ruby on Rails
│   │   │   │   ├── Sinatra.qll    # Sinatra
│   │   │   │   └── Rack.qll       # Rack
│   │   │   └── Concepts.qll   # 通用概念
│   │   └── ruby.qll
│   ├── src/Security/          # 安全查询
│   └── examples/              # 示例查询
└── extractor/                 # Ruby 提取器
```

### 1. Rails SQL 注入检测

```ql
/**
 * @name Rails SQL 注入
 * @description 检测 Ruby on Rails 应用中的 SQL 注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id ruby/rails-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       rails
 */

import ruby
import codeql.ruby.security.SqlInjectionQuery
import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "Rails SQL 查询包含用户输入 $@", 
  source.getNode(), "用户参数"
```

### 2. 代码注入检测

```ql
/**
 * @name Ruby 代码注入
 * @description 检测 Ruby 中的代码注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @id ruby/code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       ruby
 */

import ruby
import codeql.ruby.dataflow.TaintTracking
import DataFlow::PathGraph

class RubyCodeInjectionConfig extends TaintTracking::Configuration {
  RubyCodeInjectionConfig() { this = "RubyCodeInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // HTTP 参数
    exists(MethodCall call |
      call.getMethodName() = "params" and
      source.asExpr().getAChild*() = call
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // 代码执行方法
    exists(MethodCall call |
      call.getMethodName() in ["eval", "instance_eval", "class_eval", "module_eval"] and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

from RubyCodeInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Ruby 代码执行包含用户输入 $@", 
  source.getNode(), "HTTP 参数"
```

## Swift 语言分析

### 目录结构

```
swift/
├── ql/
│   ├── lib/
│   │   ├── codeql/swift/
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   └── frameworks/    # 框架支持
│   │   └── swift.qll
│   ├── src/Security/          # 安全查询
│   └── examples/              # 示例查询
└── extractor/                 # Swift 提取器
```

### 1. 不安全的数据存储

```ql
/**
 * @name iOS 不安全的数据存储
 * @description 检测在 iOS 应用中不安全的敏感数据存储
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @id swift/insecure-data-storage
 * @tags security
 *       mobile
 *       external/cwe/cwe-312
 *       swift
 */

import swift

from CallExpr call, StringLiteralExpr key
where
  // UserDefaults 存储
  call.getStaticTarget().hasName("set") and
  call.getStaticTarget().getEnclosingDecl().getName() = "UserDefaults" and
  key = call.getArgument(1).getExpr() and
  key.getValue().regexpMatch("(?i).*(password|secret|token|key|pin|credential).*")

select call, "敏感数据存储在 UserDefaults 中，应使用 Keychain"
```

### 2. 弱加密检测

```ql
/**
 * @name Swift 弱加密算法
 * @description 检测使用弱加密算法的 Swift 代码
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @id swift/weak-crypto-algorithm
 * @tags security
 *       external/cwe/cwe-327
 *       swift
 */

import swift

from CallExpr call
where
  call.getStaticTarget().hasName(["MD5", "SHA1"]) or
  (call.getStaticTarget().hasName("init") and
   call.getStaticTarget().getEnclosingDecl().getName() in ["Insecure.MD5", "Insecure.SHA1"])

select call, "使用了弱加密算法，建议使用 SHA-256 或更强的算法"
```

## Rust 语言分析

### 目录结构

```
rust/
├── ql/
│   ├── lib/
│   │   ├── codeql/rust/
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   └── elements/      # 语言元素
│   │   └── rust.qll
│   ├── src/Security/          # 安全查询
│   └── examples/              # 示例查询
└── extractor/                 # Rust 提取器
```

### 1. 不安全代码块检测

```ql
/**
 * @name Rust 不安全代码块
 * @description 检测 Rust 中的 unsafe 代码块
 * @kind problem
 * @problem.severity warning
 * @id rust/unsafe-code-block
 * @tags security
 *       unsafe
 *       rust
 */

import rust

from UnsafeBlockExpr unsafe
select unsafe, "使用了 unsafe 代码块，需要仔细审查内存安全性"
```

### 2. 潜在的 Panic 检测

```ql
/**
 * @name Rust 潜在的 Panic
 * @description 检测可能导致 panic 的 Rust 代码
 * @kind problem
 * @problem.severity warning
 * @id rust/potential-panic
 * @tags reliability
 *       rust
 */

import rust

from CallExpr call
where
  call.getExpr().(PathExpr).getPath().toString() in [
    "unwrap", "expect", "panic!", "unreachable!", "unimplemented!"
  ]

select call, "可能导致 panic 的调用，考虑使用更安全的错误处理"
```

## 跨语言分析模式

### 1. 通用安全模式

```ql
/**
 * @name 跨语言硬编码密钥检测
 * @description 检测各种语言中的硬编码密钥
 * @kind problem
 * @problem.severity error
 * @id multi-lang/hardcoded-key
 */

// 这个查询需要在特定语言的上下文中实现
// 但可以使用相似的模式

predicate isHardcodedSecret(string value) {
  value.length() > 16 and
  value.regexpMatch("[A-Za-z0-9+/]{20,}={0,2}") and  // Base64
  not value.regexpMatch("(?i).*(example|test|dummy).*")
}

// 在每种语言中查找字符串字面量
// Python: StrConst
// Java: StringLiteral  
// JavaScript: StringLiteral
// Go: StringLit
// C++: StringLiteral
// 等等...
```

### 2. 配置文件安全检查

```ql
/**
 * @name 配置文件敏感信息
 * @description 检测配置文件中的敏感信息
 * @kind problem
 * @problem.severity error
 * @id config/sensitive-info
 */

// 检查各种配置文件格式
// .env, .properties, .yaml, .json, .xml, .ini
// 查找包含敏感信息的键值对
```

## 最佳实践

### 1. 语言特定优化

```ql
// Go: 利用 Goroutine 和 Channel 的特性
import go

from GoStmt goStmt, SendStmt send
where send.getParent+() = goStmt.getCall().getTarget().getBody()
select goStmt, "Goroutine 使用了 channel 通信"

// C++: 利用 RAII 和智能指针
import cpp

from Variable v
where v.getType().(PointerType).getBaseType().hasName("unique_ptr")
select v, "使用了智能指针"

// Rust: 利用所有权系统
import rust

from BorrowExpr borrow
select borrow, "借用表达式"
```

### 2. 框架特定分析

```ql
// Rails 特定
import ruby

from MethodCall call
where 
  call.getMethodName() = "where" and
  call.getReceiver().getType().getName().matches("ActiveRecord::%")
select call, "ActiveRecord 查询"

// ASP.NET Core 特定
import csharp

from Attribute attr
where attr.getType().hasName("HttpPostAttribute")
select attr, "HTTP POST 端点"
```

### 3. 性能考虑

不同语言的查询性能特点：

- **Go**: 并发模式分析可能较慢
- **C/C++**: 指针分析复杂度高
- **Rust**: 生命周期分析需要特殊处理
- **Swift**: iOS 框架调用链较深

## 测试和验证

### 多语言测试策略

```bash
# 为每种语言创建测试数据库
codeql database create go-db --language=go --source-root=./go-project
codeql database create cpp-db --language=cpp --source-root=./cpp-project
codeql database create csharp-db --language=csharp --source-root=./csharp-project

# 运行语言特定的查询套件
codeql database analyze go-db go-security-and-quality.qls
codeql database analyze cpp-db cpp-security-and-quality.qls
codeql database analyze csharp-db csharp-security-and-quality.qls
```

## 下一步

掌握了其他语言支持后，建议继续学习：

1. **[开发工具](11-tools.md)** - CodeQL CLI、VS Code 扩展、CI/CD 集成
2. **[最佳实践](12-best-practices.md)** - 查询优化和调试技巧
3. **[贡献指南](13-contributing.md)** - 如何为 CodeQL 项目贡献代码

---

**其他语言支持掌握完毕！** 🌐 现在您可以分析多种编程语言的安全问题了。
