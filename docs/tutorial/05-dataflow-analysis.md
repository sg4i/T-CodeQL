# 数据流分析

> 掌握 CodeQL 最强大的功能：数据流分析和污点追踪技术

## 数据流分析概述

数据流分析是 CodeQL 的核心功能，用于追踪数据在程序中的流动。它是发现安全漏洞的关键技术。

### 核心概念

- **Source（源）**：数据的起点，通常是用户输入
- **Sink（汇）**：敏感操作，如数据库查询、文件操作
- **Flow（流）**：从源到汇的数据传播路径
- **Barrier（屏障）**：阻止数据流的清理或验证操作
- **Sanitizer（清理器）**：移除或中和危险数据的操作

### 数据流类型

1. **局部数据流**：函数内部的数据流
2. **全局数据流**：跨函数、跨文件的数据流
3. **污点追踪**：追踪"被污染"的数据（来自不可信源）

## 基础数据流

### 局部数据流示例

```ql
/**
 * @name 局部数据流示例
 * @kind path-problem
 * @id py/local-dataflow-example
 */

import python
import semmle.python.dataflow.new.DataFlow
import DataFlow::PathGraph

from DataFlow::Node source, DataFlow::Node sink
where 
  // 在同一函数内的数据流
  DataFlow::localFlow(source, sink) and
  
  // 源：函数参数
  source.asExpr().(Name).getId() = "user_input" and
  
  // 汇：print 调用
  exists(CallNode call |
    call.getFunction().(NameNode).getId() = "print" and
    sink.asCfgNode() = call.getArg(0)
  )

select sink, source, sink, "数据从参数 $@ 流向 print", source, "user_input"
```

**测试代码：**
```python
def example(user_input):
    data = user_input      # 数据流步骤1
    result = data + "!"    # 数据流步骤2
    print(result)          # 数据流步骤3 - 到达汇点
```

### 全局数据流配置

```ql
/**
 * @name 全局数据流配置
 * @kind path-problem
 * @id py/global-dataflow-example
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module GlobalFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 定义源：HTTP 请求参数
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["args", "form", "json"] and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 定义汇：文件写入操作
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "write" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 定义屏障：经过验证的数据
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "sanitize" and
      node.asCfgNode() = call
    )
  }
}

module GlobalFlow = DataFlow::Global<GlobalFlowConfig>;

from GlobalFlow::PathNode source, GlobalFlow::PathNode sink
where GlobalFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "未经验证的用户输入 $@ 被写入文件", source.getNode(), "HTTP 请求"
```

## 污点追踪

污点追踪是数据流分析的扩展，专门追踪来自不可信源的"被污染"数据。

### 基础污点追踪

```ql
/**
 * @name 基础污点追踪
 * @kind path-problem
 * @id py/basic-taint-tracking
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module BasicTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 污点源：用户输入
    source.asCfgNode().(CallNode).getFunction().(NameNode).getId() = "input"
  }

  predicate isSink(DataFlow::Node sink) {
    // 污点汇：系统命令执行
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "os" and
      call.getFunction().(Attribute).getName() = "system" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module BasicTaint = TaintTracking::Global<BasicTaintConfig>;

from BasicTaint::PathNode source, BasicTaint::PathNode sink
where BasicTaint::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "系统命令执行使用了来自 $@ 的污点数据", source.getNode(), "用户输入"
```

### 高级污点追踪：自定义传播

```ql
/**
 * @name 高级污点追踪
 * @kind path-problem
 * @id py/advanced-taint-tracking
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module AdvancedTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 多种污点源
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["input", "raw_input"] or
      (
        call.getFunction().(Attribute).getObject().(Name).getId() = "request" and
        call.getFunction().(Attribute).getName() in ["args", "form", "json", "data"]
      )
    |
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 多种危险操作
    exists(CallNode call |
      (
        // 代码执行
        call.getFunction().(NameNode).getId() in ["eval", "exec", "compile"] or
        
        // 系统命令
        (call.getFunction().(Attribute).getObject().(Name).getId() = "os" and
         call.getFunction().(Attribute).getName() in ["system", "popen"]) or
         
        // 子进程
        (call.getFunction().(Attribute).getObject().(Name).getId() = "subprocess" and
         call.getFunction().(Attribute).getName() in ["call", "run", "Popen"])
      ) and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 自定义污点传播步骤
    
    // 1. 字符串格式化传播污点
    exists(BinOp binop |
      binop.getOp() instanceof Mod and  // % 格式化
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
    
    // 2. 通过自定义函数传播
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["process_data", "transform", "encode"] and
      fromNode.asCfgNode() = call.getArg(0) and
      toNode.asCfgNode() = call
    )
    or
    
    // 3. 通过列表/字典操作传播
    exists(Subscript sub |
      fromNode.asExpr() = sub.getValue() and
      toNode.asExpr() = sub
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 清理函数阻止污点传播
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in [
        "escape", "sanitize", "validate", "clean", 
        "html_escape", "sql_escape", "shell_escape"
      ] and
      node.asCfgNode() = call
    )
  }
}

module AdvancedTaint = TaintTracking::Global<AdvancedTaintConfig>;

from AdvancedTaint::PathNode source, AdvancedTaint::PathNode sink
where AdvancedTaint::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "危险操作使用了来自 $@ 的污点数据", source.getNode(), "不可信源"
```

## 实际安全查询示例

### SQL 注入检测

```ql
/**
 * @name SQL 注入检测
 * @description 检测 SQL 查询中的用户输入，可能导致 SQL 注入
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/sql-injection-detection
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Web 框架输入源
    exists(Attribute attr |
      attr.getObject().(Name).getId() in ["request", "req"] and
      attr.getName() in ["args", "form", "json", "data", "params"] and
      source.asExpr() = attr
    )
    or
    // 直接用户输入
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["input", "raw_input"] and
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 数据库执行方法
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in [
        "execute", "executemany", "query", "raw"
      ] and
      sink.asCfgNode() = call.getArg(0)
    )
    or
    // ORM 原始查询
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["raw", "extra"] and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 参数化查询（安全）
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "execute" and
      call.getNumArg() >= 2 and  // 有参数列表
      node.asCfgNode() = call.getArg(0)
    )
    or
    // SQL 转义函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId().regexpMatch(".*escape.*") and
      node.asCfgNode() = call
    )
  }
  
  predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // SQL 字符串拼接
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
  }
}

module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "SQL 查询包含来自 $@ 的用户输入，可能导致 SQL 注入", 
  source.getNode(), "HTTP 请求"
```

### 命令注入检测

```ql
/**
 * @name 命令注入检测
 * @description 检测系统命令中的用户输入，可能导致命令注入
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/command-injection-detection
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module CommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 用户输入源（同 SQL 注入）
    exists(Attribute attr |
      attr.getObject().(Name).getId() in ["request", "req"] and
      attr.getName() in ["args", "form", "json", "data"] and
      source.asExpr() = attr
    )
    or
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["input", "raw_input"] and
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 系统命令执行
    exists(CallNode call |
      (
        // os 模块
        (call.getFunction().(Attribute).getObject().(Name).getId() = "os" and
         call.getFunction().(Attribute).getName() in ["system", "popen", "execv", "execl"]) or
        
        // subprocess 模块
        (call.getFunction().(Attribute).getObject().(Name).getId() = "subprocess" and
         call.getFunction().(Attribute).getName() in ["call", "run", "Popen", "check_output"]) or
         
        // 直接调用
        call.getFunction().(NameNode).getId() in ["exec", "eval"]
      ) and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 命令转义或验证
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in [
        "shlex.quote", "pipes.quote", "shell_escape"
      ] and
      node.asCfgNode() = call
    )
    or
    // 使用参数列表而非字符串（相对安全）
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["call", "run", "Popen"] and
      call.getArg(0).asExpr() instanceof List and
      node.asCfgNode() = call.getArg(0)
    )
  }
}

module CommandInjectionFlow = TaintTracking::Global<CommandInjectionConfig>;

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "系统命令包含来自 $@ 的用户输入，可能导致命令注入", 
  source.getNode(), "用户输入"
```

### 路径遍历检测

```ql
/**
 * @name 路径遍历检测
 * @description 检测文件路径中的用户输入，可能导致路径遍历攻击
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/path-traversal-detection
 * @tags security
 *       external/cwe/cwe-022
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module PathTraversalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 用户提供的文件名/路径
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["args", "form", "json"] and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 文件操作函数
    exists(CallNode call |
      (
        // 内置文件函数
        call.getFunction().(NameNode).getId() in ["open", "file"] or
        
        // os.path 操作
        (call.getFunction().(Attribute).getObject().(Name).getId() = "os" and
         call.getFunction().(Attribute).getName() in ["remove", "unlink", "rmdir"]) or
         
        // shutil 操作
        (call.getFunction().(Attribute).getObject().(Name).getId() = "shutil" and
         call.getFunction().(Attribute).getName() in ["copy", "move", "rmtree"])
      ) and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 路径验证和清理
    exists(CallNode call |
      (
        // 路径规范化
        (call.getFunction().(Attribute).getObject().(Name).getId() = "os.path" and
         call.getFunction().(Attribute).getName() in ["abspath", "realpath", "normpath"]) or
         
        // 自定义验证函数
        call.getFunction().(NameNode).getId() in ["validate_path", "sanitize_filename"]
      ) and
      node.asCfgNode() = call
    )
  }
  
  predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 路径拼接操作
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "os.path" and
      call.getFunction().(Attribute).getName() = "join" and
      fromNode.asCfgNode() = call.getArg(_) and
      toNode.asCfgNode() = call
    )
  }
}

module PathTraversalFlow = TaintTracking::Global<PathTraversalConfig>;

from PathTraversalFlow::PathNode source, PathTraversalFlow::PathNode sink
where PathTraversalFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "文件操作使用了来自 $@ 的用户输入，可能导致路径遍历", 
  source.getNode(), "HTTP 请求"
```

## 调试数据流查询

### 使用部分流分析

当数据流查询没有找到预期结果时，可以使用部分流分析来调试：

```ql
/**
 * @name 数据流调试 - 部分流
 * @kind problem
 * @id py/dataflow-debug-partial
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
select node, source, dist, "部分流：距离源 " + dist + " 步"
order by dist desc
```

### 数据流调试技巧

```ql
/**
 * @name 数据流调试技巧
 */

import python
import semmle.python.dataflow.new.DataFlow

// 1. 检查源是否存在
from DataFlow::Node source
where 
  source.asCfgNode().(CallNode).getFunction().(NameNode).getId() = "input"
select source, "找到数据源"

// 2. 检查汇是否存在  
from DataFlow::Node sink
where
  exists(CallNode call |
    call.getFunction().(NameNode).getId() = "eval" and
    sink.asCfgNode() = call.getArg(0)
  )
select sink, "找到数据汇"

// 3. 检查局部流
from DataFlow::Node source, DataFlow::Node sink
where 
  source.asCfgNode().(CallNode).getFunction().(NameNode).getId() = "input" and
  exists(CallNode call |
    call.getFunction().(NameNode).getId() = "eval" and
    sink.asCfgNode() = call.getArg(0)
  ) and
  DataFlow::localFlow(source, sink)
select source, sink, "存在局部数据流"
```

## 性能优化

### 优化数据流查询性能

```ql
/**
 * @name 性能优化的数据流配置
 */

import python
import semmle.python.dataflow.new.TaintTracking

module OptimizedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 使用更具体的条件，减少候选源
    exists(CallNode call |
      call.getFunction().(Attribute).getObject().(Name).getId() = "request" and
      call.getFunction().(Attribute).getName() = "args" and
      call.getArg(0).asExpr().(StrConst).getText() = "user_input" and  // 具体参数名
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 限制在特定的危险函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "eval" and  // 只检查 eval
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  // 使用屏障减少搜索空间
  predicate isBarrier(DataFlow::Node node) {
    // 在函数边界设置屏障（如果不需要跨函数分析）
    node.asExpr() instanceof Parameter
  }
}
```

## 下一步

掌握了数据流分析后，建议继续学习：

1. **[安全查询实战](06-security-queries.md)** - 编写实用的安全检测查询
2. **[Python 场景](07-python.md)** - Python 特定的数据流模式
3. **[最佳实践](12-best-practices.md)** - 查询性能优化和调试技巧

---

**数据流分析掌握完毕！** 🌊 现在您可以追踪复杂的数据流路径了。
