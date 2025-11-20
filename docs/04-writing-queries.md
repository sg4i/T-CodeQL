# 查询编写

> 从简单查询到复杂分析，掌握 CodeQL 查询编写的核心技能

## 第一个查询

### Hello World 查询

让我们从最简单的查询开始：

```ql
/**
 * @name Hello World
 * @description 我的第一个 CodeQL 查询
 * @kind problem
 * @id my/hello-world
 */

import python

from Function f
where f.getName() = "main"
select f, "找到了 main 函数！"
```

**查询解析：**
- `import python`：导入 Python 语言库
- `from Function f`：声明变量 f，类型为 Function
- `where f.getName() = "main"`：筛选条件
- `select f, "message"`：输出结果

### 运行查询

```bash
# 保存为 hello.ql，然后运行
codeql query run hello.ql --database=python-db
```

## 查询类型详解

### 1. 问题查询 (@kind problem)

用于标记代码中的问题位置。

```ql
/**
 * @name 未使用的变量
 * @kind problem
 * @problem.severity warning
 * @id py/unused-variable
 */

import python

from Variable v
where 
  not exists(Name use | use.uses(v)) and
  not v.getName().matches("_%")  // 排除 _var 形式的变量
select v, "变量 '" + v.getName() + "' 未被使用"
```

### 2. 路径查询 (@kind path-problem)

显示数据流路径，常用于安全分析。

```ql
/**
 * @name 简单数据流
 * @kind path-problem
 * @id py/simple-dataflow
 */

import python
import semmle.python.dataflow.new.DataFlow
import DataFlow::PathGraph

module SimpleFlow implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 定义数据源：用户输入
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "input" |
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 定义数据汇：print 函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "print" |
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module Flow = DataFlow::Global<SimpleFlow>;

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "数据从 $@ 流向这里", source.getNode(), "用户输入"
```

### 3. 指标查询 (@kind metric)

用于统计和度量代码。

```ql
/**
 * @name 函数复杂度
 * @kind metric
 * @id py/function-complexity
 */

import python

from Function f, int complexity
where 
  complexity = count(Stmt s | s.getScope() = f) and
  complexity > 0
select f, complexity as "语句数量"
```

## 查询编写进阶

### 使用类扩展功能

```ql
/**
 * @name 危险函数调用
 * @kind problem
 * @id py/dangerous-function-call
 */

import python

class DangerousFunction extends Function {
  DangerousFunction() {
    this.getName() in ["eval", "exec", "compile", "__import__"]
  }
  
  string getDangerLevel() {
    if this.getName() in ["eval", "exec"] 
    then result = "高危"
    else result = "中危"
  }
}

from CallNode call, DangerousFunction dangerous
where call.getFunction().pointsTo().getClass() = dangerous
select call, "调用了" + dangerous.getDangerLevel() + "函数: " + dangerous.getName()
```

### 复杂条件组合

```ql
/**
 * @name 复杂的安全检查
 * @kind problem
 * @id py/complex-security-check
 */

import python

from Function f, Parameter p
where
  // 函数名包含敏感词
  f.getName().regexpMatch("(?i).*(auth|login|password).*") and
  
  // 有参数
  p = f.getAParameter() and
  
  // 参数名也包含敏感词
  p.getName().regexpMatch("(?i).*(pass|pwd|secret|token).*") and
  
  // 函数体中没有加密或哈希操作
  not exists(CallNode call |
    call.getScope() = f and
    call.getFunction().(NameNode).getId().regexpMatch("(?i).*(hash|encrypt|bcrypt|pbkdf2).*")
  )
select f, "敏感函数 '" + f.getName() + "' 可能缺少密码加密处理"
```

### 使用辅助谓词

```ql
/**
 * @name 模块化查询示例
 * @kind problem
 * @id py/modular-query
 */

import python

// 辅助谓词：检查是否为 Web 框架函数
predicate isWebFrameworkFunction(Function f) {
  exists(Decorator d |
    d = f.getADecorator() and
    d.getName() in ["route", "app.route", "get", "post"]
  )
}

// 辅助谓词：检查是否有输入验证
predicate hasInputValidation(Function f) {
  exists(CallNode call |
    call.getScope() = f and
    call.getFunction().(NameNode).getId() in ["validate", "sanitize", "escape"]
  )
}

from Function f
where 
  isWebFrameworkFunction(f) and
  not hasInputValidation(f)
select f, "Web 接口函数缺少输入验证"
```

## 数据流查询模式

### 基础数据流配置

```ql
/**
 * @name SQL 注入检测
 * @kind path-problem
 * @id py/sql-injection-custom
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // HTTP 请求参数
    exists(Attribute attr |
      attr.getObject().(Name).getId() = "request" and
      attr.getName() in ["args", "form", "json"] and
      source.asExpr() = attr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // SQL 执行函数
    exists(CallNode call |
      call.getFunction().(Attribute).getName() in ["execute", "executemany"] and
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  predicate isBarrier(DataFlow::Node node) {
    // 参数化查询不是漏洞
    exists(CallNode call |
      call.getFunction().(Attribute).getName() = "execute" and
      call.getNumArg() >= 2 and  // 有参数
      node.asCfgNode() = call.getArg(0)
    )
  }
}

module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "SQL 查询依赖于 $@", source.getNode(), "用户输入"
```

### 高级数据流：自定义传播步骤

```ql
/**
 * @name 带自定义传播的数据流
 * @kind path-problem
 * @id py/custom-taint-step
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module CustomTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr().(CallNode).getFunction().(NameNode).getId() = "get_user_input"
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "dangerous_operation" |
      sink.asCfgNode() = call.getArg(0)
    )
  }
  
  // 自定义污点传播步骤
  predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 通过自定义处理函数的污点传播
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "process_data" and
      fromNode.asCfgNode() = call.getArg(0) and
      toNode.asCfgNode() = call
    )
    or
    // 通过字符串格式化的污点传播
    exists(BinOp binop |
      binop.getOp() instanceof Mod and  // % 格式化
      fromNode.asExpr() = binop.getRight() and
      toNode.asExpr() = binop
    )
  }
}

module CustomFlow = TaintTracking::Global<CustomTaintConfig>;

from CustomFlow::PathNode source, CustomFlow::PathNode sink
where CustomFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "危险操作依赖于 $@", source.getNode(), "用户输入"
```

## 实用查询示例

### 1. 查找硬编码密钥

```ql
/**
 * @name 硬编码密钥检测
 * @kind problem
 * @problem.severity error
 * @id py/hardcoded-key
 */

import python

from AssignStmt assign, StrConst secret
where
  // 变量名包含敏感词
  exists(Name target |
    target = assign.getATarget() and
    target.getId().regexpMatch("(?i).*(key|secret|password|token|api_key).*")
  ) and
  
  // 赋值为字符串常量
  secret = assign.getValue() and
  
  // 字符串长度合理（可能是密钥）
  secret.getText().length() > 10 and
  
  // 不是明显的占位符
  not secret.getText().regexpMatch("(?i).*(example|test|dummy|placeholder|your_key_here).*")

select assign, "发现硬编码密钥: " + secret.getText().prefix(20) + "..."
```

### 2. 检测不安全的随机数生成

```ql
/**
 * @name 不安全的随机数生成
 * @kind problem
 * @problem.severity warning
 * @id py/insecure-random
 */

import python

from CallNode call, string module, string function
where
  // 使用了不安全的随机数函数
  call.getFunction().(Attribute).getObject().(Name).getId() = module and
  call.getFunction().(Attribute).getName() = function and
  (
    (module = "random" and function in ["random", "randint", "choice"]) or
    (module = "time" and function = "time")
  ) and
  
  // 在安全相关的上下文中
  exists(Function f |
    call.getScope() = f and
    f.getName().regexpMatch("(?i).*(auth|login|session|token|key|crypto).*")
  )

select call, "在安全上下文中使用了不安全的随机数生成函数: " + module + "." + function
```

### 3. 查找缺少异常处理的文件操作

```ql
/**
 * @name 缺少异常处理的文件操作
 * @kind problem
 * @problem.severity recommendation
 * @id py/file-operation-without-exception-handling
 */

import python

from CallNode fileOp
where
  // 文件操作函数
  fileOp.getFunction().(NameNode).getId() in ["open", "read", "write"] and
  
  // 不在 try 语句中
  not exists(TryStmt try |
    try.getBody().contains(fileOp.getNode())
  ) and
  
  // 不在已知安全的上下文中（如 with 语句）
  not exists(With with |
    with.getBody().contains(fileOp.getNode())
  )

select fileOp, "文件操作缺少异常处理"
```

### 4. 检测潜在的代码注入

```ql
/**
 * @name 代码注入检测
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @id py/code-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

module CodeInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 用户输入源
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["input", "raw_input"] or
      (
        call.getFunction().(Attribute).getObject().(Name).getId() = "request" and
        call.getFunction().(Attribute).getName() in ["args", "form", "json"]
      )
    |
      source.asCfgNode() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 代码执行函数
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["eval", "exec", "compile"] |
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module CodeInjectionFlow = TaintTracking::Global<CodeInjectionConfig>;

from CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink
where CodeInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "代码执行依赖于 $@，可能导致代码注入", source.getNode(), "用户输入"
```

## 查询优化技巧

### 1. 使用缓存提升性能

```ql
/**
 * @name 性能优化示例
 */

import python

// 缓存昂贵的计算
cached
predicate isComplexFunction(Function f) {
  count(Stmt s | s.getScope() = f) > 50 or
  count(CallNode c | c.getScope() = f) > 20
}

// 缓存常用的类型检查
cached
predicate isWebFunction(Function f) {
  exists(Decorator d |
    d = f.getADecorator() and
    d.getName().regexpMatch(".*route.*")
  )
}

from Function f
where 
  isWebFunction(f) and
  isComplexFunction(f)
select f, "复杂的 Web 函数，考虑重构"
```

### 2. 提前过滤减少计算量

```ql
/**
 * @name 过滤优化示例
 */

import python

from CallNode call, Function target
where
  // 先用最强的限制条件
  target.getName() = "execute" and
  call.getFunction().pointsTo().getClass() = target and
  
  // 再检查其他条件
  target.getScope().(Class).getName() = "Cursor"

select call, "数据库执行调用"
```

### 3. 避免笛卡尔积

```ql
/**
 * @name 避免笛卡尔积
 */

import python

// 不好的做法：可能产生大量无关组合
// from Function f, Variable v
// where someCondition(f, v)

// 好的做法：通过关系连接
from Function f, Variable v
where 
  v.getScope() = f and  // 建立明确关系
  someCondition(f, v)
select f, v
```

## 测试查询

### 创建测试用例

创建测试目录结构：
```
test/
├── MyQuery/
│   ├── test.py              # 测试代码
│   ├── MyQuery.qlref        # 查询引用
│   └── MyQuery.expected     # 期望结果
```

**test.py:**
```python
def bad_function():
    user_input = input("Enter data: ")
    eval(user_input)  # 应该被检测到

def good_function():
    user_input = input("Enter data: ")
    print(f"You entered: {user_input}")  # 不应该被检测到
```

**MyQuery.qlref:**
```
queries/MyQuery.ql
```

**MyQuery.expected:**
```
| test.py:3:5:3:20 | 代码执行依赖于用户输入，可能导致代码注入 |
```

### 运行测试

```bash
codeql test run test/MyQuery/ --database=test-db
```

## 查询文档

### 编写查询帮助文档

创建 `.qhelp` 文件：

```xml
<!DOCTYPE qhelp PUBLIC "-//Semmle//qhelp//EN" "qhelp.dtd">
<qhelp>
<overview>
<p>
此查询检测可能的代码注入漏洞。当用户输入直接传递给代码执行函数（如 eval、exec）时，
攻击者可能能够执行任意代码。
</p>
</overview>

<recommendation>
<p>
避免使用 eval() 和 exec() 函数处理用户输入。如果必须动态执行代码，请：
</p>
<ul>
<li>严格验证和清理输入</li>
<li>使用白名单限制可执行的操作</li>
<li>考虑使用更安全的替代方案</li>
</ul>
</recommendation>

<example>
<p>以下代码存在代码注入风险：</p>
<sample src="bad.py" />

<p>更安全的做法：</p>
<sample src="good.py" />
</example>

<references>
<li>CWE-94: <a href="https://cwe.mitre.org/data/definitions/94.html">Improper Control of Generation of Code</a></li>
<li>OWASP: <a href="https://owasp.org/www-community/attacks/Code_Injection">Code Injection</a></li>
</references>
</qhelp>
```

## 下一步

掌握了查询编写基础后，建议继续学习：

1. **[数据流分析](05-dataflow-analysis.md)** - 深入理解数据流和污点追踪
2. **[安全查询实战](06-security-queries.md)** - 编写实用的安全检测查询
3. **[Python 场景](07-python.md)** - Python 特定的查询技巧

---

**查询编写技能 GET！** 🎯 现在您可以编写自己的 CodeQL 查询了。
