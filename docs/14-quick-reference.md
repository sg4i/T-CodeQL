# 快速参考

> QL 语法速查、常用模式、API 参考和实用代码片段

## QL 语法速查表

### 基本结构

```ql
/**
 * 查询元数据
 * @name 查询名称
 * @description 查询描述  
 * @kind problem | path-problem | metric
 * @id 语言/标识符
 * @tags security | correctness
 */

import 模块名

from 类型 变量
where 条件表达式
select 结果表达式, "消息"
```

### 导入语句

```ql
// 基础导入
import python
import java
import javascript

// 特定模块导入
import semmle.python.dataflow.new.DataFlow
import semmle.code.java.security.SqlInjectionQuery
import semmle.javascript.security.dataflow.ReflectedXssQuery

// 别名导入
import DataFlow::PathGraph
```

### 类定义

```ql
class MyClass extends BaseClass {
  // 特征谓词（构造函数）
  MyClass() { 
    this.hasProperty() 
  }
  
  // 成员谓词
  predicate isValid() { 
    this.checkCondition() 
  }
  
  // 返回谓词
  string getName() { 
    result = this.getNameInternal() 
  }
  
  // 重写谓词
  override string toString() { 
    result = "MyClass: " + this.getName() 
  }
}
```

### 谓词定义

```ql
// 布尔谓词
predicate isPublic(Method m) {
  m.hasModifier("public")
}

// 返回谓词
string getMethodName(Method m) {
  result = m.getName()
}

// 多参数谓词
predicate calls(Function caller, Function callee) {
  exists(Call c | 
    c.getEnclosingFunction() = caller and
    c.getTarget() = callee
  )
}

// 缓存谓词
cached
predicate expensiveCheck(Node n) {
  // 昂贵的计算
}
```

### 逻辑运算符

```ql
// 基本逻辑
condition1 and condition2
condition1 or condition2
not condition
condition1 implies condition2

// 存在量词
exists(Type var | restrictions | formula)

// 全称量词
forall(Type var | restrictions | formula)

// 聚合
count(Type var | restrictions | var)
sum(Type var | restrictions | var.getValue())
max(Type var | restrictions | var.getValue())
min(Type var | restrictions | var.getValue())
any(Type var | restrictions | var)
```

### 条件表达式

```ql
// if-then-else
if condition then result1 else result2

// 多重条件
if condition1 then result1
else if condition2 then result2
else result3
```

### 类型检查和转换

```ql
// 类型检查
expr instanceof StringLiteral
expr.getType() instanceof IntType

// 类型转换（后缀）
expr.(StringLiteral).getValue()

// 类型转换（前缀）  
(StringLiteral)expr.getValue()
```

### 字符串操作

```ql
// 模式匹配
s.matches("*password*")
s.matches("temp%")

// 正则表达式
s.regexpMatch(".*\\b(password|secret)\\b.*")

// 字符串操作
s.length()
s.charAt(0)
s.substring(0, 5)
s.indexOf("sub")
s.toLowerCase()
s.toUpperCase()

// 字符串连接
result = "Found: " + s.getValue()
```

## 常用查询模式

### 1. 查找特定类型的节点

```ql
// 查找所有函数调用
from Call call
select call

// 查找特定名称的函数调用
from Call call
where call.getTarget().getName() = "dangerous_function"
select call

// 查找字符串字面量
from StringLiteral s
where s.getValue().matches("*secret*")
select s
```

### 2. 遍历语法树

```ql
// 查找函数的所有子节点
from Function f, AstNode child
where child = f.getAChild*()
select f, child

// 查找特定深度的子节点
from Function f, Expr e
where e = f.getAChild().getAChild()
select f, e
```

### 3. 控制流分析

```ql
// 查找可达的语句
from Stmt s
where s.getAFlowNode().isReachable()
select s

// 查找死代码
from Stmt s
where not s.getAFlowNode().isReachable()
select s, "Dead code"
```

### 4. 数据流模式

```ql
// 局部数据流
from DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink)
select source, sink

// 全局数据流配置
module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { ... }
  predicate isSink(DataFlow::Node sink) { ... }
}

module MyFlow = TaintTracking::Global<MyConfig>;

// 路径查询
from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink, source, sink, "Flow from $@ to here", source, "source"
```

## 语言特定 API 参考

### Python

#### 基本类型

```ql
// 模块
Module m
m.getName()
m.getFile()

// 函数
Function f
f.getName()
f.getAParameter()
f.getBody()
f.isMethod()

// 类
Class c
c.getName()
c.getAMethod()
c.getASuperclass()

// 变量
Variable v
v.getName()
v.getScope()
v.getAUse()

// 调用
CallNode call
call.getFunction()
call.getArg(0)
call.getAKeyword()

// 字符串
StrConst s
s.getText()
s.getValue()
```

#### 数据流

```ql
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

// 数据流节点
DataFlow::Node node
node.asExpr()
node.asCfgNode()

// 污点追踪配置
module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = API::moduleImport("flask").getMember("request").getMember("args").getACall()
  }
  
  predicate isSink(DataFlow::Node sink) {
    exists(CallNode call |
      call.getFunction().(NameNode).getId() = "eval" and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}
```

### Java

#### 基本类型

```ql
// 类
Class c
c.getName()
c.getQualifiedName()
c.getAMethod()
c.getASupertype()

// 方法
Method m
m.getName()
m.getDeclaringType()
m.getAParameter()
m.getBody()

// 调用
MethodCall call
call.getMethod()
call.getArgument(0)
call.getQualifier()

// 字段
Field f
f.getName()
f.getType()
f.getDeclaringType()
```

#### 数据流

```ql
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

// 数据流配置
class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "MyConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source.asParameter().getCallable().hasName("doGet")
  }
  
  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().hasName("execute") and
      sink.asExpr() = call.getArgument(0)
    )
  }
}
```

### JavaScript

#### 基本类型

```ql
// 函数
Function f
f.getName()
f.getAParameter()
f.getBody()

// 调用
CallExpr call
call.getCallee()
call.getArgument(0)
call.getNumArgument()

// 属性访问
PropAccess prop
prop.getBase()
prop.getPropertyName()

// 变量
Variable v
v.getName()
v.getADeclaration()
v.getAnAccess()
```

#### 数据流

```ql
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking

// 数据流配置
class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "MyConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("req").getAPropertyRead("query")
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink = DataFlow::globalVarRef("eval").getACall().getArgument(0)
  }
}
```

## 查询元数据参考

### 必需字段

```ql
/**
 * @name 查询的简短名称
 * @description 查询的详细描述
 * @kind problem | path-problem | metric | table
 * @id 语言前缀/唯一标识符
 */
```

### 可选字段

```ql
/**
 * @problem.severity error | warning | recommendation
 * @security-severity 0.0-10.0
 * @precision low | medium | high | very-high
 * @tags security | correctness | maintainability
 *       external/cwe/cwe-XXX
 *       external/owasp/owasp-XXX
 */
```

### 语言前缀

| 语言 | 前缀 | 示例 |
|------|------|------|
| Python | `py` | `py/sql-injection` |
| Java | `java` | `java/sql-injection` |
| JavaScript | `js` | `js/reflected-xss` |
| Go | `go` | `go/sql-injection` |
| C/C++ | `cpp` | `cpp/buffer-overflow` |
| C# | `cs` | `cs/sql-injection` |
| Ruby | `rb` | `rb/sql-injection` |
| Swift | `swift` | `swift/weak-crypto` |

## 常用代码片段

### 1. 查找 TODO 注释

```ql
/**
 * @name TODO comments
 * @kind problem
 * @id lang/todo-comment
 */

import python

from Comment c
where c.getText().regexpMatch("(?si).*\\bTODO\\b.*")
select c, "TODO comment found"
```

### 2. 查找空的异常处理

```ql
/**
 * @name Empty except block
 * @kind problem
 * @id py/empty-except
 */

import python

from ExceptStmt except
where 
  except.getBody().(StmtList).getNumChild() = 0 or
  except.getBody().(StmtList).getChild(0) instanceof Pass
select except, "Empty except block"
```

### 3. 查找硬编码凭证

```ql
/**
 * @name Hard-coded credentials
 * @kind problem
 * @id py/hardcoded-credentials
 */

import python

from AssignStmt assign, StrConst s
where
  assign.getATarget().(Name).getId().regexpMatch("(?i).*(password|secret|key|token).*") and
  assign.getValue() = s and
  s.getText().length() > 8
select assign, "Possible hard-coded credential"
```

### 4. 查找未使用的导入

```ql
/**
 * @name Unused import
 * @kind problem
 * @id py/unused-import
 */

import python

from Import imp, ImportMember im
where
  im = imp.getAName() and
  not exists(Name use | 
    use.getId() = im.getName() and
    use.getScope() = im.getScope() and
    use != im
  )
select im, "Unused import: " + im.getName()
```

### 5. 查找复杂函数

```ql
/**
 * @name Complex function
 * @kind problem
 * @id py/complex-function
 */

import python

from Function f
where
  count(Stmt s | s.getScope() = f) > 50
select f, "Function has " + count(Stmt s | s.getScope() = f) + " statements"
```

## 性能优化技巧

### 1. 使用索引友好的条件

```ql
// 好：使用索引
where f.getName() = "specific_name"

// 不好：无法使用索引
where f.getName().matches("%name%")
```

### 2. 提前过滤

```ql
// 好：先用强限制条件
from Method m
where 
  m.getName() = "execute" and
  m.getDeclaringType().hasQualifiedName("java.sql", "Statement")
select m

// 不好：后用强限制条件
from Method m
where 
  m.getDeclaringType().hasQualifiedName("java.sql", "Statement") and
  m.getName() = "execute"
select m
```

### 3. 避免不必要的连接

```ql
// 好：直接关系
from Call c, Function f
where c.getTarget() = f
select c, f

// 不好：间接关系
from Call c, Function f
where exists(string name | c.getTarget().getName() = name and f.getName() = name)
select c, f
```

### 4. 使用缓存

```ql
cached
predicate isSecuritySensitive(Function f) {
  f.getName() in ["execute", "eval", "system"] or
  f.getDeclaringType().getQualifiedName().matches("%.security.%")
}
```

## 调试命令

### CodeQL CLI 调试

```bash
# 详细输出
codeql query run query.ql --database=db --verbose

# 调试模式
codeql query run query.ql --database=db --debug

# 查看查询计划
codeql query run query.ql --database=db --tuple-counting

# 性能分析
codeql query run query.ql --database=db --evaluator-log=log.txt
```

### VS Code 调试

- **Quick Evaluation**: 选中代码 → 右键 → "CodeQL: Quick Evaluation"
- **View AST**: 右键 → "CodeQL: View AST"
- **Query History**: 查看之前运行的查询
- **Database Schema**: 浏览数据库结构

## 常见错误和解决方案

### 1. "No results" 但应该有结果

```ql
// 调试：检查数据是否存在
from Function f
select f, f.getName()

// 调试：检查条件是否过严
from Function f
where f.getName().matches("%target%")  // 放宽条件
select f
```

### 2. 查询超时

```ql
// 添加更强的限制条件
from LargeClass obj
where 
  obj.hasSpecificProperty() and  // 强限制
  obj.meetsComplexCondition()    // 复杂条件
select obj
```

### 3. 内存不足

```bash
# 增加内存限制
codeql query run query.ql --database=db --ram=8192
```

### 4. 类型错误

```ql
// 检查类型
from Expr e
select e, e.getType()

// 安全转换
from Expr e
where e instanceof StringLiteral
select e.(StringLiteral).getValue()
```

## 有用的资源

### 官方文档
- **QL 语言参考**: https://codeql.github.com/docs/ql-language-reference/
- **CodeQL 标准库**: https://codeql.github.com/codeql-standard-libraries/
- **查询帮助**: https://codeql.github.com/codeql-query-help/

### 示例查询
- **仓库示例**: `<language>/ql/examples/snippets/`
- **安全查询**: `<language>/ql/src/Security/`
- **质量查询**: `<language>/ql/src/`

### 社区资源
- **GitHub Discussions**: https://github.com/github/codeql/discussions
- **Security Lab**: https://securitylab.github.com/
- **CTF 挑战**: https://securitylab.github.com/ctf/

---

**快速参考完成！** 📖 将此页面加入书签，随时查阅语法和 API。
