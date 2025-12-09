# Python 场景应用

> Python 代码分析完整指南：从 Web 应用到数据科学，掌握 Python 特定的 CodeQL 查询技巧

- codeql-library-for-python: [https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-python/](https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-python/)
- Using API graphs in Python: [https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/](https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/)

## Python 语言支持概览

### 目录结构

```
python/
├── ql/
│   ├── lib/                    # Python 核心库
│   │   ├── semmle/python/     # 标准库实现
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
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
| **Web 框架** | Flask, Django, FastAPI, Tornado | `semmle/python/frameworks/` |
| **数据库** | SQLAlchemy, Django ORM, PyMongo | `semmle/python/frameworks/` |
| **HTTP 客户端** | requests, urllib, httpx | `semmle/python/frameworks/` |
| **模板引擎** | Jinja2, Django Templates | `semmle/python/frameworks/` |
| **序列化** | pickle, json, yaml | `semmle/python/frameworks/` |


## CodeQL Python from 语句速查表

### 基础 AST 节点

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from Module m` | 模块分析 | `getName()`, `getFile()`, `getAStmt()` | 查找所有 Python 模块 |
| `from Function f` | 函数定义 | `getName()`, `getAParameter()`, `isMethod()` | 分析函数结构和参数 |
| `from Class c` | 类定义 | `getName()`, `getAMethod()`, `getASuperclass()` | 类继承关系分析 |
| `from Scope s` | 作用域 | `getEnclosingScope()`, `getAStmt()` | 变量作用域分析 |

### 表达式类

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from Expr e` | 表达式基类 | `getScope()`, `getASubExpression()` | 通用表达式分析 |
| `from Call call` | 函数调用 | `getFunc()`, `getArg(n)`, `getAKeyword()` | 函数调用分析 |
| `from Attribute attr` | 属性访问 | `getObject()`, `getName()` | `obj.attr` 模式 |
| `from Name name` | 变量名 | `getId()`, `getVariable()`, `uses()` | 变量引用分析 |
| `from StrConst s` | 字符串常量 | `getText()`, `getValue()` | 字符串字面量 |
| `from Num n` | 数字常量 | `getN()`, `getValue()` | 数字字面量 |
| `from List lst` | 列表字面量 | `getAnElt()`, `getElt(n)` | `[1, 2, 3]` 模式 |
| `from Dict d` | 字典字面量 | `getAKey()`, `getAValue()` | `{k: v}` 模式 |
| `from Tuple t` | 元组字面量 | `getAnElt()`, `getElt(n)` | `(1, 2, 3)` 模式 |
| `from BinOp binop` | 二元运算 | `getLeft()`, `getRight()`, `getOp()` | `a + b` 模式 |
| `from UnaryOp unop` | 一元运算 | `getOperand()`, `getOp()` | `-a`, `not a` 模式 |
| `from Compare cmp` | 比较运算 | `getLeft()`, `getAComparator()` | `a == b` 模式 |
| `from Subscript sub` | 下标访问 | `getObject()`, `getIndex()` | `obj[key]` 模式 |
| `from Lambda lambda` | Lambda 表达式 | `getArgs()`, `getBody()` | `lambda x: x + 1` |

### 语句类

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from Stmt s` | 语句基类 | `getScope()`, `getASubExpression()` | 通用语句分析 |
| `from AssignStmt assign` | 赋值语句 | `getATarget()`, `getValue()` | `a = b` 模式 |
| `from AugAssign augassign` | 增强赋值 | `getTarget()`, `getValue()`, `getOp()` | `a += b` 模式 |
| `from If ifstmt` | 条件语句 | `getTest()`, `getBody()`, `getOrelse()` | `if-else` 结构 |
| `from For forstmt` | for 循环 | `getTarget()`, `getIter()`, `getBody()` | `for x in y` 模式 |
| `from While whilestmt` | while 循环 | `getTest()`, `getBody()` | `while` 循环 |
| `from TryStmt trystmt` | 异常处理 | `getBody()`, `getAHandler()` | `try-except` 块 |
| `from ExceptStmt except` | except 子句 | `getType()`, `getName()`, `getBody()` | 异常捕获 |
| `from With withstmt` | with 语句 | `getContextExpr()`, `getOptionalVars()` | 上下文管理器 |
| `from Return ret` | return 语句 | `getValue()` | 函数返回 |
| `from Yield yld` | yield 表达式 | `getValue()` | 生成器 |
| `from Raise raise` | raise 语句 | `getExc()`, `getCause()` | 抛出异常 |

### 控制流和数据流

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from ControlFlowNode node` | 控制流节点 | `getNode()`, `getASuccessor()` | 控制流分析 |
| `from CallNode call` | 调用节点 | `getFunction()`, `getArg(n)` | CFG 中的调用 |
| `from AttrNode attr` | 属性节点 | `getObject()`, `getName()` | CFG 中的属性访问 |
| `from NameNode name` | 名称节点 | `getId()`, `getVariable()` | CFG 中的变量 |
| `from DataFlow::Node node` | 数据流节点 | `asCfgNode()`, `getLocation()` | 数据流分析 |
| `from DataFlow::ParameterNode param` | 参数节点 | `getParameter()`, `getCallable()` | 函数参数流 |
| `from DataFlow::CallCfgNode call` | 调用数据流 | `getFunction()`, `getArg(n)` | 调用的数据流 |

### 变量和导入

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from Variable v` | 变量 | `getId()`, `getScope()`, `getAUse()` | 变量分析 |
| `from GlobalVariable gv` | 全局变量 | `getId()`, `getScope()` | 全局变量 |
| `from LocalVariable lv` | 局部变量 | `getId()`, `getScope()` | 局部变量 |
| `from Parameter p` | 参数变量 | `getFunction()`, `getIndex()` | 函数参数 |
| `from Import imp` | import 语句 | `getAName()`, `getAnAlias()` | `import module` |
| `from ImportMember im` | 导入成员 | `getName()`, `getModule()` | `from module import name` |
| `from ImportStar impstar` | 星号导入 | `getModule()` | `from module import *` |
| `from Alias alias` | 导入别名 | `getValue()`, `getAsname()` | `import x as y` |

### 特殊构造

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from ListComp lc` | 列表推导 | `getElt()`, `getAGenerator()` | `[x for x in lst]` |
| `from DictComp dc` | 字典推导 | `getKey()`, `getValue()` | `{k: v for k, v in items}` |
| `from SetComp sc` | 集合推导 | `getElt()`, `getAGenerator()` | `{x for x in lst}` |
| `from GeneratorExp ge` | 生成器表达式 | `getElt()`, `getAGenerator()` | `(x for x in lst)` |
| `from Comprehension comp` | 推导生成器 | `getTarget()`, `getIter()` | 推导式的 for 部分 |
| `from Decorator d` | 装饰器 | `getName()`, `getDecorated()` | `@decorator` |
| `from Pattern pattern` | 模式匹配 | `getCase()` | Python 3.10+ match |
| `from Match match` | match 语句 | `getSubject()`, `getACase()` | `match` 语句 |
| `from Case case` | case 语句 | `getPattern()`, `getGuard()` | `case` 分支 |

### 类型和对象

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from Object obj` | 对象 | `toString()`, `getOrigin()` | 运行时对象 |
| `from ClassObject cls` | 类对象 | `getName()`, `getASuperclass()` | 类的运行时表示 |
| `from FunctionObject func` | 函数对象 | `getName()`, `getFunction()` | 函数的运行时表示 |
| `from ModuleObject mod` | 模块对象 | `getName()` | 模块的运行时表示 |

### Web 框架

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from FlaskRoute route` | Flask 路由 | `getFunction()`, `getUrl()` | Flask 路由分析 |
| `from FlaskRequestData request` | Flask 请求 | `getKind()` | Flask 请求数据 |
| `from DjangoView view` | Django 视图 | `getFunction()`, `getHttpMethod()` | Django 视图分析 |
| `from DjangoRequestData request` | Django 请求 | `getKind()` | Django 请求数据 |

### 其他工具类

| from 语句 | 用途 | 核心方法 | 示例 |
|-----------|------|----------|------|
| `from Comment comment` | 注释 | `getText()`, `getContents()` | 代码注释 |
| `from File f` | 文件 | `getAbsolutePath()`, `getBaseName()` | 源文件信息 |
| `from Location loc` | 位置 | `getFile()`, `getStartLine()` | 代码位置 |

### 快速示例

```ql
// 查找所有函数调用
from Call call
select call.getFunc(), call.getLocation()

// 查找 SQL 相关的字符串
from StrConst s
where s.getText().toLowerCase().matches("%select%")
select s, s.getLocation()

// 查找所有类方法
from Function f
where f.isMethod()
select f.getName(), f.getEnclosingScope().(Class).getName()

// 数据流分析示例
import semmle.python.dataflow.new.DataFlow
from DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink)
select source, sink
```

## CodeQL Python 支持的所有 from 语句

### 1. 基础 AST 节点类

#### 模块和作用域
```ql
import python

// 模块 - Python 文件的顶级容器
from Module m
select m.getName(), m.getFile(), m.getPackageName()

// 作用域 - 变量可见性范围
from Scope s
select s.getName(), s.getEnclosingScope(), s.getAStmt()

// 函数 - 函数定义
from Function f
select f.getName(), f.getQualifiedName(), f.getAParameter()

// 类 - 类定义
from Class c
select c.getName(), c.getAMethod(), c.getASuperclass()
```

**常用方法：**
- `Module`: `getName()`, `getFile()`, `getPackageName()`, `getAStmt()`, `isPackage()`
- `Scope`: `getEnclosingScope()`, `getAStmt()`, `getBody()`, `getDocstring()`
- `Function`: `getName()`, `getQualifiedName()`, `getAParameter()`, `isMethod()`, `isGenerator()`
- `Class`: `getName()`, `getAMethod()`, `getASuperclass()`, `getADecorator()`

#### 表达式类
```ql
import python

// 表达式基类
from Expr e
select e, e.getScope(), e.getLocation()

// 属性访问 - obj.attr
from Attribute attr
select attr.getObject(), attr.getName(), attr.getCtx()

// 函数调用 - func(args)
from Call call
select call.getFunc(), call.getArg(0), call.getAKeyword()

// 下标访问 - obj[index]
from Subscript sub
select sub.getObject(), sub.getIndex(), sub.getCtx()

// 名称引用 - 变量名
from Name name
select name.getId(), name.getCtx(), name.getVariable()

// 字符串常量
from StrConst s
select s.getText(), s.getValue(), s.getLocation()

// 数字常量
from Num n
select n.getN(), n.getValue(), n.getLocation()

// 列表字面量 - [1, 2, 3]
from List lst
select lst.getAnElt(), lst.getElt(0), lst.getCtx()

// 字典字面量 - {key: value}
from Dict d
select d.getAKey(), d.getAValue(), d.getAnItem()

// 元组字面量 - (1, 2, 3)
from Tuple t
select t.getAnElt(), t.getElt(0), t.getCtx()

// 二元运算 - a + b
from BinOp binop
select binop.getLeft(), binop.getRight(), binop.getOp()

// 一元运算 - -a, not a
from UnaryOp unop
select unop.getOperand(), unop.getOp()

// 比较运算 - a == b, a < b
from Compare cmp
select cmp.getLeft(), cmp.getAComparator(), cmp.getAnOp()

// 布尔运算 - a and b, a or b
from BoolOp boolop
select boolop.getAValue(), boolop.getOp()

// 条件表达式 - a if test else b
from IfExp ifexp
select ifexp.getTest(), ifexp.getBody(), ifexp.getOrelse()

// Lambda 表达式 - lambda x: x + 1
from Lambda lambda
select lambda.getArgs(), lambda.getBody()
```

**常用方法：**
- `Expr`: `getScope()`, `getLocation()`, `getASubExpression()`, `hasSideEffects()`
- `Attribute`: `getObject()`, `getName()`, `getCtx()`
- `Call`: `getFunc()`, `getArg(n)`, `getAKeyword()`, `getNumArg()`
- `Name`: `getId()`, `getCtx()`, `getVariable()`, `uses()`, `defines()`
- `StrConst`: `getText()`, `getValue()`, `getLocation()`

#### 语句类
```ql
import python

// 语句基类
from Stmt s
select s, s.getScope(), s.getLocation()

// 赋值语句 - a = b
from AssignStmt assign
select assign.getATarget(), assign.getValue()

// 增强赋值 - a += b
from AugAssign augassign
select augassign.getTarget(), augassign.getValue(), augassign.getOp()

// 表达式语句
from ExprStmt exprstmt
select exprstmt.getValue()

// if 语句
from If ifstmt
select ifstmt.getTest(), ifstmt.getBody(), ifstmt.getOrelse()

// for 循环
from For forstmt
select forstmt.getTarget(), forstmt.getIter(), forstmt.getBody()

// while 循环
from While whilestmt
select whilestmt.getTest(), whilestmt.getBody(), whilestmt.getOrelse()

// try 语句
from TryStmt trystmt
select trystmt.getBody(), trystmt.getAHandler(), trystmt.getFinalbody()

// except 子句
from ExceptStmt except
select except.getType(), except.getName(), except.getBody()

// with 语句
from With withstmt
select withstmt.getContextExpr(), withstmt.getOptionalVars(), withstmt.getBody()

// return 语句
from Return ret
select ret.getValue()

// yield 表达式
from Yield yld
select yld.getValue()

// raise 语句
from Raise raise
select raise.getExc(), raise.getCause()

// import 语句
from Import imp
select imp.getAName(), imp.getAnAlias()

// from import 语句
from ImportStar impstar
select impstar.getModule()

// 断言语句
from Assert assert
select assert.getTest(), assert.getMsg()

// 删除语句
from Delete del
select del.getATarget()

// pass 语句
from Pass pass
select pass

// break 语句
from Break brk
select brk

// continue 语句
from Continue cont
select cont
```

**常用方法：**
- `Stmt`: `getScope()`, `getLocation()`, `getASubExpression()`, `getASubStatement()`
- `AssignStmt`: `getATarget()`, `getValue()`, `defines()`
- `If`: `getTest()`, `getBody()`, `getOrelse()`, `getAStmt()`
- `For`: `getTarget()`, `getIter()`, `getBody()`, `getOrelse()`
- `TryStmt`: `getBody()`, `getAHandler()`, `getFinalbody()`, `getOrelse()`

### 2. 控制流和数据流

#### 控制流节点
```ql
import python

// 控制流节点
from ControlFlowNode node
select node, node.getNode(), node.getASuccessor()

// 基本块
from BasicBlock bb
select bb, bb.getNode(0), bb.getLastNode()

// 调用节点
from CallNode call
select call.getFunction(), call.getArg(0), call.getAKeyword()

// 属性节点
from AttrNode attr
select attr.getObject(), attr.getName()

// 名称节点
from NameNode name
select name.getId(), name.getVariable()
```

**常用方法：**
- `ControlFlowNode`: `getNode()`, `getASuccessor()`, `getAPredecessor()`, `dominates()`
- `CallNode`: `getFunction()`, `getArg(n)`, `getAKeyword()`, `getNumArg()`
- `AttrNode`: `getObject()`, `getName()`

#### 数据流节点
```ql
import python
import semmle.python.dataflow.new.DataFlow

// 数据流节点
from DataFlow::Node node
select node, node.getLocation(), node.toString()

// 参数节点
from DataFlow::ParameterNode param
select param, param.getParameter()

// 调用节点
from DataFlow::CallCfgNode call
select call, call.getFunction()

// 后置更新节点
from DataFlow::PostUpdateNode post
select post, post.getPreUpdateNode()
```

**常用方法：**
- `DataFlow::Node`: `getLocation()`, `toString()`, `asCfgNode()`
- `DataFlow::ParameterNode`: `getParameter()`, `getCallable()`
- `DataFlow::CallCfgNode`: `getFunction()`, `getArg(n)`, `getAKeyword()`

### 3. 变量和导入

#### 变量类
```ql
import python

// 变量
from Variable v
select v.getId(), v.getScope(), v.getAUse()

// 全局变量
from GlobalVariable gv
select gv.getId(), gv.getScope()

// 局部变量
from LocalVariable lv
select lv.getId(), lv.getScope()

// 参数变量
from Parameter p
select p.getId(), p.getFunction(), p.getIndex()
```

**常用方法：**
- `Variable`: `getId()`, `getScope()`, `getAUse()`, `getALoad()`, `getAStore()`
- `Parameter`: `getFunction()`, `getIndex()`, `isSelf()`, `isVararg()`

#### 导入相关
```ql
import python

// 导入表达式
from ImportExpr imp
select imp.getName(), imp.getLevel()

// 导入成员
from ImportMember im
select im.getName(), im.getModule()

// 别名
from Alias alias
select alias.getValue(), alias.getAsname()
```

**常用方法：**
- `ImportExpr`: `getName()`, `getLevel()`, `getEnclosingModule()`
- `ImportMember`: `getName()`, `getModule()`, `getImport()`

### 4. 特殊构造

#### 推导式和生成器
```ql
import python

// 列表推导 - [x for x in lst]
from ListComp lc
select lc.getElt(), lc.getAGenerator()

// 字典推导 - {k: v for k, v in items}
from DictComp dc
select dc.getKey(), dc.getValue(), dc.getAGenerator()

// 集合推导 - {x for x in lst}
from SetComp sc
select sc.getElt(), sc.getAGenerator()

// 生成器表达式 - (x for x in lst)
from GeneratorExp ge
select ge.getElt(), ge.getAGenerator()

// 推导生成器
from Comprehension comp
select comp.getTarget(), comp.getIter(), comp.getAIf()
```

**常用方法：**
- `ListComp/DictComp/SetComp/GeneratorExp`: `getElt()`, `getAGenerator()`
- `Comprehension`: `getTarget()`, `getIter()`, `getAIf()`

#### 装饰器和模式匹配
```ql
import python

// 装饰器
from Decorator dec
select dec.getName(), dec.getDecorated()

// 模式匹配 (Python 3.10+)
from Pattern pattern
select pattern, pattern.getCase()

// match 语句
from Match match
select match.getSubject(), match.getACase()

// case 语句
from Case case
select case.getPattern(), case.getGuard(), case.getBody()
```

**常用方法：**
- `Decorator`: `getName()`, `getDecorated()`, `getArg(n)`
- `Match`: `getSubject()`, `getACase()`
- `Case`: `getPattern()`, `getGuard()`, `getBody()`

### 5. 类型和对象

#### 类型相关
```ql
import python

// 对象
from Object obj
select obj, obj.toString()

// 类对象
from ClassObject cls
select cls, cls.getName(), cls.getASuperclass()

// 函数对象
from FunctionObject func
select func, func.getName(), func.getFunction()

// 模块对象
from ModuleObject mod
select mod, mod.getName()
```

**常用方法：**
- `Object`: `toString()`, `getOrigin()`
- `ClassObject`: `getName()`, `getASuperclass()`, `getAMethod()`
- `FunctionObject`: `getName()`, `getFunction()`, `getAParameter()`

### 6. 注释和文档

#### 注释
```ql
import python

// 注释
from Comment comment
select comment.getText(), comment.getContents(), comment.getLocation()
```

**常用方法：**
- `Comment`: `getText()`, `getContents()`, `getLocation()`, `getFollowing()`

### 7. 安全相关

#### 污点追踪
```ql
import python
import semmle.python.dataflow.new.TaintTracking

// 污点追踪配置
module MyTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { ... }
  predicate isSink(DataFlow::Node sink) { ... }
}

module MyTaintFlow = TaintTracking::Global<MyTaintConfig>;

from MyTaintFlow::PathNode source, MyTaintFlow::PathNode sink
where MyTaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "污点从 $@ 流向此处", source.getNode(), "源"
```

### 8. Web 框架支持

#### Flask 相关
```ql
import python
import semmle.python.web.flask.Flask

// Flask 路由
from FlaskRoute route
select route.getFunction(), route.getUrl(), route.getHttpMethod()

// Flask 请求数据
from FlaskRequestData request
select request, request.getKind()
```

#### Django 相关
```ql
import python
import semmle.python.web.django.Django

// Django 视图
from DjangoView view
select view.getFunction(), view.getUrl(), view.getHttpMethod()

// Django 请求数据
from DjangoRequestData request
select request, request.getKind()
```

### 9. 常用工具类

#### 文件和位置
```ql
import python

// 文件
from File f
select f.getAbsolutePath(), f.getBaseName()

// 位置
from Location loc
select loc.getFile(), loc.getStartLine(), loc.getEndLine()
```

**常用方法：**
- `File`: `getAbsolutePath()`, `getBaseName()`, `getExtension()`
- `Location`: `getFile()`, `getStartLine()`, `getEndLine()`, `getStartColumn()`

## 实用查询示例

### 1. 基础语法分析

#### 查找所有函数定义
```ql
import python

from Function f
select f, f.getName(), f.getQualifiedName(), f.getLocation()
```

#### 查找特定名称的函数
```ql
import python

from Function f
where f.getName() = "execute"
select f, f.getLocation(), f.getEnclosingModule().getName()
```

#### 查找所有类方法
```ql
import python

from Function f
where f.isMethod()
select f, f.getName(), f.getEnclosingScope().(Class).getName()
```

#### 查找装饰器使用
```ql
import python

from Decorator d
select d.getName(), d.getDecorated(), d.getLocation()
```

### 2. 变量和数据流分析

#### 查找变量定义和使用
```ql
import python

from Variable v, Name use
where use = v.getAUse()
select v.getId(), use.getLocation(), use.getScope().getName()
```

#### 查找全局变量
```ql
import python

from GlobalVariable gv
select gv.getId(), gv.getScope().(Module).getName()
```

#### 查找函数参数
```ql
import python

from Parameter p
select p.getId(), p.getFunction().getName(), p.getIndex()
```

### 3. 调用分析

#### 查找所有函数调用
```ql
import python

# call location: file name with lineno
# call module: xxx.xx

from Call call
select call.getFunc(), "execute call at location: " + call.getLocation().toString() + " in module: " + call.getEnclosingModule().getName()
```

#### 查找特定函数的调用
```ql
import python

from Call call, Name func
where call.getFunc() = func and func.getId() = "execute"
select call, call.getLocation(), call.getEnclosingModule().getName()
```

#### 查找方法调用
```ql
import python

from Call call, Attribute attr
where call.getFunc() = attr
select call, attr.getObject(), attr.getName(), call.getLocation()
```

#### 分析调用参数
```ql
import python

from Call call
select call, call.getArg(0), call.getNumArg(), call.getAKeyword()
```

### 4. 字符串和常量分析


#### 查找包含特定内容的字符串
```ql
import python

from StrConst s
where s.getText().matches("%SELECT%")
select s, s.getText(), s.getLocation()
```

#### 查找硬编码密码
```ql
import python

from AssignStmt assign, StrConst value
where 
  exists(Name target | 
    target.getId().toLowerCase().matches("%password%") and
    assign.getATarget() = target
  ) and
  assign.getValue() = value
select assign, value.getText(), assign.getLocation()
```

### 5. 导入分析

#### 查找所有导入
```ql
import python

from Import imp, ImportMember im
where im = imp.getAName()
select imp, im.getName(), im.getModule()
```

#### 查找特定模块的导入
```ql
import python

from ImportMember im
where im.getModule() = "os"
select im, im.getName(), im.getLocation()
```

#### 查找 from import 语句
```ql
import python

from ImportStar impstar
select impstar, impstar.getModule(), impstar.getLocation()
```

### 6. 异常处理分析

#### 查找 try-except 块
```ql
import python

from TryStmt try, ExceptStmt except
where except = try.getAHandler()
select try, except.getType(), except.getName()
```

#### 查找空的 except 块
```ql
import python

from ExceptStmt except
where not exists(except.getType()) and
      count(except.getAStmt()) = 1 and
      except.getAStmt() instanceof Pass
select except, "空的 except 块", except.getLocation()
```

#### 查找 raise 语句
```ql
import python

from Raise raise
select raise, raise.getExc(), raise.getCause(), raise.getLocation()
```

### 7. 控制流分析

#### 查找 if 语句
```ql
import python

from If ifstmt
select ifstmt, ifstmt.getTest(), ifstmt.getLocation()
```

#### 查找循环
```ql
import python

from For forstmt
select forstmt, forstmt.getTarget(), forstmt.getIter(), forstmt.getLocation()

from While whilestmt
select whilestmt, whilestmt.getTest(), whilestmt.getLocation()
```

#### 查找 with 语句
```ql
import python

from With withstmt
select withstmt, withstmt.getContextExpr(), withstmt.getOptionalVars()
```

### 8. 推导式和生成器

#### 查找列表推导
```ql
import python

from ListComp lc
select lc, lc.getElt(), lc.getAGenerator()
```

#### 查找字典推导
```ql
import python

from DictComp dc
select dc, dc.getKey(), dc.getValue(), dc.getAGenerator()
```

#### 查找生成器表达式
```ql
import python

from GeneratorExp ge
select ge, ge.getElt(), ge.getAGenerator()
```

### 9. 类和继承分析

#### 查找类定义
```ql
import python

from Class c
select c, c.getName(), c.getAMethod(), c.getASuperclass()
```

#### 查找继承关系
```ql
import python

from Class c, Class superclass
where superclass = c.getASuperclass()
select c.getName(), superclass.getName(), c.getLocation()
```

#### 查找特殊方法
```ql
import python

from Function f
where f.isSpecialMethod()
select f, f.getName(), f.getEnclosingScope().(Class).getName()
```

### 10. 数据流追踪示例

#### 简单数据流
```ql
import python
import semmle.python.dataflow.new.DataFlow

from DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink)
select source, sink, "数据从此处流向 sink"
```

#### 参数到返回值的流
```ql
import python
import semmle.python.dataflow.new.DataFlow

from DataFlow::ParameterNode param, DataFlow::Node ret
where 
  exists(Function f | 
    param.getCallable().asCallable() = f and
    ret.asCfgNode().(NameNode).getId() = param.getParameter().getId() and
    ret.getScope() = f
  )
select param, ret, "参数流向返回值"
```

## 高级查询技巧

### 1. 复杂数据流分析

#### 跨函数的数据流
```ql
import python
import semmle.python.dataflow.new.DataFlow

module CrossFunctionFlow implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 用户输入源
    exists(Call call |
      call.getFunc().(Name).getId() = "input" and
      source.asCfgNode() = call
    )
  }
  
  predicate isSink(DataFlow::Node sink) {
    // 危险函数调用
    exists(Call call |
      call.getFunc().(Name).getId() in ["eval", "exec"] and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module CrossFunctionFlowPath = DataFlow::Global<CrossFunctionFlow>;

from CrossFunctionFlowPath::PathNode source, CrossFunctionFlowPath::PathNode sink
where CrossFunctionFlowPath::flowPath(source, sink)
select sink.getNode(), source, sink, "用户输入 $@ 流向危险函数", source.getNode(), "input"
```

#### 属性访问的数据流
```ql
import python
import semmle.python.dataflow.new.DataFlow

from DataFlow::Node source, DataFlow::AttrRead sink
where DataFlow::localFlow(source, sink.getObject())
select source, sink, "数据流向属性访问: " + sink.getAttributeName()
```

### 2. 模式匹配和复杂查询

#### 查找 SQL 注入模式
```ql
import python

from Call call, BinOp concat, StrConst query, Name userInput
where
  // 字符串拼接模式
  call.getFunc().(Attribute).getName() = "execute" and
  call.getArg(0) = concat and
  concat.getOp() instanceof Add and
  concat.getLeft() = query and
  concat.getRight() = userInput and
  query.getText().toLowerCase().matches("%select%")
select call, "可能的 SQL 注入: " + query.getText(), call.getLocation()
```

#### 查找不安全的反序列化
```ql
import python

from Call call, ImportMember pickle
where
  pickle.getName() = "loads" and
  pickle.getModule() = "pickle" and
  call.getFunc() = pickle.getAUse()
select call, "不安全的 pickle 反序列化", call.getLocation()
```

#### 查找硬编码凭据
```ql
import python

from AssignStmt assign, StrConst value, Name target
where
  assign.getATarget() = target and
  assign.getValue() = value and
  (
    target.getId().toLowerCase().matches("%password%") or
    target.getId().toLowerCase().matches("%secret%") or
    target.getId().toLowerCase().matches("%key%") or
    target.getId().toLowerCase().matches("%token%")
  ) and
  value.getText().length() > 8  // 排除空字符串和占位符
select assign, "硬编码凭据: " + target.getId(), assign.getLocation()
```

### 3. 框架特定分析

#### Flask 路由分析
```ql
import python

from Decorator route, Function handler
where
  route.getName() = "route" and
  route.getDecorated() = handler and
  exists(Call call |
    call.getFunc().(Attribute).getName() = "route" and
    route.getACall() = call
  )
select handler, route.getArg(0), "Flask 路由处理器"
```

#### Django 模型字段分析
```ql
import python

from Class model, AssignStmt field, Call fieldCall
where
  exists(Class django_model |
    django_model.getName() = "Model" and
    model.getASuperclass*() = django_model
  ) and
  field.getScope() = model and
  field.getValue() = fieldCall and
  fieldCall.getFunc().(Attribute).getName().matches("%Field")
select model.getName(), field.getATarget().(Name).getId(), fieldCall.getFunc().(Attribute).getName()
```

### 4. 代码质量检查

#### 查找过长的函数
```ql
import python

from Function f, int lineCount
where
  lineCount = f.getLocation().getEndLine() - f.getLocation().getStartLine() + 1 and
  lineCount > 50 and
  not f.getName().matches("test_%")
select f, "函数过长: " + lineCount + " 行", f.getLocation()
```

#### 查找深度嵌套的代码
```ql
import python

predicate nestedDepth(Stmt s, int depth) {
  not exists(Stmt parent | parent.getASubStatement() = s) and depth = 0
  or
  exists(Stmt parent, int parentDepth |
    parent.getASubStatement() = s and
    nestedDepth(parent, parentDepth) and
    depth = parentDepth + 1
  )
}

from Stmt s, int depth
where 
  nestedDepth(s, depth) and
  depth > 5
select s, "嵌套过深: " + depth + " 层", s.getLocation()
```

#### 查找重复的字符串常量
```ql
import python

from StrConst s1, StrConst s2
where
  s1.getText() = s2.getText() and
  s1.getText().length() > 10 and
  s1.getLocation().getFile() = s2.getLocation().getFile() and
  s1 != s2
select s1, "重复的字符串常量: " + s1.getText(), s1.getLocation()
```

### 5. 性能分析

#### 查找循环中的字符串拼接
```ql
import python

from For loop, AugAssign concat, Name target
where
  concat.getParent+() = loop and
  concat.getTarget() = target and
  concat.getOp() instanceof Add and
  // 检查是否是字符串类型（简化检查）
  exists(StrConst s | s.getParent+() = concat)
select concat, "循环中的字符串拼接，考虑使用 join()", concat.getLocation()
```

#### 查找不必要的列表创建
```ql
import python

from Call call, ListComp lc
where
  call.getFunc().(Name).getId() in ["sum", "max", "min", "any", "all"] and
  call.getArg(0) = lc
select lc, "可以用生成器表达式替代列表推导", lc.getLocation()
```

### 6. 安全漏洞检测

#### 查找命令注入
```ql
import python

from Call call, Name func, Expr arg
where
  func = call.getFunc() and
  func.getId() in ["system", "popen", "call", "run"] and
  arg = call.getArg(0) and
  // 检查参数是否包含用户输入（简化检查）
  exists(BinOp concat | concat.getParent*() = arg and concat.getOp() instanceof Add)
select call, "可能的命令注入", call.getLocation()
```

#### 查找路径遍历漏洞
```ql
import python

from Call call, StrConst path
where
  call.getFunc().(Name).getId() = "open" and
  call.getArg(0) = path and
  (
    path.getText().matches("%../%") or
    path.getText().matches("%..\\%")
  )
select call, "可能的路径遍历: " + path.getText(), call.getLocation()
```

### 7. API 使用分析

#### 查找已弃用的 API 使用
```ql
import python

from Call call, Attribute attr
where
  call.getFunc() = attr and
  (
    (attr.getObject().(Name).getId() = "os" and attr.getName() = "popen") or
    (attr.getObject().(Name).getId() = "subprocess" and attr.getName() = "call")
  )
select call, "使用了已弃用的 API: " + attr.getName(), call.getLocation()
```

#### 查找缺少异常处理的危险操作
```ql
import python

from Call call
where
  call.getFunc().(Name).getId() in ["open", "int", "float"] and
  not exists(TryStmt try | try.getBody().contains(call))
select call, "缺少异常处理的危险操作", call.getLocation()
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

## 测试和示例

### 创建测试用例

**测试目录结构：**
```
~/codeql-projects/my-queries/
├── queries/
│   └── Security/
│       └── SqlInjection.ql       # 您的查询
└── test/
    └── Security/
        └── CWE-089/
            └── SqlInjection/
                ├── test.py               # 测试代码
                ├── SqlInjection.qlref    # 查询引用
                └── SqlInjection.expected # 期望结果
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
# 在您的 Python 项目目录中
cd ~/codeql-projects/my-projects/your-python-project

# 创建 Python 数据库
codeql database create python-db --language=python --source-root=.

# 运行单个查询（使用 CodeQL 标准库中的查询）
codeql query run ~/codeql-projects/codeql/python/ql/src/Security/CWE-089/SqlInjection.ql \
  --database=python-db

# 运行 Python 安全套件
codeql database analyze python-db \
  ~/codeql-projects/codeql/python/ql/src/codeql-suites/python-security-and-quality.qls \
  --format=sarif-latest --output=results.sarif
```

## 最佳实践和优化技巧

### 1. 查询性能优化

#### 使用适当的谓词顺序
```ql
import python

// 好的做法：先过滤，后连接
from Call call, Name func
where 
  func.getId() = "execute" and  // 先过滤
  call.getFunc() = func         // 后连接
select call

// 避免：先连接，后过滤
// from Call call, Name func
// where 
//   call.getFunc() = func and     // 先连接（开销大）
//   func.getId() = "execute"      // 后过滤
```

#### 利用 exists 优化子查询
```ql
import python

// 好的做法：使用 exists
from Function f
where exists(Decorator d | d.getDecorated() = f and d.getName() = "property")
select f

// 避免：直接连接可能导致重复结果
// from Function f, Decorator d
// where d.getDecorated() = f and d.getName() = "property"
// select f
```

exists 版本 将条件转换为子查询，只检查是否存在匹配的 func，而不物化完整的连接结果。这类似于半连接（semi-join），引擎可短路求值（一旦找到匹配即停止），减少内存和计算开销。

适用场景：当子条件不影响 select 输出，exists 更高效

### 2. 利用 Python 特定的 API

#### 使用 API 图追踪框架
```ql
import python
import semmle.python.ApiGraphs

// 追踪 Flask 请求对象
from API::Node request
where request = API::moduleImport("flask").getMember("request")
select request.getMember("args").getACall(), "Flask 请求参数访问"

// 追踪 Django 模型
// something like API::moduleImport("django.db.models") will not do what you expect
from API::Node model
where model = API::moduleImport("django").getMemeber("db").getMember("models").getMember("Model")
select model.getASubclass(), "Django 模型子类"
```

#### 使用指向分析
```ql
import python
import semmle.python.pointsto.PointsTo

from ControlFlowNode node, Object obj
where node.pointsTo(obj)
select node, obj, "节点指向对象"
```

### 3. 处理 Python 的动态特性

#### 动态属性访问
```ql
import python

// 直接属性访问
from Attribute attr
where attr.getName() = "dangerous_method"
select attr, "直接属性访问"

// getattr 调用
from Call call, StrConst attrName
where 
  call.getFunc().(Name).getId() = "getattr" and
  call.getArg(1) = attrName and
  attrName.getText() = "dangerous_method"
select call, "通过 getattr 访问属性"

// hasattr 检查
from Call call, StrConst attrName
where 
  call.getFunc().(Name).getId() = "hasattr" and
  call.getArg(1) = attrName
select call, "属性存在性检查: " + attrName.getText()
```

#### 动态导入处理
```ql
import python

// __import__ 调用
from Call call, StrConst modName
where 
  call.getFunc().(Name).getId() = "__import__" and
  call.getArg(0) = modName
select call, "动态导入: " + modName.getText()

// importlib.import_module 调用
from Call call, StrConst modName
where 
  call.getFunc().(Attribute).getName() = "import_module" and
  call.getArg(0) = modName
select call, "importlib 动态导入: " + modName.getText()
```


### 调试和测试技巧

#### 添加调试信息
```ql
import python

from Function f
select f, f.getName(), f.getLocation().toString(), f.getQualifiedName()
```

#### 使用 toString() 方法
```ql
import python

from Expr e
select e.toString(), e.getLocation(), e.getScope().getName()
```

#### 检查查询覆盖范围
```ql
import python

// 统计不同类型的节点数量
select "Functions", count(Function f)
select "Classes", count(Class c)
select "Calls", count(Call call)
select "Modules", count(Module m)
```

### 7. 常见陷阱和解决方案

#### 避免过度泛化
```ql
import python

// 好的做法：具体的模式匹配
from Call call, Attribute attr
where 
  call.getFunc() = attr and
  attr.getObject().(Name).getId() = "os" and
  attr.getName() = "system"
select call

// 避免：过于宽泛的匹配
// from Call call
// where call.getFunc().(Name).getId().matches("%system%")
// select call
```

#### 正确处理作用域
```ql
import python

// 正确：在同一作用域内查找
from Variable v, Name use
where 
  use = v.getAUse() and
  use.getScope() = v.getScope()
select v, use

// 注意：跨作用域的变量使用需要特殊处理
from Variable v, Name use
where 
  use = v.getAUse() and
  use.getScope() != v.getScope()
select v, use, "跨作用域使用"
```

### 8. 性能监控和优化

#### 查询复杂度分析
```ql
import python

// 简单查询：O(n)
from Function f
select f

// 复杂查询：注意笛卡尔积
from Function f, Call call
where call.getScope() = f  // 添加适当的连接条件
select f, call
```

#### 使用缓存和预计算
```ql
import python

// 预计算常用的谓词
cached
predicate isWebFrameworkFunction(Function f) {
  exists(Decorator d | 
    d.getDecorated() = f and
    d.getName() in ["route", "view", "api_view"]
  )
}

from Function f
where isWebFrameworkFunction(f)
select f
```

### 9. 代码组织和模块化

#### 创建可重用的谓词
```ql
import python

predicate isDangerousFunction(string name) {
  name in ["eval", "exec", "compile", "__import__"]
}

predicate isUserInput(Expr e) {
  exists(Call call |
    call.getFunc().(Name).getId() in ["input", "raw_input"] and
    e = call
  )
}

from Call call, Expr arg
where 
  isDangerousFunction(call.getFunc().(Name).getId()) and
  arg = call.getArg(0) and
  isUserInput(arg)
select call, "危险函数调用用户输入"
```

#### 使用模块化配置
```ql
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module UserInputToEval implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Call call |
      call.getFunc().(Name).getId() in ["input", "raw_input"] and
      source.asCfgNode() = call
    )
  }
  
  predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getFunc().(Name).getId() in ["eval", "exec"] and
      sink.asCfgNode() = call.getArg(0)
    )
  }
}

module UserInputToEvalFlow = TaintTracking::Global<UserInputToEval>;
```

## 总结

### 核心 from 语句速查表

| 类别 | from 语句 | 主要用途 | 常用方法 |
|------|-----------|----------|----------|
| **基础 AST** | `from Module m` | 模块分析 | `getName()`, `getFile()`, `getAStmt()` |
| | `from Function f` | 函数分析 | `getName()`, `getAParameter()`, `isMethod()` |
| | `from Class c` | 类分析 | `getName()`, `getAMethod()`, `getASuperclass()` |
| | `from Variable v` | 变量分析 | `getId()`, `getScope()`, `getAUse()` |
| **表达式** | `from Call call` | 函数调用 | `getFunc()`, `getArg(n)`, `getAKeyword()` |
| | `from Attribute attr` | 属性访问 | `getObject()`, `getName()` |
| | `from Name name` | 名称引用 | `getId()`, `getVariable()`, `uses()` |
| | `from StrConst s` | 字符串常量 | `getText()`, `getValue()` |
| **语句** | `from AssignStmt assign` | 赋值语句 | `getATarget()`, `getValue()` |
| | `from If ifstmt` | 条件语句 | `getTest()`, `getBody()`, `getOrelse()` |
| | `from For forstmt` | 循环语句 | `getTarget()`, `getIter()`, `getBody()` |
| | `from TryStmt try` | 异常处理 | `getBody()`, `getAHandler()` |
| **控制流** | `from ControlFlowNode node` | 控制流节点 | `getNode()`, `getASuccessor()` |
| | `from CallNode call` | 调用节点 | `getFunction()`, `getArg(n)` |
| **数据流** | `from DataFlow::Node node` | 数据流节点 | `asCfgNode()`, `getLocation()` |
| | `from DataFlow::ParameterNode param` | 参数节点 | `getParameter()`, `getCallable()` |
| **导入** | `from Import imp` | 导入语句 | `getAName()`, `getAnAlias()` |
| | `from ImportMember im` | 导入成员 | `getName()`, `getModule()` |
| **特殊** | `from Decorator d` | 装饰器 | `getName()`, `getDecorated()` |
| | `from Comment comment` | 注释 | `getText()`, `getContents()` |

### 常用查询模式

#### 1. 安全漏洞检测模式
```ql
// SQL 注入检测
from Call call, BinOp concat, StrConst query
where 
  call.getFunc().(Attribute).getName() = "execute" and
  call.getArg(0) = concat and
  concat.getOp() instanceof Add and
  concat.getLeft() = query and
  query.getText().toLowerCase().matches("%select%")
select call, "SQL 注入风险"

// 命令注入检测
from Call call
where 
  call.getFunc().(Name).getId() in ["system", "popen"] and
  exists(BinOp concat | concat.getParent*() = call.getArg(0))
select call, "命令注入风险"
```

#### 2. 代码质量检查模式
```ql
// 未使用的导入
from Import imp, ImportMember im
where 
  im = imp.getAName() and
  not exists(Name use | use.getId() = im.getName() and use.getScope() = im.getScope())
select im, "未使用的导入"

// 过长的函数
from Function f, int lines
where 
  lines = f.getLocation().getEndLine() - f.getLocation().getStartLine() and
  lines > 50
select f, "函数过长: " + lines + " 行"
```

#### 3. 数据流追踪模式
```ql
// 简单数据流
module SimpleFlow implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { /* 定义源 */ }
  predicate isSink(DataFlow::Node sink) { /* 定义汇 */ }
}

module SimpleFlowPath = DataFlow::Global<SimpleFlow>;

from SimpleFlowPath::PathNode source, SimpleFlowPath::PathNode sink
where SimpleFlowPath::flowPath(source, sink)
select sink.getNode(), source, sink, "数据流"
```

### 性能优化要点

1. **查询顺序**：先过滤，后连接
2. **使用 exists**：避免不必要的笛卡尔积
3. **适当缓存**：对复杂谓词使用 `cached`
4. **边界检查**：确保对象存在再访问属性
5. **作用域限制**：在合适的作用域内进行查询

### 调试技巧

1. **逐步构建**：从简单查询开始，逐步添加条件
2. **使用 toString()**：查看对象的字符串表示
3. **检查位置**：使用 `getLocation()` 确认结果
4. **统计数量**：使用 `count()` 验证查询范围
5. **添加调试输出**：临时添加额外的 select 子句

## REF

- [CodeQL query help for Python](https://codeql.github.com/codeql-query-help/python/)