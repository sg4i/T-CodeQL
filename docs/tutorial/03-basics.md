# CodeQL 基础

> 深入了解 CodeQL 的核心概念、仓库结构和 QL 语言基础

## 核心概念

### 数据库（Database）

CodeQL 数据库是源代码的关系表示，包含了代码的语法和语义信息。

#### 数据库创建过程

1. **提取（Extraction）**
   - 分析源代码文件
   - 提取语法树（AST）
   - 收集语义信息（类型、作用域等）

2. **存储（Storage）**
   - 将信息存储为关系表
   - 创建索引以优化查询性能

3. **查询（Querying）**
   - 使用 QL 语言查询数据库
   - 返回结构化结果

#### 编译型 vs 解释型语言

**编译型语言**（Java、C++、Go）：
- 监控构建过程
- 在编译时提取信息
- 需要成功的构建

**解释型语言**（Python、JavaScript、Ruby）：
- 直接分析源代码
- 解析依赖关系
- 不需要构建过程

### 查询（Query）

查询是用 QL 语言编写的 `.ql` 文件，用于从数据库中提取特定信息。

#### 查询类型

```ql
/**
 * @kind problem        - 问题查询：标记代码位置
 * @kind path-problem   - 路径查询：显示数据流路径  
 * @kind metric         - 指标查询：统计信息
 * @kind table          - 表格查询：结构化数据
 */
```

#### 查询结构

```ql
/**
 * 查询元数据
 */

import 模块

from 变量声明
where 条件约束
select 结果表达式
```

### QLPack（包管理）

QLPack 是 CodeQL 的包管理系统，类似于 npm、pip。

#### qlpack.yml 结构

```yaml
name: codeql/python-all          # 包名
version: 4.1.1-dev               # 版本号
groups: python                   # 语言组
dbscheme: semmlecode.python.dbscheme  # 数据库模式
extractor: python                # 提取器名称
library: true                    # 是否为库包
upgrades: upgrades               # 升级脚本目录

dependencies:                    # 依赖包
  codeql/dataflow: ${workspace}
  codeql/util: ${workspace}

dataExtensions:                  # 数据扩展
  - semmle/python/frameworks/**/*.model.yml
  - ext/*.model.yml
```

#### 包类型

- **库包** (`library: true`)：提供可重用的类和谓词
- **查询包** (`library: false`)：包含可执行的查询
- **测试包**：包含单元测试

### 提取器（Extractor）

提取器负责将源代码转换为 CodeQL 数据库。

#### 提取器位置

```
<language>/
├── extractor/              # 提取器实现
├── tools/                  # 辅助工具
└── codeql-extractor.yml   # 提取器配置
```

#### 提取器配置示例

```yaml
name: python
display_name: Python
version: 1.0.0
column_kind: utf16
primary_language: python
```

## 仓库结构详解

### 顶层目录

```
codeql/
├── python/              # Python 语言支持
├── java/                # Java/Kotlin 语言支持
├── javascript/          # JavaScript/TypeScript 语言支持
├── go/                  # Go 语言支持
├── cpp/                 # C/C++ 语言支持
├── csharp/              # C# 语言支持
├── ruby/                # Ruby 语言支持
├── swift/               # Swift 语言支持
├── rust/                # Rust 语言支持（新增）
├── shared/              # 跨语言共享库
├── ql/                  # QL 语言核心
├── docs/                # 官方文档
├── misc/                # 工具脚本
├── actions/             # GitHub Actions 相关
├── config/              # 配置文件
└── change-notes/        # 版本变更日志
```

### 语言目录结构

以 Python 为例：

```
python/
├── ql/
│   ├── lib/                    # 核心库
│   │   ├── semmle/python/     # 标准库实现
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   ├── Concepts.qll   # 通用概念
│   │   │   ├── ApiGraphs.qll  # API 建模
│   │   │   └── ...
│   │   ├── qlpack.yml         # 库包配置
│   │   └── python.qll         # 主入口文件
│   ├── src/                    # 查询源码
│   │   ├── Security/          # 安全查询
│   │   │   ├── CWE-089/      # SQL 注入
│   │   │   ├── CWE-078/      # 命令注入
│   │   │   └── ...
│   │   ├── Quality/           # 代码质量查询
│   │   ├── codeql-suites/     # 预定义查询套件
│   │   └── qlpack.yml         # 查询包配置
│   ├── test/                   # 测试用例
│   │   ├── query-tests/       # 查询测试
│   │   ├── library-tests/     # 库测试
│   │   └── qlpack.yml         # 测试包配置
│   └── examples/               # 示例查询
│       └── snippets/          # 代码片段示例
├── extractor/                  # Python 提取器
│   ├── semmle/                # 提取器实现
│   └── qlpack.yml             # 提取器包配置
├── tools/                      # 工具脚本
└── codeql-extractor.yml       # 提取器配置
```

### 共享库目录

```
shared/
├── concepts/           # 通用概念（HTTP、数据库等）
├── controlflow/        # 控制流图
├── dataflow/           # 数据流分析框架
├── ssa/                # 静态单赋值形式
├── regex/              # 正则表达式分析
├── threat-models/      # 威胁建模
├── util/               # 通用工具
├── xml/                # XML 处理
├── yaml/               # YAML 处理
└── ...
```

## QL 语言基础

### 基本语法

#### 1. 导入模块

```ql
import python                    // 导入 Python 标准库
import semmle.python.dataflow.new.DataFlow  // 导入数据流模块
import DataFlow::PathGraph       // 导入路径图
```

#### 2. 类定义

```ql
/**
 * 表示临时变量的类
 */
class TemporaryVariable extends Variable {
  TemporaryVariable() {
    // 特征谓词：定义类的成员条件
    this.getName().matches("temp%")
  }
  
  /**
   * 获取变量描述
   */
  string getDescription() {
    result = "临时变量: " + this.getName()
  }
  
  /**
   * 检查是否为数字临时变量
   */
  predicate isNumeric() {
    this.getName().regexpMatch("temp\\d+")
  }
}
```

#### 3. 谓词定义

```ql
// 无返回值的谓词（布尔谓词）
predicate isPublicMethod(Method m) {
  m.isPublic()
}

// 有返回值的谓词
int getNumberOfParameters(Method m) {
  result = count(m.getAParameter())
}

// 多参数谓词
predicate calls(Function caller, Function callee) {
  exists(CallNode call |
    call.getScope() = caller and
    call.getFunction().pointsTo().getClass() = callee
  )
}
```

#### 4. 查询语句

```ql
from Variable v
where 
  v.getName().matches("temp%") and
  not v.isUsed()
select v, "未使用的临时变量"
```

### 逻辑运算符

#### 基本运算符

```ql
// 逻辑与
where condition1 and condition2

// 逻辑或
where condition1 or condition2

// 逻辑非
where not condition

// 蕴含
where condition1 implies condition2

// 等价
where condition1 if and only if condition2
```

#### 存在量词

```ql
// 存在：至少有一个满足条件的元素
exists(Type variable | restrictions | formula)

// 示例：查找调用了 eval 函数的代码
exists(CallNode call |
  call.getFunction().(NameNode).getId() = "eval" |
  select call, "危险的 eval 调用"
)
```

#### 聚合函数

```ql
// 计数
count(Type var | restrictions | var)

// 求和
sum(Type var | restrictions | var.getValue())

// 最大值
max(Type var | restrictions | var.getValue())

// 最小值  
min(Type var | restrictions | var.getValue())

// 任意一个
any(Type var | restrictions | var)

// 全称量词
forall(Type var | restrictions | formula)

// 严格计数（至少2个）
strictcount(Type var | restrictions | var) >= 2
```

### 条件表达式

```ql
// if-then-else
if condition 
then result1 
else result2

// 示例
string getVisibility(Method m) {
  if m.isPublic()
  then result = "public"
  else if m.isPrivate()
  then result = "private"
  else result = "protected"
}
```

### 类型和转换

```ql
// 类型检查
where expr instanceof StringLiteral

// 类型转换（后缀）
expr.(StringLiteral).getValue()

// 类型转换（前缀）
(StringLiteral)expr.getValue()
```

### 字符串操作

```ql
// 字符串匹配
where s.matches("*password*")

// 正则表达式
where s.regexpMatch(".*\\b(password|secret)\\b.*")

// 字符串连接
result = "Found: " + s.getValue()

// 字符串长度
where s.length() > 10
```

## 常用模式

### 1. 查找函数调用

```ql
/**
 * @name 查找危险函数调用
 */
import python

from CallNode call, string funcName
where 
  call.getFunction().(NameNode).getId() = funcName and
  funcName in ["eval", "exec", "compile"]
select call, "调用了危险函数: " + funcName
```

### 2. 查找字符串常量

```ql
/**
 * @name 查找硬编码密码
 */
import python

from StrConst s
where 
  s.getText().regexpMatch(".*(?i)(password|secret|key).*") and
  s.getText().length() > 8
select s, "可能的硬编码凭证"
```

### 3. 查找类和方法

```ql
/**
 * @name 查找公共方法
 */
import python

from Function f
where 
  f.isMethod() and
  not f.getName().matches("_%")  // 不是私有方法
select f, f.getQualifiedName()
```

### 4. 控制流分析

```ql
/**
 * @name 查找无法到达的代码
 */
import python

from Stmt s
where not s.getAFlowNode().isReachable()
select s, "无法到达的代码"
```

### 5. 数据流基础

```ql
/**
 * @name 简单数据流
 */
import python
import semmle.python.dataflow.new.DataFlow

from DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink)
select sink, source, "数据从这里流向这里"
```

## 调试技巧

### 1. 使用 select 调试

```ql
// 查看中间结果
from Expr e
where e instanceof Call
select e, e.getType(), e.getLocation()
```

### 2. 检查数据是否存在

```ql
// 验证数据库中是否有期望的数据
from Function f
select f, f.getName(), f.getLocation()
```

### 3. 使用 Quick Evaluation

在 VS Code 中：
1. 选中要测试的代码片段
2. 右键 → "CodeQL: Quick Evaluation"
3. 选择数据库
4. 查看结果

### 4. 逐步构建查询

```ql
// 第一步：找到所有函数
from Function f
select f

// 第二步：添加条件
from Function f
where f.getName() = "dangerous"
select f

// 第三步：添加更多信息
from Function f
where f.getName() = "dangerous"
select f, f.getLocation(), f.getScope()
```

## 性能优化

### 1. 使用缓存

```ql
cached
predicate expensiveComputation(Node n) {
  // 昂贵的计算
  exists(ComplexAnalysis analysis |
    analysis.analyze(n) and
    analysis.isInteresting()
  )
}
```

### 2. 提前过滤

```ql
// 好的做法：先用限制性强的条件
from Variable v
where 
  v.getName() = "specific_name" and  // 强限制
  v.getType() instanceof ComplexType  // 弱限制
select v

// 不好的做法：先用限制性弱的条件
from Variable v
where 
  v.getType() instanceof ComplexType and  // 弱限制
  v.getName() = "specific_name"            // 强限制
select v
```

### 3. 避免笛卡尔积

```ql
// 不好：可能产生大量组合
from Function f, Variable v
where someCondition(f, v)
select f, v

// 好：通过关系连接
from Function f, Variable v
where 
  v.getScope() = f and  // 建立关系
  someCondition(f, v)
select f, v
```

### 4. 使用 exists 限制作用域

```ql
// 限制在特定范围内搜索
exists(Function f |
  f.getName() = "main" |
  // 在 main 函数内搜索
  result = f.getAChild()
)
```

## 下一步

掌握了 CodeQL 基础后，建议继续学习：

1. **[查询编写](04-writing-queries.md)** - 编写您的第一个实用查询
2. **[数据流分析](05-dataflow-analysis.md)** - 学习高级分析技术
3. **[Python 场景](07-python.md)** - 深入特定语言的应用

---

**基础知识掌握完毕！** 🎓 现在您可以开始编写更复杂的查询了。
