# JavaScript 场景应用

> 前端和 Node.js 安全分析完整指南，涵盖 React、Vue、Express、Next.js 等主流技术栈

## JavaScript 语言支持概览

### 目录结构

```
javascript/
├── ql/
│   ├── lib/                    # JavaScript 核心库
│   │   ├── semmle/javascript/ # 标准库实现
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   ├── frameworks/    # 框架支持
│   │   │   │   ├── Express.qll    # Express.js
│   │   │   │   ├── React.qll      # React
│   │   │   │   ├── Vue.qll        # Vue.js
│   │   │   │   ├── Angular.qll    # Angular
│   │   │   │   └── NodeJS.qll     # Node.js
│   │   │   ├── DOM.qll        # DOM 操作
│   │   │   └── Concepts.qll   # 通用概念
│   │   ├── qlpack.yml         # 库包配置
│   │   └── javascript.qll     # 主入口文件
│   ├── src/                    # 查询源码
│   │   ├── Security/          # 安全查询
│   │   │   ├── CWE-079/      # XSS
│   │   │   ├── CWE-089/      # SQL 注入
│   │   │   ├── CWE-078/      # 命令注入
│   │   │   └── CWE-094/      # 代码注入
│   │   ├── NodeJS/            # Node.js 特定
│   │   ├── React/             # React 特定
│   │   ├── Vue/               # Vue 特定
│   │   └── codeql-suites/     # 预定义查询套件
│   ├── test/                   # 测试用例
│   └── examples/               # 示例查询
└── extractor/                  # JavaScript 提取器
```

### 支持的 JavaScript 环境

- **浏览器环境** - 完全支持
- **Node.js** - 完全支持 (8.x+)
- **TypeScript** - 完全支持 (3.x+)
- **Deno** - 基础支持
- **Bun** - 基础支持

### 框架支持

| 框架类型 | 支持的框架 | 位置 |
|----------|------------|------|
| **前端框架** | React, Vue, Angular, Svelte | `semmle/javascript/frameworks/` |
| **后端框架** | Express, Koa, Fastify, NestJS | `semmle/javascript/frameworks/` |
| **全栈框架** | Next.js, Nuxt.js, SvelteKit | `semmle/javascript/frameworks/` |
| **构建工具** | Webpack, Vite, Rollup | `semmle/javascript/frameworks/` |
| **测试框架** | Jest, Mocha, Cypress | `semmle/javascript/frameworks/` |
| **数据库** | MongoDB, MySQL, PostgreSQL | `semmle/javascript/frameworks/` |

## JavaScript 核心类和概念

### 基本语法元素

```ql
import javascript

// 函数
from Function f
select f.getName(), f.getNumParameter(), f.getBody()

// 变量
from Variable v
select v.getName(), v.getADeclaration(), v.getAnAccess()

// 函数调用
from CallExpr call
select call.getCallee(), call.getNumArgument(), call.getArgument(0)

// 属性访问
from PropAccess prop
select prop.getBase(), prop.getPropertyName()

// 字符串字面量
from StringLiteral str
select str.getValue(), str.getStringValue()

// 对象字面量
from ObjectExpr obj
select obj.getAProperty()
```

### JavaScript 特定类

```ql
import javascript

// 箭头函数
from ArrowFunctionExpr arrow
select arrow.getBody(), arrow.getAParameter()

// 模板字面量
from TemplateLiteral tmpl
select tmpl.getAnElement()

// 解构赋值
from DestructuringPattern pattern
select pattern.getABindingVarRef()

// 异步函数
from Function f
where f.isAsync()
select f, "异步函数"

// Promise
from NewExpr newExpr
where newExpr.getCallee().(GlobalVarAccess).getName() = "Promise"
select newExpr, "Promise 构造"

// 模块导入/导出
from ImportDeclaration imp
select imp.getASpecifier(), imp.getImportedPath()

from ExportDeclaration exp
select exp.getASpecifier()
```

## 前端安全分析

### 1. React XSS 检测

```ql
/**
 * @name React XSS 通过 dangerouslySetInnerHTML
 * @description 检测 React 中通过 dangerouslySetInnerHTML 的 XSS 漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id js/react-dangerous-innerhtml-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/owasp-a03
 *       react
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

class ReactDangerousInnerHTMLConfig extends TaintTracking::Configuration {
  ReactDangerousInnerHTMLConfig() { this = "ReactDangerousInnerHTMLConfig" }

  override predicate isSource(DataFlow::Node source) {
    // 用户输入源
    exists(HTTP::RequestInputAccess input |
      source = input
    )
    or
    // URL 参数
    exists(DataFlow::GlobalVarRef url |
      url.getName() = "location" and
      source = url.getAPropertyRead("search")
    )
    or
    // localStorage/sessionStorage
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef(["localStorage", "sessionStorage"]).getAMethodCall("getItem") and
      source = call
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // dangerouslySetInnerHTML 属性
    exists(JSXAttribute attr |
      attr.getName() = "dangerouslySetInnerHTML" and
      exists(ObjectExpr obj, Property prop |
        obj = attr.getValue() and
        prop = obj.getAProperty() and
        prop.getName() = "__html" and
        sink.asExpr() = prop.getValue()
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // HTML 转义函数
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["escape", "escapeHtml", "sanitize", "DOMPurify.sanitize"] and
      node = call
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 字符串拼接
    exists(AddExpr add |
      (fromNode.asExpr() = add.getLeftOperand() or fromNode.asExpr() = add.getRightOperand()) and
      toNode.asExpr() = add
    )
    or
    // 模板字符串
    exists(TemplateLiteral tmpl, TemplateElement elem |
      tmpl.getAnElement() = elem and
      fromNode.asExpr() = elem.getValue() and
      toNode.asExpr() = tmpl
    )
  }
}

from ReactDangerousInnerHTMLConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "React dangerouslySetInnerHTML 包含用户输入 $@，可能导致 XSS 攻击", 
  source.getNode(), "用户数据"
```

### 2. DOM XSS 检测

```ql
/**
 * @name DOM 型 XSS
 * @description 检测通过 DOM 操作的 XSS 漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @id js/dom-based-xss
 * @tags security
 *       external/cwe/cwe-079
 *       dom
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXssQuery
import DomBasedXss::Configuration
import DataFlow::PathGraph

from Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "DOM XSS: 用户输入 $@ 直接插入到 DOM 中", 
  source.getNode(), "DOM 源"
```

### 3. 客户端原型污染

```ql
/**
 * @name 客户端原型污染
 * @description 检测可能导致原型污染的客户端代码
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @id js/client-side-prototype-pollution
 * @tags security
 *       external/cwe/cwe-1321
 *       prototype-pollution
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

class ClientPrototypePollutionConfig extends TaintTracking::Configuration {
  ClientPrototypePollutionConfig() { this = "ClientPrototypePollutionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // URL 参数
    exists(DataFlow::GlobalVarRef url |
      url.getName() = "location" and
      source = url.getAPropertyRead(["search", "hash"])
    )
    or
    // postMessage 数据
    exists(DataFlow::ParameterNode param |
      param.getName() = "event" and
      exists(EventHandler handler |
        handler.getAParameter() = param.getParameter() and
        handler.getEventType() = "message"
      ) and
      source = param.getAPropertyRead("data")
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // 对象属性赋值，可能影响原型
    exists(Assignment assign |
      assign.getLhs().(PropAccess).getPropertyName() = "__proto__" and
      sink.asExpr() = assign.getRhs()
    )
    or
    // 深度合并函数
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["merge", "extend", "assign", "deepMerge"] and
      sink = call.getAnArgument()
    )
  }
}

from ClientPrototypePollutionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "客户端原型污染: 用户输入 $@ 可能污染对象原型", 
  source.getNode(), "用户数据"
```

### 4. 不安全的 eval 使用

```ql
/**
 * @name 不安全的 eval 使用
 * @description 检测使用用户输入的 eval 调用
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @id js/unsafe-eval-usage
 * @tags security
 *       external/cwe/cwe-094
 *       eval
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

class UnsafeEvalConfig extends TaintTracking::Configuration {
  UnsafeEvalConfig() { this = "UnsafeEvalConfig" }

  override predicate isSource(DataFlow::Node source) {
    // 各种用户输入源
    exists(HTTP::RequestInputAccess input |
      source = input
    )
    or
    exists(DataFlow::GlobalVarRef ref |
      ref.getName() = "location" and
      source = ref.getAPropertyRead()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // eval 调用
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef("eval").getACall() and
      sink = call.getArgument(0)
    )
    or
    // Function 构造函数
    exists(DataFlow::NewNode newCall |
      newCall = DataFlow::globalVarRef("Function").getAnInstantiation() and
      sink = newCall.getAnArgument()
    )
    or
    // setTimeout/setInterval 字符串参数
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef(["setTimeout", "setInterval"]).getACall() and
      call.getArgument(0).asExpr() instanceof StringLiteral and
      sink = call.getArgument(0)
    )
  }
}

from UnsafeEvalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "不安全的代码执行: 用户输入 $@ 被传递给 eval", 
  source.getNode(), "用户数据"
```

## Node.js 后端安全分析

### 1. Express.js SQL 注入检测

```ql
/**
 * @name Express.js SQL 注入
 * @description 检测 Express.js 应用中的 SQL 注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id js/express-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       express
 *       nodejs
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.frameworks.Express
import DataFlow::PathGraph

class ExpressSqlInjectionConfig extends TaintTracking::Configuration {
  ExpressSqlInjectionConfig() { this = "ExpressSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Express 请求参数
    source instanceof Express::RequestInputAccess
  }

  override predicate isSink(DataFlow::Node sink) {
    // 数据库查询方法
    exists(DataFlow::MethodCallNode call |
      (
        // MySQL
        (call.getReceiver().getALocalSource().asExpr().(CallExpr).getCallee().(PropAccess).getPropertyName() = "createConnection" and
         call.getMethodName() = "query") or
        
        // PostgreSQL
        (call.getMethodName() = "query" and
         call.getReceiver().getALocalSource().asExpr().(CallExpr).getCallee().(GlobalVarAccess).getName() = "Client") or
         
        // MongoDB (不安全的原生查询)
        (call.getMethodName() in ["eval", "$where"] and
         call.getReceiver().toString().matches("*collection*"))
      ) and
      sink = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // 参数化查询
    exists(DataFlow::ArrayCreationNode array |
      node = array and
      array.getAnElement().asExpr() instanceof StringLiteral
    )
    or
    // SQL 转义函数
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["escape", "escapeId", "format"] and
      node = call
    )
  }
}

from ExpressSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Express SQL 查询包含用户输入 $@，可能导致 SQL 注入", 
  source.getNode(), "请求参数"
```

### 2. Node.js 命令注入检测

```ql
/**
 * @name Node.js 命令注入
 * @description 检测 Node.js 中的系统命令注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id js/nodejs-command-injection
 * @tags security
 *       external/cwe/cwe-078
 *       nodejs
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

class NodeCommandInjectionConfig extends TaintTracking::Configuration {
  NodeCommandInjectionConfig() { this = "NodeCommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // HTTP 请求输入
    source instanceof HTTP::RequestInputAccess
    or
    // 命令行参数
    exists(DataFlow::PropRead read |
      read.getBase() = DataFlow::globalVarRef("process").getAPropertyRead("argv") and
      source = read
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // child_process 模块的危险方法
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleImport("child_process").getAMemberCall(["exec", "execSync", "spawn", "spawnSync"]) and
      sink = call.getArgument(0)
    )
    or
    // shell 选项为 true 的情况
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleImport("child_process").getAMemberCall(["spawn", "spawnSync"]) and
      exists(DataFlow::ObjectLiteralNode options |
        options = call.getArgument(2) and
        options.hasPropertyWrite("shell", DataFlow::valueNode(any(BooleanLiteral b | b.getValue() = "true")))
      ) and
      sink = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // 使用数组形式的命令（相对安全）
    node.asExpr() instanceof ArrayExpr
    or
    // 命令转义
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["shellEscape", "shellescape"] and
      node = call
    )
  }
}

from NodeCommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Node.js 命令执行包含用户输入 $@，可能导致命令注入", 
  source.getNode(), "用户输入"
```

### 3. 路径遍历检测

```ql
/**
 * @name Node.js 路径遍历
 * @description 检测 Node.js 文件操作中的路径遍历漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id js/nodejs-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       nodejs
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

class NodePathTraversalConfig extends TaintTracking::Configuration {
  NodePathTraversalConfig() { this = "NodePathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    // HTTP 请求中的文件名参数
    source instanceof HTTP::RequestInputAccess
  }

  override predicate isSink(DataFlow::Node sink) {
    // 文件系统操作
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleImport("fs").getAMemberCall([
        "readFile", "readFileSync", "writeFile", "writeFileSync",
        "unlink", "unlinkSync", "stat", "statSync", "open", "openSync"
      ]) and
      sink = call.getArgument(0)
    )
    or
    // 路径操作
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleImport("path").getAMemberCall(["join", "resolve"]) and
      sink = call.getAnArgument()
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // 路径规范化
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleImport("path").getAMemberCall(["normalize", "resolve"]) and
      node = call
    )
    or
    // 路径验证
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(validate|sanitize|clean).*path.*") and
      node = call
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 路径拼接
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleImport("path").getAMemberCall("join") and
      fromNode = call.getAnArgument() and
      toNode = call
    )
  }
}

from NodePathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "文件操作使用了用户输入的路径 $@，可能导致路径遍历", 
  source.getNode(), "请求参数"
```

### 4. NoSQL 注入检测

```ql
/**
 * @name MongoDB NoSQL 注入
 * @description 检测 MongoDB 查询中的 NoSQL 注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id js/mongodb-nosql-injection
 * @tags security
 *       external/cwe/cwe-943
 *       mongodb
 *       nosql
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

class MongoNoSqlInjectionConfig extends TaintTracking::Configuration {
  MongoNoSqlInjectionConfig() { this = "MongoNoSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // HTTP 请求输入
    source instanceof HTTP::RequestInputAccess
  }

  override predicate isSink(DataFlow::Node sink) {
    // MongoDB 查询方法
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in [
        "find", "findOne", "update", "updateOne", "updateMany",
        "deleteOne", "deleteMany", "aggregate", "count"
      ] and
      // 确保是 MongoDB 集合对象
      call.getReceiver().getALocalSource().asExpr().(CallExpr).getCallee().(PropAccess).getPropertyName() = "collection" and
      sink = call.getArgument(0)
    )
    or
    // MongoDB 原生查询
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "eval" and
      call.getReceiver().toString().matches("*db*") and
      sink = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // 类型验证
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["parseInt", "parseFloat", "Number"] and
      node = call
    )
    or
    // 对象验证
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["isObject", "isPlainObject"] and
      node.getALocalSource() = call.getArgument(0)
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // JSON 解析
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef("JSON").getAMemberCall("parse") and
      fromNode = call.getArgument(0) and
      toNode = call
    )
  }
}

from MongoNoSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "MongoDB 查询包含用户输入 $@，可能导致 NoSQL 注入", 
  source.getNode(), "请求数据"
```

## 现代框架安全模式

### 1. Next.js 服务端渲染 XSS

```ql
/**
 * @name Next.js SSR XSS
 * @description 检测 Next.js 服务端渲染中的 XSS 漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @id js/nextjs-ssr-xss
 * @tags security
 *       external/cwe/cwe-079
 *       nextjs
 *       ssr
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

class NextjsSsrXssConfig extends TaintTracking::Configuration {
  NextjsSsrXssConfig() { this = "NextjsSsrXssConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Next.js 服务端 props
    exists(DataFlow::FunctionNode getServerSideProps |
      getServerSideProps.getName() = "getServerSideProps" and
      source = getServerSideProps.getAReturn().getAPropertyWrite("props").getRhs().getAPropertyWrite().getRhs()
    )
    or
    // 查询参数
    exists(DataFlow::PropRead read |
      read.getPropertyName() = "query" and
      read.getBase().getALocalSource().asExpr().(Parameter).getName() = "context" and
      source = read.getAPropertyRead()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // dangerouslySetInnerHTML
    exists(JSXAttribute attr |
      attr.getName() = "dangerouslySetInnerHTML" and
      sink.asExpr() = attr.getValue().(ObjectExpr).getAProperty().getValue()
    )
    or
    // 直接 JSX 插值（可能不安全）
    exists(JSXExpressionContainer container |
      sink.asExpr() = container.getExpression() and
      not exists(DataFlow::CallNode call |
        call.getCalleeName() in ["escape", "sanitize"] and
        call = container.getExpression().flow()
      )
    )
  }
}

from NextjsSsrXssConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Next.js SSR 包含未转义的用户输入 $@，可能导致 XSS", 
  source.getNode(), "服务端数据"
```

### 2. GraphQL 注入检测

```ql
/**
 * @name GraphQL 注入
 * @description 检测 GraphQL 查询中的注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @id js/graphql-injection
 * @tags security
 *       external/cwe/cwe-943
 *       graphql
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

class GraphQLInjectionConfig extends TaintTracking::Configuration {
  GraphQLInjectionConfig() { this = "GraphQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // GraphQL resolver 参数
    exists(DataFlow::FunctionNode resolver |
      resolver.getAParameter().getName() in ["args", "variables", "context"] and
      source = resolver.getAParameter().getAPropertyRead()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // 动态 GraphQL 查询构建
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["gql", "graphql", "buildSchema"] and
      sink = call.getArgument(0)
    )
    or
    // 数据库查询在 resolver 中
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in ["query", "find", "findOne"] and
      sink = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // GraphQL 参数验证
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(validate|sanitize|escape).*") and
      node = call
    )
  }
}

from GraphQLInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "GraphQL 查询包含用户输入 $@，可能导致注入攻击", 
  source.getNode(), "resolver 参数"
```

## 客户端安全模式

### 1. 不安全的第三方脚本

```ql
/**
 * @name 不安全的第三方脚本加载
 * @description 检测从不可信源加载的第三方脚本
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @id js/unsafe-third-party-script
 * @tags security
 *       external/cwe/cwe-829
 *       third-party
 */

import javascript

from HTMLElement script, HTMLAttribute src
where
  script.getName() = "script" and
  src = script.getAttributeByName("src") and
  exists(string url |
    url = src.getValue() and
    // 检测不安全的 CDN 或域名
    (
      url.regexpMatch("http://.*") or  // 非 HTTPS
      url.regexpMatch(".*\\.tk/.*") or  // 可疑 TLD
      url.regexpMatch(".*\\.ml/.*") or
      url.regexpMatch(".*\\.ga/.*") or
      url.regexpMatch(".*\\.cf/.*") or
      // 已知不安全的 CDN
      url.matches("*rawgit.com*") or
      url.matches("*gitcdn.xyz*")
    ) and
    // 排除已知安全的 CDN
    not (
      url.matches("*cdnjs.cloudflare.com*") or
      url.matches("*unpkg.com*") or
      url.matches("*jsdelivr.net*") or
      url.matches("*googleapis.com*")
    )
  )

select script, "加载了来自不可信源的第三方脚本: " + src.getValue()
```

### 2. 敏感信息客户端存储

```ql
/**
 * @name 敏感信息客户端存储
 * @description 检测在客户端存储敏感信息的安全风险
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @id js/sensitive-info-client-storage
 * @tags security
 *       external/cwe/cwe-312
 *       client-side
 */

import javascript

predicate isSensitiveData(Expr expr) {
  exists(string value |
    value = expr.(StringLiteral).getValue() and
    (
      value.regexpMatch("(?i).*(password|secret|token|key|api.?key|private.?key).*") or
      value.regexpMatch("[A-Za-z0-9+/]{20,}={0,2}") or  // Base64 编码
      value.regexpMatch("[a-f0-9]{32,}")  // 十六进制编码
    )
  )
  or
  exists(VarAccess var |
    var = expr and
    var.getName().regexpMatch("(?i).*(password|secret|token|key|credential).*")
  )
}

from DataFlow::CallNode call, DataFlow::Node arg
where
  (
    // localStorage.setItem
    call = DataFlow::globalVarRef("localStorage").getAMemberCall("setItem") or
    // sessionStorage.setItem
    call = DataFlow::globalVarRef("sessionStorage").getAMemberCall("setItem") or
    // Cookie 设置
    exists(Assignment assign |
      assign.getLhs().(PropAccess).getBase().(GlobalVarAccess).getName() = "document" and
      assign.getLhs().(PropAccess).getPropertyName() = "cookie" and
      call.asExpr() = assign.getRhs()
    )
  ) and
  arg = call.getAnArgument() and
  isSensitiveData(arg.asExpr())

select call, "在客户端存储敏感信息，可能被恶意脚本访问"
```

## 性能和资源管理

### 1. 内存泄露检测

```ql
/**
 * @name JavaScript 内存泄露风险
 * @description 检测可能导致内存泄露的代码模式
 * @kind problem
 * @problem.severity warning
 * @id js/memory-leak-risk
 * @tags performance
 *       reliability
 */

import javascript

from DataFlow::CallNode call
where
  (
    // 未清理的定时器
    call = DataFlow::globalVarRef(["setTimeout", "setInterval"]).getACall() and
    not exists(DataFlow::CallNode clear |
      clear = DataFlow::globalVarRef(["clearTimeout", "clearInterval"]).getACall() and
      clear.getArgument(0).getALocalSource() = call
    )
  ) or
  (
    // 未移除的事件监听器
    call.getCalleeName() = "addEventListener" and
    not exists(DataFlow::CallNode remove |
      remove.getCalleeName() = "removeEventListener" and
      remove.getArgument(0) = call.getArgument(0) and
      remove.getArgument(1) = call.getArgument(1)
    )
  ) or
  (
    // 未关闭的 WebSocket
    call = DataFlow::globalVarRef("WebSocket").getAnInstantiation() and
    not exists(DataFlow::MethodCallNode close |
      close.getMethodName() = "close" and
      close.getReceiver().getALocalSource() = call
    )
  )

select call, "可能的内存泄露: " + call.getCalleeName() + " 未正确清理"
```

### 2. 大量 DOM 操作检测

```ql
/**
 * @name 循环中的 DOM 操作
 * @description 检测在循环中进行大量 DOM 操作的性能问题
 * @kind problem
 * @problem.severity warning
 * @id js/dom-operations-in-loop
 * @tags performance
 */

import javascript

from LoopStmt loop, DataFlow::CallNode domCall
where
  domCall.getEnclosingStmt().getParent+() = loop and
  (
    // DOM 查询
    domCall = DataFlow::globalVarRef("document").getAMemberCall([
      "getElementById", "getElementsByClassName", "getElementsByTagName",
      "querySelector", "querySelectorAll"
    ]) or
    
    // DOM 修改
    exists(DataFlow::MethodCallNode method |
      method = domCall and
      method.getMethodName() in [
        "appendChild", "removeChild", "insertBefore",
        "setAttribute", "removeAttribute", "addClass", "removeClass"
      ]
    )
  )

select domCall, "在循环中进行 DOM 操作可能影响性能，考虑批量操作或使用 DocumentFragment"
```

## 测试和示例

### 创建测试用例

**测试目录结构：**
```
test/
├── Security/
│   └── CWE-079/
│       └── ReflectedXss/
│           ├── test.js
│           ├── ReflectedXss.qlref
│           └── ReflectedXss.expected
```

**test.js:**
```javascript
const express = require('express');
const app = express();

app.get('/bad', (req, res) => {
    // 应该被检测到的 XSS
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`);
});

app.get('/good', (req, res) => {
    // 不应该被检测到（使用了转义）
    const name = req.query.name;
    const escaped = name.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    res.send(`<h1>Hello ${escaped}</h1>`);
});

// React 组件示例
function BadComponent({ userInput }) {
    // 应该被检测到
    return <div dangerouslySetInnerHTML={{__html: userInput}} />;
}

function GoodComponent({ userInput }) {
    // 不应该被检测到
    return <div>{userInput}</div>;
}
```

### 运行 JavaScript 查询

```bash
# 创建 JavaScript 数据库
codeql database create js-db --language=javascript --source-root=.

# 运行单个查询
codeql query run javascript/ql/src/Security/CWE-079/ReflectedXss.ql \
  --database=js-db

# 运行 JavaScript 安全套件
codeql database analyze js-db \
  javascript/ql/src/codeql-suites/javascript-security-and-quality.qls \
  --format=sarif-latest --output=results.sarif
```

## 最佳实践

### 1. 利用 JavaScript 特定的 API

```ql
import javascript

// 使用 HTTP 框架特定的类
import semmle.javascript.frameworks.Express

from Express::RouteHandler handler
select handler, handler.getARequestExpr()

// 使用 React 特定的类
import semmle.javascript.frameworks.React

from React::Component component
select component, component.getAJSXElement()
```

### 2. 处理 JavaScript 的动态特性

```ql
// 处理动态属性访问
from PropAccess prop
where prop.getPropertyName() = "eval"
select prop, "动态访问 eval 属性"

// 处理模板字符串
from TemplateLiteral tmpl
select tmpl, tmpl.getAnElement()

// 处理异步代码
from AwaitExpr await
select await, await.getOperand()
```

### 3. 框架特定的优化

```ql
// 专门针对 Node.js 的查询
import semmle.javascript.frameworks.NodeJS

from NodeJS::RouteHandler handler
select handler, "Node.js 路由处理器"

// 针对前端框架的查询
import semmle.javascript.frameworks.React

from React::Component component
where component.isClassComponent()
select component, "React 类组件"
```

## 下一步

掌握了 JavaScript 场景应用后，建议继续学习：

1. **[其他语言](10-other-languages.md)** - Go、C/C++、C#、Ruby、Swift、Rust
2. **[开发工具](11-tools.md)** - CodeQL CLI、VS Code 扩展、CI/CD 集成
3. **[最佳实践](12-best-practices.md)** - 查询优化和调试技巧

---

**JavaScript 场景掌握完毕！** 🚀 现在您可以分析各种前端和 Node.js 应用的安全问题了。
