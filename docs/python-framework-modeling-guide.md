# Python 框架 CodeQL 建模指南

> 本指南面向 CodeQL 新人，提供从零开始为 Python 开源框架编写 CodeQL 库的完整教程。

## 目录

1. [前置知识](#1-前置知识)
2. [开发流程 Step by Step](#2-开发流程-step-by-step)
3. [代码模板](#3-代码模板)
4. [测试验证](#4-测试验证)
5. [常见问题与最佳实践](#5-常见问题与最佳实践)

---

## 1. 前置知识

### 1.1 QL 语言基础

在开始建模之前，你需要掌握以下 QL 概念：

| 概念 | 说明 | 示例 |
|------|------|------|
| 谓词（Predicate） | 定义逻辑关系的函数 | `predicate isFlaskApp(Expr e) { ... }` |
| 类（Class） | 描述一组值的类型 | `class FlaskRequest extends DataFlow::Node { ... }` |
| 模块（Module） | 组织代码的命名空间 | `module Flask { ... }` |
| 特征谓词 | 类的成员约束条件 | `MyClass() { this = ... }` |

**推荐学习资源**：
- [QL 语言参考](../codeql/docs/codeql/ql-language-reference/index.rst)
- [CodeQL for Python 指南](../codeql/docs/codeql/codeql-language-guides/codeql-for-python.rst)

### 1.2 API 图概念

API 图是 CodeQL 中用于建模外部库的核心机制：

```
模块导入 → 成员访问 → 调用/实例化 → 返回值/参数
```

**核心方法**：

```ql
// 从模块导入开始
API::moduleImport("flask")
  .getMember("Flask")      // 访问 Flask 类
  .getReturn()             // 获取实例（构造函数返回值）
  .getMember("route")      // 访问 route 方法
  .getACall()              // 获取调用点
```

**详细文档**：参见 [Using API graphs in Python](../codeql/docs/codeql/codeql-language-guides/using-api-graphs-in-python.rst)

### 1.3 数据流和污点分析

| 概念 | 用途 | 关键类 |
|------|------|--------|
| 数据流源（Source） | 数据进入程序的点 | `RemoteFlowSource::Range` |
| 数据流汇（Sink） | 敏感操作点 | 各种 `Concepts` 类 |
| 污点步骤（Taint Step） | 数据传播规则 | `TaintTracking::AdditionalTaintStep` |

---

## 2. 开发流程 Step by Step

### Step 1: 分析目标库的 API 结构

**目标**：了解库的核心类、函数和使用模式

**操作**：
1. 阅读官方文档
2. 查看示例代码
3. 确定需要建模的 API

**示例 - 分析 Flask**：

```python
# Flask 核心 API 分析
from flask import Flask, request, Response, Blueprint

# 1. Flask 应用实例
app = Flask(__name__)

# 2. 路由装饰器
@app.route('/hello')
def hello():
    return 'Hello!'

# 3. 请求对象（用户输入）
name = request.args.get('name')  # 远程流源

# 4. 响应对象
resp = Response('data')  # HTTP 响应
```

**分析清单**：

| 分类 | Flask 中的例子 | 安全相关性 |
|------|----------------|------------|
| 应用入口 | `Flask()` | 配置安全 |
| 用户输入 | `request.args`, `request.form` | 污点源 |
| 响应输出 | `Response()`, 返回值 | XSS 风险 |
| 路由定义 | `@app.route()` | 端点分析 |
| 文件操作 | `send_file()` | 路径遍历 |

### Step 2: 创建 .qll 文件和模块结构

**文件位置**：`codeql/python/ql/lib/semmle/python/frameworks/YourFramework.qll`

**基础模板**：

```ql
/**
 * Provides classes modeling security-relevant aspects of the `yourframework` PyPI package.
 * See https://yourframework.example.com/.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.ApiGraphs
private import semmle.python.frameworks.internal.InstanceTaintStepsHelper

/**
 * Provides models for the `yourframework` PyPI package.
 */
module YourFramework {
  // Step 3-6 的代码将放在这里
}
```

### Step 3: 建模类和函数引用

**模式**：使用 `classRef()` 和 `instance()` 谓词

```ql
module YourFramework {
  /**
   * Provides models for the main application class.
   */
  module App {
    /** Gets a reference to the `yourframework.App` class. */
    API::Node classRef() {
      result = API::moduleImport("yourframework").getMember("App")
    }

    /** Gets a reference to an instance of `yourframework.App`. */
    API::Node instance() { 
      result = classRef().getReturn() 
    }
  }

  /**
   * Provides models for the request object.
   */
  module Request {
    /** Gets a reference to the request object. */
    API::Node request() {
      result = API::moduleImport("yourframework").getMember("request")
    }
  }
}
```

### Step 4: 建模远程流源

**目的**：标识来自用户的不可信输入

```ql
module YourFramework {
  // ... 前面的代码 ...

  /**
   * A source of remote flow from a yourframework request.
   */
  private class YourFrameworkRequestSource extends RemoteFlowSource::Range {
    YourFrameworkRequestSource() { 
      this = Request::request().asSource() 
    }

    override string getSourceType() { 
      result = "yourframework.request" 
    }
  }
}
```

### Step 5: 建模污点传播步骤

**目的**：定义污点如何通过对象属性和方法传播

```ql
module YourFramework {
  // ... 前面的代码 ...

  /**
   * Taint propagation for request object.
   */
  private class RequestTaintSteps extends InstanceTaintStepsHelper {
    RequestTaintSteps() { this = "yourframework.Request" }

    override DataFlow::Node getInstance() { 
      result = Request::request().getAValueReachableFromSource() 
    }

    override string getAttributeName() {
      // 列出所有会传播污点的属性
      result in [
        "args",      // 查询参数
        "form",      // 表单数据
        "data",      // 原始数据
        "cookies",   // Cookie
        "headers"    // 请求头
      ]
    }

    override string getMethodName() { 
      result in ["get_data", "get_json"] 
    }

    override string getAsyncMethodName() { 
      none() 
    }
  }
}
```

### Step 6: 建模安全相关 Sink

**目的**：标识需要安全检查的敏感操作

#### 6.1 HTTP 响应建模

```ql
module YourFramework {
  module Response {
    API::Node classRef() {
      result = API::moduleImport("yourframework").getMember("Response")
    }

    /** A direct instantiation of Response. */
    private class ResponseInstantiation extends Http::Server::HttpResponse::Range, 
        DataFlow::CallCfgNode 
    {
      ResponseInstantiation() { this = classRef().getACall() }

      override DataFlow::Node getBody() {
        result in [this.getArg(0), this.getArgByName("body")]
      }

      override string getMimetypeDefault() { result = "text/html" }

      override DataFlow::Node getMimetypeOrContentTypeArg() { 
        result in [this.getArg(1), this.getArgByName("content_type")]
      }
    }
  }
}
```

#### 6.2 路由处理建模

```ql
module YourFramework {
  /**
   * A route setup in yourframework.
   */
  private class RouteSetup extends Http::Server::RouteSetup::Range, DataFlow::CallCfgNode {
    RouteSetup() {
      this = App::instance().getMember("route").getACall()
    }

    override DataFlow::Node getUrlPatternArg() {
      result in [this.getArg(0), this.getArgByName("path")]
    }

    override Function getARequestHandler() { 
      result.getADecorator().getAFlowNode() = node 
    }

    override string getFramework() { result = "YourFramework" }
  }
}
```

#### 6.3 文件系统访问建模

```ql
module YourFramework {
  /**
   * A call to send_file function.
   */
  private class SendFileCall extends FileSystemAccess::Range, DataFlow::CallCfgNode {
    SendFileCall() {
      this = API::moduleImport("yourframework").getMember("send_file").getACall()
    }

    override DataFlow::Node getAPathArgument() {
      result in [this.getArg(0), this.getArgByName("path")]
    }
  }
}
```

### Step 7: 编写测试用例

详见 [测试验证](#4-测试验证) 章节。

---

## 3. 代码模板

### 3.1 完整框架模板

```ql
/**
 * Provides classes modeling security-relevant aspects of the `myframework` PyPI package.
 * See https://myframework.example.com/.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.ApiGraphs
private import semmle.python.frameworks.internal.InstanceTaintStepsHelper

/**
 * Provides models for the `myframework` PyPI package.
 */
module MyFramework {

  // =========================================================================
  // 模块 1: 核心类建模
  // =========================================================================
  
  module App {
    API::Node classRef() {
      result = API::moduleImport("myframework").getMember("App")
    }

    API::Node instance() { result = classRef().getReturn() }
  }

  // =========================================================================
  // 模块 2: 请求对象建模
  // =========================================================================
  
  API::Node request() {
    result = API::moduleImport("myframework").getMember("request")
  }

  // =========================================================================
  // 模块 3: 远程流源
  // =========================================================================
  
  private class RequestSource extends RemoteFlowSource::Range {
    RequestSource() { this = request().asSource() }
    override string getSourceType() { result = "myframework.request" }
  }

  // =========================================================================
  // 模块 4: 污点传播
  // =========================================================================
  
  private class RequestTaintSteps extends InstanceTaintStepsHelper {
    RequestTaintSteps() { this = "myframework.Request" }
    override DataFlow::Node getInstance() { 
      result = request().getAValueReachableFromSource() 
    }
    override string getAttributeName() { 
      result in ["args", "form", "data", "headers", "cookies"] 
    }
    override string getMethodName() { result in ["get_json"] }
    override string getAsyncMethodName() { none() }
  }

  // =========================================================================
  // 模块 5: 路由建模
  // =========================================================================
  
  private class RouteSetup extends Http::Server::RouteSetup::Range, DataFlow::CallCfgNode {
    RouteSetup() { this = App::instance().getMember("route").getACall() }
    
    override DataFlow::Node getUrlPatternArg() { result = this.getArg(0) }
    override Function getARequestHandler() { 
      result.getADecorator().getAFlowNode() = node 
    }
    override string getFramework() { result = "MyFramework" }
  }

  // =========================================================================
  // 模块 6: HTTP 响应建模
  // =========================================================================
  
  module Response {
    API::Node classRef() {
      result = API::moduleImport("myframework").getMember("Response")
    }

    private class Instantiation extends Http::Server::HttpResponse::Range, 
        DataFlow::CallCfgNode 
    {
      Instantiation() { this = classRef().getACall() }
      override DataFlow::Node getBody() { result = this.getArg(0) }
      override string getMimetypeDefault() { result = "text/html" }
      override DataFlow::Node getMimetypeOrContentTypeArg() { none() }
    }
  }
}
```

### 3.2 远程流源模板

```ql
/**
 * A source of remote user input.
 */
private class MyRemoteSource extends RemoteFlowSource::Range {
  MyRemoteSource() {
    // 方式 1: 直接的 API 节点
    this = API::moduleImport("mylib").getMember("get_user_input").getReturn().asSource()
    or
    // 方式 2: 特定对象的属性
    this = API::moduleImport("mylib").getMember("request").getMember("data").asSource()
    or
    // 方式 3: 函数参数
    exists(Function f |
      f = any(MyRouteSetup rs).getARequestHandler() and
      this.asExpr() = f.getArg(_).asName().getAFlowNode()
    )
  }

  override string getSourceType() { result = "mylib.user_input" }
}
```

### 3.3 HTTP 响应模板

```ql
/**
 * Models for HTTP responses.
 */
module Response {
  abstract class InstanceSource extends Http::Server::HttpResponse::Range, DataFlow::Node { }

  /** Direct class instantiation. */
  private class DirectInstantiation extends InstanceSource, DataFlow::CallCfgNode {
    DirectInstantiation() { 
      this = API::moduleImport("mylib").getMember("Response").getACall() 
    }

    override DataFlow::Node getBody() {
      result in [this.getArg(0), this.getArgByName("body"), this.getArgByName("content")]
    }

    override string getMimetypeDefault() { result = "text/html" }

    override DataFlow::Node getMimetypeOrContentTypeArg() {
      result in [this.getArg(1), this.getArgByName("mimetype"), this.getArgByName("content_type")]
    }
  }

  /** Helper function return value. */
  private class HelperFunctionResponse extends InstanceSource, DataFlow::CallCfgNode {
    HelperFunctionResponse() {
      this = API::moduleImport("mylib").getMember("make_response").getACall()
    }

    override DataFlow::Node getBody() { result = this.getArg(0) }
    override string getMimetypeDefault() { result = "text/html" }
    override DataFlow::Node getMimetypeOrContentTypeArg() { none() }
  }
}
```

### 3.4 路由处理模板

```ql
/**
 * Route setup pattern.
 */
abstract class MyRouteSetup extends Http::Server::RouteSetup::Range {
  override string getFramework() { result = "MyFramework" }
}

/** Decorator-based route: @app.route('/path') */
private class DecoratorRoute extends MyRouteSetup, DataFlow::CallCfgNode {
  DecoratorRoute() {
    this = API::moduleImport("mylib").getMember("App").getReturn()
           .getMember("route").getACall()
  }

  override DataFlow::Node getUrlPatternArg() {
    result in [this.getArg(0), this.getArgByName("rule")]
  }

  override Function getARequestHandler() { 
    result.getADecorator().getAFlowNode() = node 
  }
}

/** Explicit route registration: app.add_route('/path', handler) */
private class ExplicitRoute extends MyRouteSetup, DataFlow::CallCfgNode {
  ExplicitRoute() {
    this = API::moduleImport("mylib").getMember("App").getReturn()
           .getMember("add_route").getACall()
  }

  override DataFlow::Node getUrlPatternArg() { result = this.getArg(0) }

  override Function getARequestHandler() {
    exists(DataFlow::LocalSourceNode src |
      src.flowsTo(this.getArg(1)) and
      src.asExpr() = result.getDefinition()
    )
  }
}
```

---

## 4. 测试验证

### 4.1 测试文件组织结构

```
codeql/python/ql/test/library-tests/frameworks/myframework/
├── ConceptsTest.expected      # 概念测试期望结果
├── ConceptsTest.ql            # 概念测试查询
├── InlineTaintTest.expected   # 污点测试期望结果
├── InlineTaintTest.ql         # 污点测试查询
├── basic_test.py              # 基础功能测试
├── routing_test.py            # 路由测试
├── taint_test.py              # 污点传播测试
└── response_test.py           # 响应测试
```

### 4.2 内联注释测试语法

在 Python 测试文件中使用特殊注释标记期望结果：

```python
from myframework import App, request

app = App(__name__)

@app.route("/test/<name>")  # $routeSetup="/test/<name>"
def test_handler(name):  # $requestHandler routedParameter=name
    # 标记污点源
    user_input = request.args.get('key')  # $ tainted
    
    # 标记 HTTP 响应
    return "Hello " + name  # $HttpResponse
```

**常用注释标记**：

| 标记 | 用途 | 示例 |
|------|------|------|
| `# $ tainted` | 标记污点数据 | `request.args  # $ tainted` |
| `# $routeSetup="..."` | 标记路由设置 | `@app.route("/")  # $routeSetup="/"` |
| `# $requestHandler` | 标记请求处理函数 | `def handler():  # $requestHandler` |
| `# $HttpResponse` | 标记 HTTP 响应 | `return data  # $HttpResponse` |
| `# $routedParameter=name` | 标记路由参数 | `def f(name):  # $routedParameter=name` |
| `# $ MISSING: tainted` | 标记预期但缺失的结果 | 用于已知限制 |
| `# $ SPURIOUS: ...` | 标记误报 | 用于已知误报 |

### 4.3 测试查询文件

**ConceptsTest.ql** - 测试安全概念识别：

```ql
import python
import experimental.meta.ConceptsTest

class DedicatedTest extends DedicatedResponseTest {
  DedicatedTest() { this = "response_test.py" }

  override predicate isDedicatedFile(File file) { 
    file.getShortName() = this 
  }
}
```

**InlineTaintTest.ql** - 测试污点传播：

```ql
import experimental.meta.InlineTaintTest
import MakeInlineTaintTest<TestTaintTrackingConfig>
```

### 4.4 编写测试用例示例

**taint_test.py**：

```python
from myframework import App, request

app = App(__name__)

# 辅助函数（测试框架使用）
def ensure_tainted(*args):
    pass

def ensure_not_tainted(*args):
    pass

@app.route("/test/<name>/<int:id>")  # $routeSetup="/test/<name>/<int:id>"
def test_route_params(name, id):  # $requestHandler routedParameter=name routedParameter=id
    # 路由参数应该被标记为污点
    ensure_tainted(name, id)  # $ tainted

@app.route("/test_request")  # $routeSetup="/test_request"
def test_request_taint():  # $requestHandler
    # 测试请求对象的各种属性
    ensure_tainted(
        request.args,           # $ tainted
        request.args.get('k'),  # $ tainted
        request.form,           # $ tainted
        request.data,           # $ tainted
        request.headers,        # $ tainted
        request.cookies,        # $ tainted
    )
    
    # 非污点数据
    ensure_not_tainted(
        request.method,  # 方法名不是用户可控的
    )
```

**response_test.py**：

```python
from myframework import App, Response, make_response

app = App(__name__)

@app.route("/html")  # $routeSetup="/html"
def html_response():  # $requestHandler
    return "<h1>Hello</h1>"  # $HttpResponse mimetype=text/html

@app.route("/json")  # $routeSetup="/json"
def json_response():  # $requestHandler
    resp = Response('{"key": "value"}', mimetype='application/json')
    return resp  # $HttpResponse mimetype=application/json

@app.route("/make")  # $routeSetup="/make"
def make_resp():  # $requestHandler
    return make_response("data")  # $HttpResponse
```

### 4.5 运行测试命令

```bash
# 进入 CodeQL 仓库目录
cd codeql

# 运行特定框架的测试
codeql test run python/ql/test/library-tests/frameworks/myframework/

# 运行所有 Python 框架测试
codeql test run python/ql/test/library-tests/frameworks/

# 更新期望结果（当你确认新结果正确时）
codeql test run --update-expected-output python/ql/test/library-tests/frameworks/myframework/
```

### 4.6 测试期望文件格式

`.expected` 文件包含查询的期望输出：

```
| basic_test.py:10:5:10:15 | request.args | flask.request |
| basic_test.py:15:1:15:20 | @app.route("/") | /  |
```

---

## 5. 常见问题与最佳实践

### 5.1 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 模块 | PascalCase，与库名对应 | `module Flask { }` |
| 子模块 | PascalCase，描述功能 | `module Response { }` |
| 谓词 | camelCase | `classRef()`, `instance()` |
| 类 | PascalCase | `class FlaskRequestSource` |
| 私有元素 | 使用 `private` 关键字 | `private class ...` |

### 5.2 模块组织原则

```ql
module MyFramework {
  // 1. 首先定义核心类/对象的引用
  module App { ... }
  module Request { ... }
  module Response { ... }
  
  // 2. 然后定义便捷谓词
  API::Node request() { ... }
  
  // 3. 接着定义远程流源
  private class RequestSource extends RemoteFlowSource::Range { ... }
  
  // 4. 然后是污点步骤
  private class TaintSteps extends InstanceTaintStepsHelper { ... }
  
  // 5. 最后是安全概念实现
  private class RouteSetup extends Http::Server::RouteSetup::Range { ... }
  private class HttpResponse extends Http::Server::HttpResponse::Range { ... }
}
```

### 5.3 性能考虑

**避免**：
```ql
// 不好：在大型代码库中会很慢
class BadPattern extends DataFlow::Node {
  BadPattern() {
    exists(Call c | 
      c.getFunc().(Attribute).getName() = "dangerous" and
      this.asExpr() = c.getArg(0)
    )
  }
}
```

**推荐**：
```ql
// 好：使用 API 图限制搜索范围
class GoodPattern extends DataFlow::Node {
  GoodPattern() {
    this = API::moduleImport("mylib")
           .getMember("dangerous")
           .getACall()
           .getArg(0)
  }
}
```

### 5.4 处理多种导入方式

```ql
API::Node getMyClass() {
  // 方式 1: from mylib import MyClass
  result = API::moduleImport("mylib").getMember("MyClass")
  or
  // 方式 2: from mylib.submodule import MyClass
  result = API::moduleImport("mylib").getMember("submodule").getMember("MyClass")
  or
  // 方式 3: 通过应用实例访问
  result = App::instance().getMember("MyClass")
}
```

### 5.5 处理已知限制

```python
# 测试文件中标记已知限制
def known_limitation():
    # 当前不支持动态属性访问
    attr_name = "args"
    value = getattr(request, attr_name)  # $ MISSING: tainted
```

### 5.6 调试技巧

**使用 Quick Evaluation**：
1. 在 VS Code 中打开 `.qll` 文件
2. 选中要测试的谓词
3. 右键选择 "CodeQL: Quick Evaluation"

**编写调试查询**：

```ql
// debug.ql - 用于调试的临时查询
import python
import semmle.python.frameworks.MyFramework

from DataFlow::Node node
where node = MyFramework::Request::request().asSource()
select node, "Found request source"
```

### 5.7 常见错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| 没有匹配结果 | API 路径错误 | 检查 `getMember` 参数是否正确 |
| 太多结果 | 匹配条件太宽松 | 添加更多约束条件 |
| 测试失败 | 期望文件过时 | 运行 `--update-expected-output` |
| 编译错误 | 类型不匹配 | 检查继承关系和类型约束 |

---

## 附录：参考资源

### 官方文档
- [CodeQL for Python](https://codeql.github.com/docs/codeql-language-guides/codeql-for-python/)
- [Using API graphs](https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/)
- [Customizing library models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-python/)

### 示例库文件
- `Flask.qll` - Web 框架完整示例
- `Django.qll` - 大型框架示例
- `Requests.qll` - HTTP 客户端示例
- `SqlAlchemy.qll` - ORM 示例

### 测试示例
- `codeql/python/ql/test/library-tests/frameworks/flask/`
- `codeql/python/ql/test/library-tests/frameworks/django/`

