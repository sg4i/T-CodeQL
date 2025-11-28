# AI 大模型 Python CodeQL 库生成工作流

> 本文档定义了 AI 大模型自动化生成 Python 框架 CodeQL 库的完整工作流，包括分析提示词、生成步骤和验证流程。

## 目录

1. [工作流概述](#1-工作流概述)
2. [Phase 1: 库分析](#2-phase-1-库分析)
3. [Phase 2: 结构生成](#3-phase-2-结构生成)
4. [Phase 3: 安全建模](#4-phase-3-安全建模)
5. [Phase 4: 测试生成](#5-phase-4-测试生成)
6. [Phase 5: 验证与修复](#6-phase-5-验证与修复)
7. [完整工作流示例](#7-完整工作流示例)

---


## 项目预处理与API提取

### 方式一：Script + AST

- 输入：
  - GitHub地址

- 动作：
  - git clone 下载源码。
  - AST解析（关键补充）：编写Python脚本（基于 ast 或 tree-sitter），遍历所有文件，提取Public API（公共接口）。
  - 对于库项目：提取所有 __init__.py 导出的类和函数，以及不以 _ 开头的公共方法。
  - 提取内容：函数名、参数列表、Docstring、函数体源码（截取）、装饰器。
  - 依赖分析：解析 requirements.txt/pyproject.toml，建立已知第三方库列表。

- 输出：
  - project_api_surface.json（包含所有潜在的Source入口和Sink候选点）。


### 方式二：LLM

```text
你是一名顶级的代码安全架构师，拥有超过20年的静态分析（SAST）工具设计经验。你的核心专长是为流行的编程语言和框架构建精确的污点分析模型。

开源项目地址为： {repository_url}
项目代码本地路径为: {repository_code_path}

## 核心使命 (Your Mission):
你的任务分析开源框架的公开API，并为开发者构建一个用于污点分析的“安全模型”。这个模型需要明确地识别并列出开源框架提供给开发者的、充当以下三种角色的核心API：

- Sources (污染源)
- Sinks (污染汇聚点)
- Sanitizers (净化器)

请基于你对开源框架的源代码分析、公开的文档完成这次建模。

## 核心定义 (Core Definitions):

- “Source” (污染源): 指框架提供的、用于引入外部不可信数据的API。这些数据通常来自用户的直接或间接输入。通常包括但不限于：
  - HTTP请求的参数、Headers、Body、Cookies
  - 从文件系统读取的内容
  - 网络套接字（Socket）接收的数据
  - 命令行参数
  - 环境变量
  - 任何第三方API的返回值
  - 数据库查询结果

- “Sink” (污染汇聚点): 指框架提供的、用于执行潜在危险操作的API。当一个Source的污点数据未经处理就流入Sink时，就可能触发漏洞。

关键词： 执行、渲染、查询、写入、重定向、反序列化、运行命令、操作文件路径。

- “Sanitizer” (净化器): 指框架提供的、用于验证、清理或编码不可信数据，使其变得安全的API。

关键词： 转义、编码、验证、清理、过滤、安全地加入。


注意：
- 你的分析必须精准、严格，避免将内部生成的、可信的数据（如常量、内部函数计算结果、安全的session信息等）误判为Source。

## 思维链与分析框架 (Chain of Thought & Analysis Framework)
为了系统性地完成建模，请严格遵循以下三个独立的分析框架，分别对Source, Sink, 和 Sanitizer 进行思考和识别。

### 识别 Sources

- 扫描API类别： 重点分析与HTTP请求处理、配置加载、文件操作相关的模块。
- 定位引入点： 寻找那些设计用来从外部世界（如浏览器、操作系统、文件系统）获取数据的函数或对象属性。
- 确认不可信性： 判断这些数据是否天然不可信（即开发者无法控制其内容）。例如，request.args 总是不可信的。
- 提取并分类： 记录下该API的完整限定名、所属模块、功能描述，并将其分类（例如：http_request_parameter, file_content, environment_variable）。

### 识别 Sinks

- 扫描API类别： 重点分析与模板渲染、数据库交互、命令执行、文件写入、HTTP响应相关的模块。
- 定位危险操作： 寻找那些接收数据并执行敏感操作的函数。
- 确认潜在风险： 判断如果输入数据是恶意的，该操作是否可能导致安全问题（如XSS, SQLi, RCE, Path Traversal）。例如，render_template_string 如果接收未转义的用户输入，就会导致XSS。
- 提取并分类： 记录下该API的完整限定名、所属模块、功能描述，并将其分类（例如：xss_sink, command_injection_sink, path_traversal_sink）。

### 识别 Sanitizers

- 扫描API类别： 重点分析与数据处理、模板系统、安全工具相关的模块（例如 markupsafe）。
- 定位净化功能： 寻找那些设计用来对数据进行编码、转义或验证的函数。
- 确认安全效果： 判断该函数的主要目的是否是消除数据中的潜在威胁。例如，escape() 的核心目的就是防止XSS。
- 提取并分类： 记录下该API的完整限定名、所属模块、功能描述，并将其分类（例如：xss_sanitizer, sql_sanitizer）。

## 输出格式要求

输出JSON格式为：

{
  apis: List[Object]
}

apis中Object字段定义如下：

| 字段路径 (Field Path) | 类型 | 业务含义 & 描述 | 示例 (Example Value) |
| :--- | :--- | :--- | :--- |
| `api_qualified_name` | String | **[必需]** API的完整限定名，作为分析结果的唯一标识符，与输入数据对应。 | `"flask.request.form"` |
| `analysis_summary` | Object | **[必需]** 一个顶层的、布尔型的快速摘要，便于程序进行快速过滤和分类。 | `{...}` |
| `analysis_summary.is_source` | Boolean | **[必需]** 判断该API是否是一个Source（污染源）。 | `true` |
| `analysis_summary.is_sink` | Boolean | **[必需]** 判断该API是否是一个Sink（污染汇聚点）。 | `false` |
| `analysis_summary.is_sanitizer` | Boolean | **[必需]** 判断该API是否是一个Sanitizer（净化器）。 | `false` |
| `source_details` | Object \| Null | 如果 `is_source` 为 `true`，则提供该Source角色的详细信息；否则为 `null`。 | `{...}` |
| `source_details.source_type` | String | **[条件必需]** 对Source类型的具体分类。 | `"http_request_form_data"` |
| `source_details.description` | String | **[条件必需]** LLM生成的关于此Source功能的自然语言描述。 | `"该API属性用于访问通过HTTP POST或PUT请求提交的表单数据。"` |
| `source_details.risk_level` | Enum | **[条件必需]** 对该Source引入数据潜在风险的评估。值域: `"High"`, `"Medium"`, `"Low"`。 | `"High"` |
| `source_details.confidence` | Float | **[条件必需]** LLM对其Source判断的置信度，范围在 0.0 到 1.0 之间。 | `0.99` |
| `source_details.reasoning` | String | **[条件必需]** LLM依据思维链（CoT）得出的详细、分步的推理过程。 | `"基于对Flask框架的知识，`request.form`是处理用户表单提交的核心接口..."` |
| `sink_details` | Object \| Null | 如果 `is_sink` 为 `true`，则提供该Sink角色的详细信息；否则为 `null`。 | `null` |
| `sink_details.sink_type` | String | **[条件必需]** 对Sink类型的具体分类。 | `"xss_sink"`, `"path_traversal_sink"` |
| `sink_details.description` | String | **[条件必需]** LLM生成的关于此Sink功能的自然语言描述。 | `"该函数用于渲染模板字符串，若输入包含用户数据则可能导致SSTI。"` |
| `sink_details.risk_level` | Enum | **[条件必需]** 对该Sink执行危险操作的风险评估。值域: `"High"`, `"Medium"`, `"Low"`。 | `"High"` |
| `sink_details.confidence` | Float | **[条件必需]** LLM对其Sink判断的置信度，范围在 0.0 到 1.0 之间。 | `0.95` |
| `sink_details.reasoning` | String | **[条件必需]** LLM关于Sink判断的详细推理过程。 | `"该函数内部调用了`os.system`，并且其参数可被外部控制..."` |
| `sanitizer_details` | Object \| Null | 如果 `is_sanitizer` 为 `true`，则提供该Sanitizer角色的详细信息；否则为 `null`。 | `null` |
| `sanitizer_details.sanitizer_type` | String | **[条件必需]** 对Sanitizer净化类型的具体分类。 | `"xss_sanitizer"`, `"sql_injection_sanitizer"` |
| `sanitizer_details.description` | String | **[条件必需]** LLM生成的关于此Sanitizer功能的自然语言描述。 | `"该函数通过HTML实体编码来净化输入，有效防止XSS攻击。"` |
| `sanitizer_details.confidence` | Float | **[条件必需]** LLM对其Sanitizer判断的置信度，范围在 0.0 到 1.0 之间。 | `0.98` |
| `sanitizer_details.reasoning` | String | **[条件必需]** LLM关于Sanitizer判断的详细推理过程。 | `"函数的核心逻辑是调用`markupsafe.escape`，这是一个已知的XSS净化器..."` |
| `taint_flow_summary` | Object | **[必需]** 对API内部污点流模式的总结，是污点分析建模的核心。 | `{...}` |
| `taint_flow_summary.flow_pattern` | Enum | **[必需]** LLM对函数污点流模式的最终判断。值域: `"data_source"`, `"data_sink"`, `"propagator"`, `"sanitizer"`, `"complex"`, `"no_flow"`。 | `"data_source"` |
| `taint_flow_summary.description` | String | **[必需]** 对`flow_pattern`的自然语言解释。 | `"此API是一个纯粹的数据源，它自身不接收参数，其返回值是污点。"` |
| `taint_flow_summary.tainted_return` | Boolean | **[必需]** 判断该API的返回值是否被污染或本身就是污点。 | `true` |
| `taint_flow_summary.tainted_parameters`| List<Object> | **[必需]** 一个列表，详细说明哪些参数是污点入口以及它们如何影响函数。若无则为空列表 `[]`。 | `[]` |
| `taint_flow_summary.tainted_parameters[].name` | String | **[条件必需]** 被污染的参数名称。 | `"command"` |
| `taint_flow_summary.tainted_parameters[].index` | Integer | **[条件必需]** 被污染参数的位置索引（从0开始，忽略`self`）。 | `0` |
| `taint_flow_summary.tainted_parameters[].reason` | String | **[条件必需]** 解释为什么这个参数是污点入口。 | `"此参数直接传递给了内部的`os.system`调用，构成了命令注入的Sink点。"` |

重要指令： 你的回答必须且只能是一个单一、完整的JSON对象。严禁在JSON代码块的前后包含任何Markdown标记（如 ```json）、介绍性文字或任何形式的解释。你的整个输出就是一个纯粹的JSON文本。

```


## 难点

###动态特性与元编程 (Metaprogramming)

问题描述：
Python 高级库（如 SQLAlchemy, Django, Pydantic）大量使用元编程。

场景 A (动态属性)：setattr(self, 'method', func) —— AST 根本看不到这个方法定义。

场景 B (装饰器副作用)：

python
@validate_request
def process(data): ...
process 函数的签名在运行时被 validate_request 修改了（例如增加了一个参数）。AST 看到的签名与实际运行时不符，导致生成的 Argument[n] 索引错误。

**场景 C (kwargs 爆炸)：

python
def wrapper(**kwargs):
    target_func(**kwargs)
AST 只能看到 kwargs，不知道里面具体传递了哪些参数。

落地阻碍：
CodeQL 的 Data Flow 极其依赖精确的参数位置。如果无法解析 **kwargs 或装饰器后的真实签名，污点链路会断开。

解决方案：

LLM 增强分析：把装饰器源码也喂给 LLM，问它：“这个装饰器是否改变了参数顺序或注入了新参数？”

放弃完美，追求覆盖：对于 **kwargs，在 CodeQL 中采用模糊匹配策略（Taint 所有参数），虽然会增加误报，但保证了不漏报。

### 类型推断缺失 (Type Inference)

问题描述：
CodeQL Java/C# 建模很准是因为有强类型。Python 是鸭子类型：

python
def save_data(obj):
    obj.write()
AST 不知道 obj 是什么类型，也就不知道 obj.write 到底是调用了 File.write (Sink) 还是 Log.write (Safe)。

落地阻碍：
没有类型信息，LLM 很难判断 obj.method() 是否危险，容易产生幻觉或大量误报。

解决方案：

集成 Type Checker：在 AST 脚本阶段，不仅用 ast 库，建议引入 pyright 或 jedi 的静态分析能力，尽可能解析出变量的类型，填入 JSON 的 annotation 字段。

LLM 上下文增强：将 obj 的实例化代码（如果在同一文件）一起提取给 LLM


### Web 框架的多样性 (Source 识别难)

问题描述：
Source（污点入口）的识别高度依赖框架：

Flask: @app.route

Django: urls.py 里的正则匹配 + views.py 的 request 参数。

FastAPI: 类型提示为 Pydantic 模型的参数。

Lambda: event 字典。

落地阻碍：
如果写死 @app.route，方案就不“通用”了。每当遇到新框架（如 Sanic, Tornado），脚本就得重写。

解决方案：

配置驱动 (Config-Driven)：将框架特征提取到配置文件中，而不是硬编码在脚本里。

LLM 启发式发现：

先提取所有装饰器列表。

让 LLM 分析：“这些装饰器中，哪些看起来像是 Web 路由注册？”（LLM 具有这种通用知识）。

解决：“分层建模” 策略：

Level 1: 基础库通用建模 (80% 的库)
目标：NumPy, Requests, Utils 类库。

策略：重点关注 Public API 的 Taint Summary (Arg -> Return)。

通用性：极高。只要是函数调用，逻辑都一样。

Level 2: Web/RPC 框架专用建模 (20% 的框架)
目标：Django, Flask, FastAPI。

策略：重点关注 Source 识别。

通用性：低。需要为前 10 大流行框架编写专门的“特征提取插件” (Plugin)，注入到 AST 脚本中。

改进建议：引入“预扫描”步骤
在你的技术方案中，在“获取源码”和“提取 Source/Sink”之间，增加一步：

步骤 1.5：项目特征指纹识别

动作：扫描依赖文件，识别项目使用了什么框架（Django? Flask? Pure Lib?）。

输出：framework_type: "flask"。

作用：指导 AST 脚本加载对应的提取策略（例如：如果是 Flask，重点找装饰器；如果是 Django，重点找 def get/post(request)）。

“通用架构 + 插件化适配 + LLM 兜底语义” 

## 1. 工作流概述

### 1.1 输入与输出

**输入**：
- Python 开源库名称（如 `flask`, `fastapi`, `bottle`）
- 库的 PyPI 页面或 GitHub 仓库地址
- （可选）库的官方文档链接

**输出**：
- 完整的 `.qll` 库文件
- 对应的测试 Python 文件
- 测试查询文件 (`.ql`)
- 测试期望文件 (`.expected`)

### 1.2 工作流阶段

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: 库分析                                                 │
│  ├── 识别核心类和函数                                            │
│  ├── 分析 HTTP 请求/响应模式                                     │
│  └── 识别安全敏感 API                                           │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2: 结构生成                                               │
│  ├── 生成模块骨架                                                │
│  ├── 生成类引用谓词                                              │
│  └── 生成实例谓词                                                │
├─────────────────────────────────────────────────────────────────┤
│  Phase 3: 安全建模                                               │
│  ├── 生成远程流源                                                │
│  ├── 生成污点传播步骤                                            │
│  └── 生成安全 Sink                                               │
├─────────────────────────────────────────────────────────────────┤
│  Phase 4: 测试生成                                               │
│  ├── 生成 Python 测试代码                                        │
│  ├── 添加内联注释标记                                            │
│  └── 生成测试查询文件                                            │
├─────────────────────────────────────────────────────────────────┤
│  Phase 5: 验证与修复                                             │
│  ├── 编译检查                                                    │
│  ├── 运行测试                                                    │
│  └── 修复问题并迭代                                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Phase 1: 库分析

### 2.1 分析提示词

```markdown
## 任务：分析 Python 库的安全相关 API

请分析以下 Python 库，提取 CodeQL 建模所需的信息：

**库名称**: {library_name}
**文档链接**: {doc_url}
**源码链接**: {source_url}

### 请提供以下分析结果：

#### 1. 库类型分类
- [ ] Web 框架 (如 Flask, Django)
- [ ] HTTP 客户端 (如 requests)
- [ ] 数据库 ORM (如 SQLAlchemy)
- [ ] 模板引擎 (如 Jinja2)
- [ ] 序列化库 (如 pickle, yaml)
- [ ] 其他: ___

#### 2. 核心类和函数列表
请列出需要建模的主要类和函数：

| 类/函数名 | 导入路径 | 用途 | 安全相关性 |
|-----------|----------|------|------------|
| | | | |

#### 3. 用户输入点（远程流源）
识别所有可能包含用户可控数据的 API：

| API | 获取方式 | 数据类型 | 示例代码 |
|-----|----------|----------|----------|
| | | | |

#### 4. HTTP 请求/响应模式
如果是 Web 框架，请分析：

**路由定义方式**:
- 装饰器模式: @app.route('/path')
- 显式注册: app.add_route('/path', handler)
- 类视图: class MyView(View)

**请求处理器签名**:
```python
def handler(request, param1, param2):
    pass
```

**响应创建方式**:
- 直接返回字符串
- Response 类实例化
- 辅助函数 (make_response, jsonify)

#### 5. 安全敏感操作
识别可能导致安全漏洞的 API：

| 操作类型 | API | 危险参数 | 对应 CWE |
|----------|-----|----------|----------|
| SQL 执行 | | | CWE-089 |
| 命令执行 | | | CWE-078 |
| 文件访问 | | | CWE-022 |
| 重定向 | | | CWE-601 |
| 模板渲染 | | | CWE-094 |

#### 6. 依赖关系
列出该库依赖的其他已建模的库：
- [ ] Werkzeug
- [ ] Jinja2
- [ ] SQLAlchemy
- [ ] 其他: ___
```

### 2.2 分析输出示例（以 Bottle 为例）

```markdown
## Bottle 库分析结果

### 1. 库类型：Web 框架

### 2. 核心类和函数

| 类/函数名 | 导入路径 | 用途 | 安全相关性 |
|-----------|----------|------|------------|
| Bottle | bottle.Bottle | 应用实例 | 低 |
| request | bottle.request | 请求对象 | 高-用户输入 |
| response | bottle.response | 响应对象 | 中-输出 |
| template | bottle.template | 模板渲染 | 高-注入风险 |
| redirect | bottle.redirect | 重定向 | 高-开放重定向 |
| static_file | bottle.static_file | 静态文件 | 高-路径遍历 |

### 3. 用户输入点

| API | 获取方式 | 数据类型 | 示例代码 |
|-----|----------|----------|----------|
| request.query | 属性访问 | FormsDict | `request.query.name` |
| request.forms | 属性访问 | FormsDict | `request.forms.get('key')` |
| request.params | 属性访问 | FormsDict | `request.params['key']` |
| request.json | 属性访问 | dict/list | `request.json` |
| request.body | 属性访问 | BytesIO | `request.body.read()` |
| request.cookies | 属性访问 | dict | `request.cookies.get('session')` |
| request.headers | 属性访问 | HeaderDict | `request.headers['X-Custom']` |

### 4. HTTP 请求/响应模式

**路由定义**:
```python
@app.route('/hello/<name>')
def hello(name):
    return f'Hello {name}'

app.route('/api', method='POST', callback=handler)
```

**响应方式**:
```python
# 直接返回
return "Hello"
return {'key': 'value'}  # 自动 JSON

# Response 对象
from bottle import HTTPResponse
return HTTPResponse(body='data', status=200)

# 辅助函数
from bottle import template
return template('index', data=data)
```

### 5. 安全敏感操作

| 操作类型 | API | 危险参数 | 对应 CWE |
|----------|-----|----------|----------|
| 文件访问 | static_file | filename | CWE-022 |
| 重定向 | redirect | url | CWE-601 |
| 模板渲染 | template | template_name | CWE-094 |

### 6. 依赖关系
- 无外部依赖（自包含框架）
```

---

## 3. Phase 2: 结构生成

### 3.1 结构生成提示词

```markdown
## 任务：生成 CodeQL 库模块结构

基于以下库分析结果，生成 CodeQL 库的模块骨架代码：

**库分析结果**: 
{phase1_output}

### 生成要求：

1. **文件头部**
   - 标准文档注释
   - 所需的 import 语句

2. **模块结构**
   - 顶层模块命名（PascalCase，与库名对应）
   - 子模块划分（按功能分组）

3. **类引用谓词**
   - 为每个需要建模的类生成 `classRef()` 谓词
   - 处理多种导入方式
   - 支持 ModelOutput 扩展

4. **实例谓词**
   - 为每个类生成 `instance()` 谓词

### 输出格式：

请生成完整的 .qll 文件代码，使用以下结构：

```ql
/**
 * Provides classes modeling security-relevant aspects of the `{library_name}` PyPI package.
 * See {doc_url}.
 */

private import python
// ... 其他必要的 import

module {ModuleName} {
  // 子模块和谓词定义
}
```
```

### 3.2 结构生成输出模板

```ql
/**
 * Provides classes modeling security-relevant aspects of the `bottle` PyPI package.
 * See https://bottlepy.org/.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.ApiGraphs
private import semmle.python.frameworks.internal.InstanceTaintStepsHelper

/**
 * Provides models for the `bottle` PyPI package.
 * See https://bottlepy.org/.
 */
module Bottle {

  // =========================================================================
  // 应用实例建模
  // =========================================================================
  
  /**
   * Provides models for bottle applications (instances of the `bottle.Bottle` class).
   */
  module BottleApp {
    /** Gets a reference to the `bottle.Bottle` class. */
    API::Node classRef() {
      result = API::moduleImport("bottle").getMember("Bottle")
    }

    /** Gets a reference to an instance of `bottle.Bottle`. */
    API::Node instance() { result = classRef().getReturn() }
  }

  // =========================================================================
  // 请求对象建模
  // =========================================================================
  
  /** Gets a reference to the `bottle.request` object. */
  API::Node request() {
    result = API::moduleImport("bottle").getMember("request")
  }

  // =========================================================================
  // 响应对象建模
  // =========================================================================
  
  /**
   * Provides models for the `bottle.HTTPResponse` class.
   */
  module Response {
    /** Gets a reference to the `bottle.HTTPResponse` class. */
    API::Node classRef() {
      result = API::moduleImport("bottle").getMember("HTTPResponse")
    }
  }

  // =========================================================================
  // 后续 Phase 将添加：
  // - 远程流源
  // - 污点传播步骤
  // - 路由建模
  // - HTTP 响应建模
  // - 安全 Sink
  // =========================================================================
}
```

---

## 4. Phase 3: 安全建模

### 4.1 远程流源生成提示词

```markdown
## 任务：生成远程流源建模代码

基于库分析中识别的用户输入点，生成 CodeQL 远程流源代码：

**用户输入点列表**:
{user_input_apis}

### 生成要求：

1. 继承 `RemoteFlowSource::Range` 类
2. 在特征谓词中使用 API 图匹配输入点
3. 实现 `getSourceType()` 返回描述性字符串

### 代码模板：

```ql
/**
 * A source of remote flow from a {library_name} request.
 */
private class {ClassName}Source extends RemoteFlowSource::Range {
  {ClassName}Source() { 
    this = {api_path}.asSource() 
  }

  override string getSourceType() { 
    result = "{library_name}.{source_description}" 
  }
}
```
```

### 4.2 污点传播步骤生成提示词

```markdown
## 任务：生成污点传播步骤代码

基于请求对象的属性和方法，生成污点传播建模代码：

**请求对象信息**:
- 属性列表: {attribute_list}
- 方法列表: {method_list}

### 生成要求：

1. 继承 `InstanceTaintStepsHelper` 类
2. 实现 `getInstance()` 返回被污染的实例
3. 实现 `getAttributeName()` 列出污点属性
4. 实现 `getMethodName()` 列出污点方法
5. 实现 `getAsyncMethodName()` 列出异步方法（如无则返回 none()）

### 代码模板：

```ql
private class {ClassName}TaintSteps extends InstanceTaintStepsHelper {
  {ClassName}TaintSteps() { this = "{library_name}.Request" }

  override DataFlow::Node getInstance() { 
    result = request().getAValueReachableFromSource() 
  }

  override string getAttributeName() {
    result in [
      // 列出所有污点属性
      "query", "forms", "params", "json", "body", "cookies", "headers"
    ]
  }

  override string getMethodName() { 
    result in ["get_json", "read"] 
  }

  override string getAsyncMethodName() { 
    none() 
  }
}
```
```

### 4.3 路由建模生成提示词

```markdown
## 任务：生成路由处理建模代码

基于库的路由定义方式，生成路由建模代码：

**路由模式**:
- 装饰器: {decorator_pattern}
- 显式注册: {explicit_pattern}
- URL 参数格式: {url_param_format}

### 生成要求：

1. 继承 `Http::Server::RouteSetup::Range`
2. 实现 `getUrlPatternArg()` 获取 URL 模式
3. 实现 `getARequestHandler()` 获取处理函数
4. 实现 `getARoutedParameter()` 识别路由参数
5. 实现 `getFramework()` 返回框架名称

### 代码模板：

```ql
abstract class {ClassName}RouteSetup extends Http::Server::RouteSetup::Range {
  override string getFramework() { result = "{FrameworkName}" }
}

private class {ClassName}DecoratorRoute extends {ClassName}RouteSetup, DataFlow::CallCfgNode {
  {ClassName}DecoratorRoute() {
    this = {app_instance}.getMember("route").getACall()
  }

  override DataFlow::Node getUrlPatternArg() {
    result in [this.getArg(0), this.getArgByName("path")]
  }

  override Function getARequestHandler() { 
    result.getADecorator().getAFlowNode() = node 
  }
}
```
```

### 4.4 HTTP 响应建模生成提示词

```markdown
## 任务：生成 HTTP 响应建模代码

基于库的响应创建方式，生成响应建模代码：

**响应创建方式**:
- 类实例化: {class_instantiation}
- 辅助函数: {helper_functions}
- 隐式响应: {implicit_response}

### 生成要求：

1. 继承 `Http::Server::HttpResponse::Range`
2. 实现 `getBody()` 获取响应体
3. 实现 `getMimetypeDefault()` 返回默认 MIME 类型
4. 实现 `getMimetypeOrContentTypeArg()` 获取类型参数

### 代码模板：

```ql
module Response {
  abstract class InstanceSource extends Http::Server::HttpResponse::Range, DataFlow::Node { }

  private class ClassInstantiation extends InstanceSource, DataFlow::CallCfgNode {
    ClassInstantiation() { this = classRef().getACall() }

    override DataFlow::Node getBody() {
      result in [this.getArg(0), this.getArgByName("body")]
    }

    override string getMimetypeDefault() { result = "text/html" }

    override DataFlow::Node getMimetypeOrContentTypeArg() {
      result in [this.getArgByName("content_type")]
    }
  }
}
```
```

### 4.5 安全 Sink 生成提示词

```markdown
## 任务：生成安全 Sink 建模代码

基于识别的安全敏感操作，生成 Sink 建模代码：

**安全敏感 API 列表**:
{security_sensitive_apis}

### 对于每种 Sink 类型，使用对应的父类：

| Sink 类型 | 父类 | 需要实现的方法 |
|-----------|------|----------------|
| 文件访问 | `FileSystemAccess::Range` | `getAPathArgument()` |
| 命令执行 | `SystemCommandExecution::Range` | `getCommand()` |
| SQL 执行 | 自定义或使用数据扩展 | - |
| 重定向 | `Http::Server::HttpRedirectResponse::Range` | `getRedirectLocation()` |

### 代码模板：

```ql
// 文件访问建模
private class {ClassName}FileAccess extends FileSystemAccess::Range, DataFlow::CallCfgNode {
  {ClassName}FileAccess() {
    this = API::moduleImport("{library}").getMember("{function}").getACall()
  }

  override DataFlow::Node getAPathArgument() {
    result in [this.getArg(0), this.getArgByName("path")]
  }
}

// 重定向建模
private class {ClassName}Redirect extends Http::Server::HttpRedirectResponse::Range, 
    DataFlow::CallCfgNode 
{
  {ClassName}Redirect() {
    this = API::moduleImport("{library}").getMember("redirect").getACall()
  }

  override DataFlow::Node getRedirectLocation() {
    result in [this.getArg(0), this.getArgByName("url")]
  }

  override DataFlow::Node getBody() { none() }
  override DataFlow::Node getMimetypeOrContentTypeArg() { none() }
  override string getMimetypeDefault() { result = "text/html" }
}
```
```

---

## 5. Phase 4: 测试生成

### 5.1 Python 测试代码生成提示词

```markdown
## 任务：生成 Python 测试代码

为生成的 CodeQL 库创建全面的测试用例：

**库信息**:
- 库名: {library_name}
- 已建模的 API: {modeled_apis}

### 生成要求：

1. **基础测试文件** (basic_test.py)
   - 导入语句
   - 基本的路由和处理器定义

2. **污点测试文件** (taint_test.py)
   - 测试所有远程流源
   - 测试污点传播路径
   - 使用 `ensure_tainted()` 和 `ensure_not_tainted()` 辅助函数

3. **响应测试文件** (response_test.py)
   - 测试各种响应创建方式
   - 测试 MIME 类型识别

4. **路由测试文件** (routing_test.py)
   - 测试装饰器路由
   - 测试显式注册路由
   - 测试路由参数识别

### 内联注释语法：

- `# $routeSetup="/path"` - 标记路由设置
- `# $requestHandler` - 标记请求处理器
- `# $routedParameter=name` - 标记路由参数
- `# $ tainted` - 标记污点数据
- `# $HttpResponse` - 标记 HTTP 响应
- `# $HttpResponse mimetype=text/html` - 带 MIME 类型
- `# $ MISSING: tainted` - 预期但尚未支持的功能

### 测试代码模板：

```python
# taint_test.py
from {library} import {imports}

app = {AppClass}(__name__)

# 辅助函数
def ensure_tainted(*args):
    pass

def ensure_not_tainted(*args):
    pass

@app.route("/test/<name>")  # $routeSetup="/test/<name>"
def test_route_params(name):  # $requestHandler routedParameter=name
    ensure_tainted(name)  # $ tainted

@app.route("/test_request")  # $routeSetup="/test_request"
def test_request():  # $requestHandler
    ensure_tainted(
        request.{attr1},  # $ tainted
        request.{attr2},  # $ tainted
    )
    return "ok"  # $HttpResponse
```
```

### 5.2 测试查询文件生成提示词

```markdown
## 任务：生成测试查询文件

生成用于验证 CodeQL 库的测试查询文件：

### 1. ConceptsTest.ql

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

### 2. InlineTaintTest.ql

```ql
import experimental.meta.InlineTaintTest
import MakeInlineTaintTest<TestTaintTrackingConfig>
```

### 文件放置位置：

```
codeql/python/ql/test/library-tests/frameworks/{library_name}/
├── ConceptsTest.ql
├── ConceptsTest.expected
├── InlineTaintTest.ql
├── InlineTaintTest.expected
├── taint_test.py
├── routing_test.py
└── response_test.py
```
```

---

## 6. Phase 5: 验证与修复

### 6.1 验证检查清单

```markdown
## CodeQL 库验证检查清单

### 编译检查

- [ ] 运行 `codeql query compile` 无错误
- [ ] 所有导入路径正确
- [ ] 类型注解正确

```bash
# 编译检查命令
cd codeql
codeql query compile python/ql/lib/semmle/python/frameworks/{LibraryName}.qll
```

### 测试运行

- [ ] 运行测试命令成功
- [ ] 测试结果与预期匹配
- [ ] 无意外的失败用例

```bash
# 测试命令
codeql test run python/ql/test/library-tests/frameworks/{library_name}/
```

### 功能验证

- [ ] 远程流源被正确识别
- [ ] 污点传播步骤工作正常
- [ ] 路由和处理器被正确识别
- [ ] HTTP 响应被正确建模
- [ ] 安全 Sink 被正确识别

### 覆盖率检查

- [ ] 覆盖主要的用户输入点
- [ ] 覆盖主要的路由定义方式
- [ ] 覆盖主要的响应创建方式
- [ ] 覆盖已知的安全敏感 API
```

### 6.2 常见错误修复提示词

```markdown
## 任务：修复 CodeQL 库编译/测试错误

**错误信息**:
{error_message}

**相关代码**:
{code_snippet}

### 常见错误类型和修复方案：

#### 1. 类型不匹配错误
```
Error: this expression has type X, but expected type Y
```
**修复**: 检查继承关系，确保类正确继承所需的父类。

#### 2. 未找到成员错误
```
Error: member not found: getMember
```
**修复**: 检查 API 路径，确保使用正确的方法链。

#### 3. 特征谓词为空
```
Warning: characteristic predicate never holds
```
**修复**: 检查 API 路径是否正确，可能是 getMember 参数拼写错误。

#### 4. 测试期望不匹配
```
Test failed: output differs from expected
```
**修复**: 
- 检查内联注释是否正确
- 运行 `--update-expected-output` 更新期望（如果新结果正确）

### 请提供：

1. 错误根因分析
2. 修复后的代码
3. 验证步骤
```

### 6.3 迭代改进提示词

```markdown
## 任务：改进 CodeQL 库覆盖率

当前库已通过基本测试，但需要扩展覆盖以下场景：

**未覆盖的场景**:
{uncovered_scenarios}

### 改进方向：

1. **添加更多导入方式支持**
   - from module import Class
   - from module.submodule import Class
   - import module.submodule

2. **添加更多实例创建方式**
   - 工厂函数
   - 类方法
   - 依赖注入

3. **添加边缘情况处理**
   - 动态属性访问
   - 装饰器嵌套
   - 异步处理器

### 请提供补充代码。
```

---

## 7. 完整工作流示例

### 7.1 输入

```yaml
library_name: bottle
doc_url: https://bottlepy.org/docs/dev/
source_url: https://github.com/bottlepy/bottle
```

### 7.2 Phase 1 输出（分析结果）

```markdown
## Bottle 库分析结果

### 核心 API
- bottle.Bottle: 应用类
- bottle.request: 请求对象（远程流源）
- bottle.response: 响应对象
- bottle.route: 路由装饰器
- bottle.template: 模板渲染
- bottle.redirect: 重定向
- bottle.static_file: 静态文件服务

### 用户输入点
- request.query: 查询参数
- request.forms: 表单数据
- request.params: 所有参数
- request.json: JSON 数据
- request.body: 原始请求体
- request.cookies: Cookie
- request.headers: 请求头
- request.files: 上传文件

### 安全敏感 API
- static_file(filename): 路径遍历风险
- redirect(url): 开放重定向风险
- template(tpl_name): 模板注入风险
```

### 7.3 Phase 2-4 输出（完整 .qll 文件）

```ql
/**
 * Provides classes modeling security-relevant aspects of the `bottle` PyPI package.
 * See https://bottlepy.org/.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.ApiGraphs
private import semmle.python.frameworks.internal.InstanceTaintStepsHelper

/**
 * Provides models for the `bottle` PyPI package.
 */
module Bottle {

  // =========================================================================
  // 应用实例建模
  // =========================================================================
  
  module BottleApp {
    API::Node classRef() {
      result = API::moduleImport("bottle").getMember("Bottle")
    }

    API::Node instance() { result = classRef().getReturn() }
  }

  // =========================================================================
  // 请求对象建模
  // =========================================================================
  
  API::Node request() {
    result = API::moduleImport("bottle").getMember("request")
  }

  // =========================================================================
  // 远程流源
  // =========================================================================
  
  private class BottleRequestSource extends RemoteFlowSource::Range {
    BottleRequestSource() { this = request().asSource() }

    override string getSourceType() { result = "bottle.request" }
  }

  // =========================================================================
  // 污点传播
  // =========================================================================
  
  private class BottleRequestTaintSteps extends InstanceTaintStepsHelper {
    BottleRequestTaintSteps() { this = "bottle.Request" }

    override DataFlow::Node getInstance() { 
      result = request().getAValueReachableFromSource() 
    }

    override string getAttributeName() {
      result in [
        "query", "forms", "params", "json", "body", 
        "cookies", "headers", "files", "url", "path"
      ]
    }

    override string getMethodName() { 
      result in ["get_cookie"] 
    }

    override string getAsyncMethodName() { none() }
  }

  // =========================================================================
  // 路由建模
  // =========================================================================
  
  abstract class BottleRouteSetup extends Http::Server::RouteSetup::Range {
    override string getFramework() { result = "Bottle" }
  }

  private class BottleDecoratorRoute extends BottleRouteSetup, DataFlow::CallCfgNode {
    BottleDecoratorRoute() {
      this = BottleApp::instance().getMember("route").getACall()
      or
      this = API::moduleImport("bottle").getMember("route").getACall()
    }

    override DataFlow::Node getUrlPatternArg() {
      result in [this.getArg(0), this.getArgByName("path")]
    }

    override Function getARequestHandler() { 
      result.getADecorator().getAFlowNode() = node 
    }
  }

  // =========================================================================
  // HTTP 响应建模
  // =========================================================================
  
  module Response {
    API::Node classRef() {
      result = API::moduleImport("bottle").getMember("HTTPResponse")
    }

    abstract class InstanceSource extends Http::Server::HttpResponse::Range, DataFlow::Node { }

    private class ClassInstantiation extends InstanceSource, DataFlow::CallCfgNode {
      ClassInstantiation() { this = classRef().getACall() }

      override DataFlow::Node getBody() {
        result in [this.getArg(0), this.getArgByName("body")]
      }

      override string getMimetypeDefault() { result = "text/html" }

      override DataFlow::Node getMimetypeOrContentTypeArg() {
        result in [this.getArgByName("content_type")]
      }
    }
  }

  // 隐式响应（路由处理器返回值）
  private class BottleRouteHandlerReturn extends Http::Server::HttpResponse::Range, DataFlow::CfgNode {
    BottleRouteHandlerReturn() {
      exists(Function routeHandler |
        routeHandler = any(BottleRouteSetup rs).getARequestHandler() and
        node = routeHandler.getAReturnValueFlowNode()
      )
    }

    override DataFlow::Node getBody() { result = this }
    override DataFlow::Node getMimetypeOrContentTypeArg() { none() }
    override string getMimetypeDefault() { result = "text/html" }
  }

  // =========================================================================
  // 重定向建模
  // =========================================================================
  
  private class BottleRedirect extends Http::Server::HttpRedirectResponse::Range, 
      DataFlow::CallCfgNode 
  {
    BottleRedirect() {
      this = API::moduleImport("bottle").getMember("redirect").getACall()
    }

    override DataFlow::Node getRedirectLocation() {
      result in [this.getArg(0), this.getArgByName("url")]
    }

    override DataFlow::Node getBody() { none() }
    override DataFlow::Node getMimetypeOrContentTypeArg() { none() }
    override string getMimetypeDefault() { result = "text/html" }
  }

  // =========================================================================
  // 文件访问建模
  // =========================================================================
  
  private class BottleStaticFile extends FileSystemAccess::Range, DataFlow::CallCfgNode {
    BottleStaticFile() {
      this = API::moduleImport("bottle").getMember("static_file").getACall()
    }

    override DataFlow::Node getAPathArgument() {
      result in [
        this.getArg(0), this.getArgByName("filename"),
        this.getArg(1), this.getArgByName("root")
      ]
    }
  }
}
```

### 7.4 测试文件示例

**taint_test.py**:

```python
from bottle import Bottle, request

app = Bottle()

def ensure_tainted(*args):
    pass

def ensure_not_tainted(*args):
    pass

@app.route("/test/<name>")  # $routeSetup="/test/<name>"
def test_route_params(name):  # $requestHandler routedParameter=name
    ensure_tainted(name)  # $ tainted
    return "ok"  # $HttpResponse

@app.route("/test_request")  # $routeSetup="/test_request"
def test_request_taint():  # $requestHandler
    ensure_tainted(
        request.query,       # $ tainted
        request.query.name,  # $ tainted
        request.forms,       # $ tainted
        request.params,      # $ tainted
        request.json,        # $ tainted
        request.body,        # $ tainted
        request.cookies,     # $ tainted
        request.headers,     # $ tainted
    )
    return "ok"  # $HttpResponse
```

### 7.5 验证命令

```bash
# 1. 编译检查
codeql query compile python/ql/lib/semmle/python/frameworks/Bottle.qll

# 2. 运行测试
codeql test run python/ql/test/library-tests/frameworks/bottle/

# 3. 更新期望结果（如果需要）
codeql test run --update-expected-output python/ql/test/library-tests/frameworks/bottle/
```

---

## 附录：提示词快速参考

### A.1 初始分析提示词

```
分析 Python 库 {name}，提取：
1. 核心类/函数及导入路径
2. 用户输入点（远程流源）
3. HTTP 请求/响应模式
4. 安全敏感 API
5. 依赖的其他已建模库
```

### A.2 代码生成提示词

```
基于分析结果，生成 CodeQL 库：
1. 模块结构（遵循 Flask.qll 模式）
2. API 图谓词（classRef/instance）
3. 远程流源（RemoteFlowSource::Range）
4. 污点步骤（InstanceTaintStepsHelper）
5. 路由建模（Http::Server::RouteSetup::Range）
6. 响应建模（Http::Server::HttpResponse::Range）
```

### A.3 测试生成提示词

```
为 CodeQL 库生成测试：
1. Python 测试代码（带内联注释）
2. 测试查询文件（ConceptsTest.ql, InlineTaintTest.ql）
3. 覆盖所有已建模的 API
```

### A.4 验证修复提示词

```
修复 CodeQL 错误：
错误信息: {error}
代码位置: {location}
请提供：根因分析 + 修复代码 + 验证步骤
```

