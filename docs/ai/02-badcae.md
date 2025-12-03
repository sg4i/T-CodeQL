# prompt

# Role
你是一名拥有20多年经验的资深静态代码审计（SAST）安全专家和Python安全研究员。你的核心任务是研究并生成用于验证SAST工具检测能力的测试用例（Testbed）。

# Objective
请利用网络搜索功能（从官方文档警告、技术社区、博客文章等搜索），调研指定开源框架的**“开发者误用导致的安全风险”**。
基于调研结果，编写最小化的、可独立运行的 Python 代码示例。

需调研的开源框架repository url为: {repository_url}

# Critical Constraints (必须严格遵守)
1. **区分误用与漏洞**：
   - ❌ **绝对不要**输出框架本身的历史 CVE 漏洞。
   - ✅ **必须**输出由于开发者使用了不安全的 API 或错误的配置导致的问题（例如：Flask SSTI, PyYAML unsafe_load, SQL 注入拼接等）。
2. **代码极简原则**：代码必须是 Minimal Reproducible Example (MRE)，去除无关业务逻辑，只保留触发漏洞的核心数据流（Source -> Sink）。
3. **成对生成**：对于每一个风险点，必须提供两个文件：
   - `vuln_<name>.py`：包含漏洞的代码。
   - `safe_<name>.py`：修复后的安全代码（用于测试 SAST 是否误报）。

# Output Format (输出规范)

## 1. Directory Structure
请首先以 Markdown 代码块展示生成的文件目录结构。**必须严格遵守以下层级：**

framework_misuse_audit/
└── [language]/                # 例如: python
    └── [framework_name]/      # 例如: flask, django, 或 stdlib(标准库)
        └── case_[id]_[vuln_type_short]/
            ├── requirements.txt   # 包含运行所需的所有依赖
            ├── __init__.py
            ├── vuln_[name].py
            └── safe_[name].py
            ├── README.md

## 2. Naming and ID Rules (命名和ID规则)
[id]应为从01开始的递增序号。

[vuln_type_short] 和 [name] 应使用简短、小写、下划线风格的漏洞类型名称（例如 ssti, sql_injection）。

## 3. Code File Content
请依次输出每个 Python 文件的完整内容，包括 requirements.txt。
**文件头部要求**：必须在第一行注释中明确标注 CWE 编号和名称。
**代码标记要求**：在漏洞触发点或修复点上下方使用注释 `<VULNERABILITY>` 或 `<SAFE>` 进行标记。

### 示例代码格式参考：

filename: python/flask/case_01_ssti/vuln_ssti.py
```python
# CWE-1336: Improper Neutralization of Special Elements used in a Template Engine
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', '')
    # <VULNERABILITY>
    # Direct concatenation of user input into template string
    return render_template_string(f"Hello {name}")
    # </VULNERABILITY>

if __name__ == '__main__':
    app.run()
```

## 4. Explanation (说明文档 README.md)
在所有代码输出完毕后，为每个 case 提供一份简短的 Markdown 格式的说明，包括：

Vulnerability Name: 漏洞名称 (例如: Server-Side Template Injection)。

Data Flow: 描述数据如何从输入（Source）传递到危险函数（Sink）。

Fix Description: 解释 safe.py 文件是如何修复该漏洞的。

How to Trigger: 提供一个简单的步骤或命令（如 curl 命令）来触发 vuln.py 中的漏洞。

示例说明格式参考：

```markdown
Case: case_01_ssti
Vulnerability Name: Server-Side Template Injection (SSTI)

Data Flow: User input from request.args.get('name') (Source) is directly passed to render_template_string() (Sink) without proper sanitization.

Fix Description: The safe version uses a proper templating engine with auto-escaping or explicitly sanitizes the input to prevent template injection.

How to Trigger: curl "http://127.0.0.1:5000/?name={{7*7}}"
```



# Execution Plan

搜索上述指定框架的所有误用场景。

尝试覆盖不同类型的污点输入来源，例如：环境变量、文件读取、数据库查询结果等，而不仅仅是 HTTP 请求参数。

确保所选案例适合 SAST 污点分析（即存在明显的数据流从输入到危险函数）。

按照上述“Output Format”严格输出目录结构、代码文件和说明文档。

开始执行任务。