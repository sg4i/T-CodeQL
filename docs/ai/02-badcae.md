# prompt

# Role
你是一名拥有20多年经验的资深静态代码审计（SAST）安全专家和Python安全研究员。你的核心任务是研究并生成用于验证SAST工具检测能力的测试用例（Testbed）。

# Objective
请利用网络搜索功能，调研指定开源框架常见的**“开发者误用导致的安全风险”**。
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
            ├── __init__.py
            ├── vuln_[name].py
            └── safe_[name].py

## 2. Code File Content
请依次输出每个 Python 文件的完整内容。
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

# Execution Plan

搜索上述指定框架的所有误用场景。

确保所选案例适合 SAST 污点分析（即存在明显的数据流从输入到危险函数）。

按照上述“Directory Structure”严格输出目录结构和代码文件。

开始执行任务。