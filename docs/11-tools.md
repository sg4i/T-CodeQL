# 开发工具

> CodeQL CLI、VS Code 扩展、CI/CD 集成等开发工具的完整使用指南

## CodeQL CLI 详解

### 安装和配置

#### 下载安装

```bash
# Linux/macOS
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip
sudo mv codeql /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-win64.zip" -OutFile "codeql.zip"
Expand-Archive -Path "codeql.zip" -DestinationPath "C:\codeql"

# 添加到 PATH
export PATH=$PATH:/usr/local/bin/codeql  # Linux/macOS
$env:PATH += ";C:\codeql\codeql"         # Windows
```

#### 验证安装

```bash
codeql --version
# 输出: CodeQL command-line toolchain release 2.15.3

codeql resolve languages
# 显示支持的语言列表
```

### 核心命令详解

#### 1. 数据库管理

```bash
# 创建数据库
codeql database create <database> \
  --language=<language> \
  --source-root=<path> \
  [--command=<build-command>] \
  [--threads=<num>] \
  [--ram=<mb>]

# 示例
codeql database create python-db \
  --language=python \
  --source-root=./my-project \
  --threads=4 \
  --ram=8192

# 编译型语言需要构建命令
codeql database create java-db \
  --language=java \
  --source-root=./java-project \
  --command="mvn clean compile"

# 查看数据库信息
codeql database info <database>

# 升级数据库
codeql database upgrade <database>

# 清理数据库
codeql database cleanup <database> \
  [--mode=brutal]  # 强制清理
```

#### 2. 查询执行

```bash
# 运行单个查询
codeql query run <query.ql> \
  --database=<database> \
  [--output=<file>] \
  [--format=csv|sarif-latest|json] \
  [--threads=<num>] \
  [--ram=<mb>]

# 示例
codeql query run python/ql/src/Security/CWE-089/SqlInjection.ql \
  --database=python-db \
  --output=results.csv \
  --format=csv

# 运行查询套件
codeql database analyze <database> <suite.qls> \
  --format=sarif-latest \
  --output=<results.sarif> \
  [--threads=<num>] \
  [--ram=<mb>] \
  [--rerun]

# 示例
codeql database analyze python-db \
  python-security-and-quality.qls \
  --format=sarif-latest \
  --output=security-results.sarif \
  --threads=8 \
  --ram=16384
```

#### 3. 查询开发

```bash
# 格式化查询
codeql query format <query.ql> \
  [--in-place]

# 编译查询
codeql query compile <query.ql> \
  [--check-only] \
  [--warnings=hide|show]

# 测试查询
codeql test run <test-directory> \
  [--threads=<num>] \
  [--ram=<mb>]

# 示例
codeql test run test/Security/CWE-089/SqlInjection/ \
  --threads=4
```

#### 4. 包管理

```bash
# 安装包
codeql pack install [<pack-name>]

# 创建包
codeql pack create <directory> \
  [--output=<path>]

# 发布包
codeql pack publish <pack> \
  [--registry=<url>]

# 下载包
codeql pack download <pack-name> \
  [--dir=<path>]

# 列出已安装的包
codeql pack ls
```

### 高级功能

#### 1. 性能调优

```bash
# 启用详细日志
codeql database create db \
  --language=python \
  --source-root=. \
  --verbose

# 性能分析
codeql query run query.ql \
  --database=db \
  --tuple-counting \
  --evaluator-log=performance.log

# 内存和线程优化
codeql database analyze db suite.qls \
  --threads=$(nproc) \
  --ram=$(free -m | awk 'NR==2{printf "%.0f", $7*0.8}')
```

#### 2. 调试功能

```bash
# 调试模式
codeql query run query.ql \
  --database=db \
  --debug

# 查看查询计划
codeql query run query.ql \
  --database=db \
  --print-tuple-counts

# 部分评估
codeql query run query.ql \
  --database=db \
  --max-paths=100
```

#### 3. 结果处理

```bash
# 转换结果格式
codeql bqrs decode results.bqrs \
  --format=csv \
  --output=results.csv

# 合并结果
codeql database interpret-results db \
  --format=sarif-latest \
  --output=combined.sarif \
  results1.bqrs results2.bqrs

# 过滤结果
codeql database interpret-results db \
  --format=sarif-latest \
  --sarif-category=security \
  --output=security-only.sarif \
  results.bqrs
```

## VS Code 扩展深度使用

### 安装和配置

#### 安装扩展

1. 打开 VS Code
2. 进入扩展市场 (Ctrl+Shift+X)
3. 搜索 "CodeQL"
4. 安装 "CodeQL" 扩展（GitHub 发布）

#### 配置设置

```json
// settings.json
{
  "codeql.cli.executablePath": "/usr/local/bin/codeql/codeql",
  "codeql.runningQueries.numberOfThreads": 8,
  "codeql.runningQueries.memory": 16384,
  "codeql.runningQueries.timeout": 1200,
  "codeql.runningQueries.debug": false,
  "codeql.runningQueries.autoSave": true,
  "codeql.runningQueries.saveCache": true,
  "codeql.runningQueries.customLogDirectory": "./logs",
  "codeql.variantAnalysis.controllerRepo": "my-org/codeql-queries",
  "codeql.telemetry.enableTelemetry": false
}
```

### 核心功能

#### 1. 数据库管理

**从 VS Code 创建数据库：**
1. 打开命令面板 (Ctrl+Shift+P)
2. 输入 "CodeQL: Create Database"
3. 选择语言和源代码目录
4. 等待数据库创建完成

**导入现有数据库：**
1. 命令面板 → "CodeQL: Add Database from Folder"
2. 选择数据库目录
3. 数据库将出现在 CodeQL 面板中

#### 2. 查询开发

**创建新查询：**
```ql
/**
 * @name My Custom Query
 * @description Description of what this query does
 * @kind problem
 * @id my/custom-query
 */

import python

from Function f
where f.getName() = "dangerous_function"
select f, "Found dangerous function"
```

**运行查询：**
1. 右键查询文件 → "CodeQL: Run Query"
2. 选择目标数据库
3. 查看结果面板

**快速评估：**
1. 选中代码片段
2. 右键 → "CodeQL: Quick Evaluation"
3. 立即查看结果

#### 3. 结果分析

**结果面板功能：**
- 📊 **表格视图**：结构化显示查询结果
- 🗺️ **路径视图**：显示数据流路径（path-problem 查询）
- 📍 **源码导航**：点击结果跳转到源码位置
- 💾 **导出结果**：导出为 CSV、SARIF 等格式

**结果过滤：**
```json
// 在结果面板中使用过滤器
{
  "severity": "error",
  "tags": ["security"],
  "file": "*.py"
}
```

#### 4. AST 查看器

**查看抽象语法树：**
1. 打开源文件
2. 右键 → "CodeQL: View AST"
3. 在侧边栏查看 AST 结构

**AST 导航：**
- 点击 AST 节点高亮对应源码
- 使用搜索功能查找特定节点类型
- 复制节点路径用于查询开发

### 高级功能

#### 1. 多仓库变体分析 (MRVA)

**设置控制器仓库：**
```json
{
  "codeql.variantAnalysis.controllerRepo": "my-org/security-queries"
}
```

**运行变体分析：**
1. 编写查询
2. 右键 → "CodeQL: Run Variant Analysis"
3. 选择目标仓库列表
4. 监控分析进度

**查看变体分析结果：**
- 在 CodeQL 面板查看所有仓库的结果
- 按仓库、严重程度过滤
- 导出汇总报告

#### 2. 查询历史

**查看查询历史：**
1. CodeQL 面板 → "Query History"
2. 查看之前运行的所有查询
3. 重新运行或比较结果

**查询收藏：**
- 右键查询历史项 → "Add to Favorites"
- 快速访问常用查询

#### 3. 调试功能

**查询调试：**
```ql
// 使用 select 语句调试
from Expr e
where e instanceof Call
select e, e.getType(), e.getLocation()  // 查看中间结果
```

**性能分析：**
1. 设置 `"codeql.runningQueries.debug": true`
2. 查看详细的执行日志
3. 分析查询性能瓶颈

#### 4. 自定义代码片段

**创建查询模板：**
```json
// snippets.json
{
  "Security Query Template": {
    "prefix": "security-query",
    "body": [
      "/**",
      " * @name ${1:Query Name}",
      " * @description ${2:Query Description}",
      " * @kind path-problem",
      " * @problem.severity error",
      " * @security-severity 8.0",
      " * @id ${3:query-id}",
      " * @tags security",
      " */",
      "",
      "import ${4:language}",
      "import semmle.${4}.dataflow.TaintTracking",
      "import DataFlow::PathGraph",
      "",
      "class ${5:ConfigName} extends TaintTracking::Configuration {",
      "  ${5}() { this = \"${5}\" }",
      "",
      "  override predicate isSource(DataFlow::Node source) {",
      "    ${6:// Define sources}",
      "  }",
      "",
      "  override predicate isSink(DataFlow::Node sink) {",
      "    ${7:// Define sinks}",
      "  }",
      "}",
      "",
      "from ${5} config, DataFlow::PathNode source, DataFlow::PathNode sink",
      "where config.hasFlowPath(source, sink)",
      "select sink.getNode(), source, sink, \"${8:Message}\"",
      "$0"
    ],
    "description": "Create a security query template"
  }
}
```

## CI/CD 集成

### GitHub Actions 集成

#### 基础工作流

```yaml
# .github/workflows/codeql.yml
name: "CodeQL Analysis"

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * 1'  # 每周一凌晨2点

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read

    strategy:
      fail-fast: false
      matrix:
        language: [ 'python', 'javascript', 'java' ]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Initialize CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: ${{ matrix.language }}
        queries: security-and-quality
        config-file: ./.github/codeql/codeql-config.yml

    - name: Autobuild
      uses: github/codeql-action/autobuild@v3

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v3
      with:
        category: "/language:${{ matrix.language }}"
        upload: true
```

#### 高级配置

```yaml
# .github/codeql/codeql-config.yml
name: "Advanced CodeQL Config"

disable-default-queries: false

queries:
  - name: security-extended
    uses: security-extended
  - name: custom-queries
    uses: ./custom-queries/

paths-ignore:
  - "**/*.test.js"
  - "**/node_modules/**"
  - "**/vendor/**"

paths:
  - "src/**"
  - "lib/**"

packs:
  - codeql/python-queries
  - my-org/custom-security-queries
```

#### 自定义查询集成

```yaml
# 使用自定义查询
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: python
    config: |
      name: "Custom Config"
      queries:
        - name: custom-security
          uses: ./security-queries/
      paths-ignore:
        - "tests/**"
        - "docs/**"
```

### 其他 CI/CD 平台

#### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

codeql-analysis:
  stage: security
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y wget unzip
    - wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
    - unzip codeql-linux64.zip
    - export PATH=$PATH:$(pwd)/codeql
  script:
    - codeql database create db --language=python --source-root=.
    - codeql database analyze db python-security-and-quality.qls --format=sarif-latest --output=results.sarif
  artifacts:
    reports:
      sast: results.sarif
    expire_in: 1 week
  only:
    - main
    - merge_requests
```

#### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        CODEQL_HOME = '/opt/codeql'
        PATH = "${CODEQL_HOME}:${PATH}"
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('CodeQL Analysis') {
            parallel {
                stage('Python Analysis') {
                    steps {
                        sh '''
                            codeql database create python-db \
                                --language=python \
                                --source-root=. \
                                --threads=4
                            
                            codeql database analyze python-db \
                                python-security-and-quality.qls \
                                --format=sarif-latest \
                                --output=python-results.sarif
                        '''
                    }
                }
                
                stage('JavaScript Analysis') {
                    steps {
                        sh '''
                            codeql database create js-db \
                                --language=javascript \
                                --source-root=. \
                                --threads=4
                            
                            codeql database analyze js-db \
                                javascript-security-and-quality.qls \
                                --format=sarif-latest \
                                --output=js-results.sarif
                        '''
                    }
                }
            }
        }
        
        stage('Process Results') {
            steps {
                script {
                    // 处理 SARIF 结果
                    def pythonResults = readJSON file: 'python-results.sarif'
                    def jsResults = readJSON file: 'js-results.sarif'
                    
                    // 发送通知或创建报告
                    if (pythonResults.runs[0].results.size() > 0) {
                        currentBuild.result = 'UNSTABLE'
                    }
                }
                
                archiveArtifacts artifacts: '*.sarif', fingerprint: true
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: '*.sarif',
                    reportName: 'CodeQL Security Report'
                ])
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
    }
}
```

#### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  CODEQL_VERSION: '2.15.3'

stages:
- stage: SecurityAnalysis
  displayName: 'Security Analysis'
  jobs:
  - job: CodeQL
    displayName: 'CodeQL Analysis'
    steps:
    - task: Bash@3
      displayName: 'Install CodeQL'
      inputs:
        targetType: 'inline'
        script: |
          wget https://github.com/github/codeql-cli-binaries/releases/download/v$(CODEQL_VERSION)/codeql-linux64.zip
          unzip codeql-linux64.zip
          echo "##vso[task.prependpath]$(pwd)/codeql"

    - task: Bash@3
      displayName: 'Create Database'
      inputs:
        targetType: 'inline'
        script: |
          codeql database create db \
            --language=python \
            --source-root=$(Build.SourcesDirectory) \
            --threads=4

    - task: Bash@3
      displayName: 'Run Analysis'
      inputs:
        targetType: 'inline'
        script: |
          codeql database analyze db \
            python-security-and-quality.qls \
            --format=sarif-latest \
            --output=$(Agent.TempDirectory)/results.sarif

    - task: PublishBuildArtifacts@1
      displayName: 'Publish Results'
      inputs:
        pathToPublish: '$(Agent.TempDirectory)/results.sarif'
        artifactName: 'CodeQL-Results'
```

## 结果处理和报告

### SARIF 格式处理

#### Python 脚本处理 SARIF

```python
#!/usr/bin/env python3
import json
import sys
from collections import defaultdict

def process_sarif(sarif_file):
    """处理 SARIF 文件并生成报告"""
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)
    
    results_by_severity = defaultdict(list)
    results_by_category = defaultdict(list)
    
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            # 按严重程度分类
            severity = result.get('level', 'note')
            results_by_severity[severity].append(result)
            
            # 按类别分类
            rule_id = result.get('ruleId', 'unknown')
            category = rule_id.split('/')[0] if '/' in rule_id else 'other'
            results_by_category[category].append(result)
    
    # 生成摘要报告
    print("CodeQL Analysis Summary")
    print("=" * 50)
    print(f"Total Issues: {sum(len(results) for results in results_by_severity.values())}")
    print()
    
    print("By Severity:")
    for severity in ['error', 'warning', 'note']:
        count = len(results_by_severity[severity])
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")
    
    print("\nBy Category:")
    for category, results in results_by_category.items():
        print(f"  {category}: {len(results)}")
    
    # 生成详细报告
    print("\nDetailed Results:")
    print("-" * 50)
    
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            rule_id = result.get('ruleId', 'unknown')
            message = result.get('message', {}).get('text', 'No message')
            
            for location in result.get('locations', []):
                physical_location = location.get('physicalLocation', {})
                file_path = physical_location.get('artifactLocation', {}).get('uri', 'unknown')
                region = physical_location.get('region', {})
                line = region.get('startLine', 'unknown')
                
                print(f"[{result.get('level', 'note').upper()}] {rule_id}")
                print(f"  File: {file_path}:{line}")
                print(f"  Message: {message}")
                print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_sarif.py <sarif_file>")
        sys.exit(1)
    
    process_sarif(sys.argv[1])
```

#### 生成 HTML 报告

```python
def generate_html_report(sarif_file, output_file):
    """生成 HTML 格式的安全报告"""
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CodeQL Security Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
            .error { color: #d32f2f; }
            .warning { color: #f57c00; }
            .note { color: #1976d2; }
            .result { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
            .result.error { border-left-color: #d32f2f; }
            .result.warning { border-left-color: #f57c00; }
            .result.note { border-left-color: #1976d2; }
        </style>
    </head>
    <body>
        <h1>CodeQL Security Report</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p>Total Issues: {total_issues}</p>
            <p>Errors: <span class="error">{errors}</span></p>
            <p>Warnings: <span class="warning">{warnings}</span></p>
            <p>Notes: <span class="note">{notes}</span></p>
        </div>
        
        <h2>Detailed Results</h2>
        {results_html}
    </body>
    </html>
    """
    
    # 处理结果...
    # 生成 HTML 内容...
    
    with open(output_file, 'w') as f:
        f.write(html_content)
```

### 集成到通知系统

#### Slack 通知

```python
import requests
import json

def send_slack_notification(webhook_url, sarif_file):
    """发送 CodeQL 结果到 Slack"""
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)
    
    # 统计结果
    total_issues = 0
    errors = 0
    warnings = 0
    
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            total_issues += 1
            level = result.get('level', 'note')
            if level == 'error':
                errors += 1
            elif level == 'warning':
                warnings += 1
    
    # 构建 Slack 消息
    color = "danger" if errors > 0 else "warning" if warnings > 0 else "good"
    
    message = {
        "attachments": [
            {
                "color": color,
                "title": "CodeQL Security Analysis Results",
                "fields": [
                    {"title": "Total Issues", "value": str(total_issues), "short": True},
                    {"title": "Errors", "value": str(errors), "short": True},
                    {"title": "Warnings", "value": str(warnings), "short": True},
                ],
                "footer": "CodeQL Analysis",
                "ts": int(time.time())
            }
        ]
    }
    
    response = requests.post(webhook_url, json=message)
    return response.status_code == 200
```

## 性能优化

### 查询性能优化

#### 1. 内存和线程配置

```bash
# 根据系统资源调整
THREADS=$(nproc)
MEMORY=$(free -m | awk 'NR==2{printf "%.0f", $7*0.8}')

codeql database analyze db suite.qls \
  --threads=$THREADS \
  --ram=$MEMORY \
  --format=sarif-latest \
  --output=results.sarif
```

#### 2. 缓存优化

```bash
# 启用查询缓存
export CODEQL_DIST_CACHE_DIR=~/.codeql/cache

# 预编译查询包
codeql pack create --output=compiled-queries/ queries/

# 使用预编译的查询
codeql database analyze db compiled-queries/ \
  --format=sarif-latest \
  --output=results.sarif
```

#### 3. 分批处理

```bash
#!/bin/bash
# 分批运行查询以避免内存不足

QUERIES=(
  "security-queries/*.ql"
  "quality-queries/*.ql"
  "performance-queries/*.ql"
)

for batch in "${QUERIES[@]}"; do
  echo "Running batch: $batch"
  codeql database analyze db "$batch" \
    --format=sarif-latest \
    --output="results-$(basename $batch .ql).sarif" \
    --threads=4 \
    --ram=8192
done

# 合并结果
codeql database interpret-results db \
  --format=sarif-latest \
  --output=combined-results.sarif \
  results-*.bqrs
```

### 数据库优化

#### 1. 增量分析

```bash
# 创建基线数据库
codeql database create baseline-db \
  --language=python \
  --source-root=. \
  --baseline

# 创建增量数据库
codeql database create incremental-db \
  --language=python \
  --source-root=. \
  --baseline=baseline-db
```

#### 2. 并行数据库创建

```bash
#!/bin/bash
# 并行创建多语言数据库

languages=("python" "javascript" "java")

for lang in "${languages[@]}"; do
  (
    echo "Creating $lang database..."
    codeql database create "${lang}-db" \
      --language="$lang" \
      --source-root=. \
      --threads=2 \
      --ram=4096
  ) &
done

wait  # 等待所有后台任务完成
echo "All databases created!"
```

## 故障排除

### 常见问题和解决方案

#### 1. 数据库创建失败

**问题**: "Extraction failed"
```bash
# 解决方案
# 1. 检查日志
codeql database create db --language=python --source-root=. --verbose

# 2. 查看详细日志
cat db/log/database-create-*.log

# 3. 清理并重试
rm -rf db
codeql database create db --language=python --source-root=. --overwrite
```

#### 2. 查询运行超时

**问题**: 查询运行时间过长
```bash
# 解决方案
# 1. 增加超时时间
codeql query run query.ql --database=db --timeout=3600

# 2. 优化查询
# 添加更强的限制条件
# 使用 cached 谓词
# 避免笛卡尔积

# 3. 分批处理
# 将复杂查询拆分为多个简单查询
```

#### 3. 内存不足

**问题**: "Out of memory"
```bash
# 解决方案
# 1. 增加内存限制
codeql query run query.ql --database=db --ram=16384

# 2. 减少并发
codeql query run query.ql --database=db --threads=2

# 3. 清理缓存
rm -rf ~/.codeql/cache
```

#### 4. VS Code 扩展问题

**问题**: 扩展无法连接到 CLI
```json
// 解决方案：检查配置
{
  "codeql.cli.executablePath": "/correct/path/to/codeql",
  "codeql.runningQueries.numberOfThreads": 4,
  "codeql.runningQueries.memory": 8192
}
```

### 调试技巧

#### 1. 启用详细日志

```bash
# CLI 详细日志
codeql --verbose query run query.ql --database=db

# VS Code 日志
# 设置 "codeql.runningQueries.debug": true
```

#### 2. 查询性能分析

```bash
# 生成性能报告
codeql query run query.ql \
  --database=db \
  --tuple-counting \
  --evaluator-log=performance.log

# 分析性能日志
grep "Evaluation completed" performance.log
```

#### 3. 部分流分析

```ql
// 调试数据流查询
import semmle.python.dataflow.new.PartialFlow

module PartialFlowDebug = PartialFlow<MyConfig>;

from PartialFlowDebug::PartialPathNode source, PartialFlowDebug::PartialPathNode node, int dist
where PartialFlowDebug::partialFlow(source, node, dist)
select node, source, dist order by dist desc
```

## 下一步

掌握了开发工具后，建议继续学习：

1. **[最佳实践](12-best-practices.md)** - 查询优化和调试技巧
2. **[贡献指南](13-contributing.md)** - 如何为 CodeQL 项目贡献代码
3. **[学习资源](15-learning-resources.md)** - 深入学习的资源汇总

---

**开发工具掌握完毕！** 🛠️ 现在您可以高效地使用 CodeQL 工具链进行代码分析了。
