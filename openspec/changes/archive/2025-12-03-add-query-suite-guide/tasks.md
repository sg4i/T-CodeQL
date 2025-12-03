# Implementation Tasks

## 1. Research and Planning
- [x] 1.1 研究 CodeQL 官方文档中关于 query suite 的内容
- [x] 1.2 分析 .qls 文件格式和语法规范
- [x] 1.3 收集常见查询套件示例（security-extended.qls, code-scanning.qls 等）
- [x] 1.4 确定文档结构和章节划分

## 2. Content Creation
- [x] 2.1 编写 query suite 概念介绍章节
- [x] 2.2 编写使用场景对比章节（何时使用 suite vs 单个查询）
- [x] 2.3 分析并解释 .qls 文件格式和语法
- [x] 2.4 创建工作流程架构图（Mermaid 格式）
  - [x] Query suite 加载流程
  - [x] 查询选择和执行流程
  - [x] 结果聚合流程
- [x] 2.5 编写常见查询套件类型说明
  - [x] security-extended.qls
  - [x] security-and-quality.qls
  - [x] code-scanning.qls
  - [x] 自定义套件
- [x] 2.6 添加多语言实际使用示例
  - [x] Python 项目示例
  - [x] Java 项目示例
  - [x] JavaScript 项目示例
  - [x] 添加查询包格式示例（codeql/python-queries:xxx）
- [x] 2.7 编写自定义查询套件教程
- [x] 2.8 添加最佳实践和常见问题 FAQ

## 3. Documentation Integration
- [x] 3.1 将新文档链接添加到 README.md
- [x] 3.2 在 docs/tutorial/ 相关章节添加引用链接
- [x] 3.3 确保文档符合项目 markdown 格式规范

## 4. Validation
- [x] 4.1 验证所有代码示例可执行
- [x] 4.2 验证 Mermaid 图表渲染正确
- [x] 4.3 检查文档中的链接有效性
- [x] 4.4 进行文档语言和格式审查
