# Capability: Query Suite Documentation

## ADDED Requirements

### Requirement: Query Suite Concept Explanation
文档 SHALL 清晰解释 CodeQL query suite 的核心概念，包括其定义、目的和与单个查询的区别。

#### Scenario: 新手理解 query suite 定义
- **WHEN** 新手阅读概念章节
- **THEN** 能够理解 query suite 是一组相关查询的集合
- **AND** 能够区分 query suite (.qls) 和单个查询 (.ql) 的使用场景

#### Scenario: 理解查询套件的优势
- **WHEN** 用户阅读使用场景对比
- **THEN** 能够理解使用 query suite 的优势（批量执行、标准化、易管理）
- **AND** 能够判断何时应该使用 query suite 而非单个查询

### Requirement: Query Suite File Format Documentation
文档 SHALL 详细说明 .qls 文件的格式、语法和配置选项。

#### Scenario: 理解 .qls 文件结构
- **WHEN** 开发者查看 .qls 文件格式章节
- **THEN** 能够理解 YAML/JSON 格式的配置结构
- **AND** 能够识别常见配置项（query、exclude、include 等）

#### Scenario: 解析实际 .qls 文件
- **WHEN** 用户查看文档中的 .qls 示例
- **THEN** 能够理解每个配置项的作用
- **AND** 能够修改示例以满足自己的需求

### Requirement: Architecture Diagram
文档 SHALL 包含使用 Mermaid 格式的架构图，展示 query suite 的工作流程。

#### Scenario: 可视化工作流程
- **WHEN** 用户查看架构图
- **THEN** 能够看到从加载 suite 到生成结果的完整流程
- **AND** 能够理解各个组件之间的交互关系

#### Scenario: 理解查询选择机制
- **WHEN** 用户查看查询选择流程图
- **THEN** 能够理解 CodeQL 如何根据 .qls 配置选择和过滤查询
- **AND** 能够理解 include/exclude 规则的优先级

### Requirement: Common Query Suites Overview
文档 SHALL 介绍 CodeQL 官方提供的常见查询套件及其适用场景。

#### Scenario: 选择安全查询套件
- **WHEN** 用户需要进行安全扫描
- **THEN** 能够了解 security-extended.qls 的内容和覆盖范围
- **AND** 能够决定是否使用该套件

#### Scenario: 选择代码质量套件
- **WHEN** 用户需要检测代码质量问题
- **THEN** 能够了解 security-and-quality.qls 与纯安全套件的区别
- **AND** 能够根据项目需求选择合适的套件

#### Scenario: CI/CD 集成场景
- **WHEN** 用户需要在 CI/CD 中集成 CodeQL
- **THEN** 能够了解 code-scanning.qls 的设计目的
- **AND** 能够理解其与 GitHub Code Scanning 的集成方式

### Requirement: Practical Examples
文档 SHALL 提供多语言、多场景的实际使用示例。

#### Scenario: Python 项目扫描示例
- **WHEN** 用户需要扫描 Python 项目
- **THEN** 能够找到完整的命令行示例
- **AND** 能够理解如何指定语言特定的查询套件

#### Scenario: Java 企业应用扫描示例
- **WHEN** 用户需要扫描 Java 企业应用
- **THEN** 能够找到针对 Java 的安全查询套件使用示例
- **AND** 能够理解输出格式选择（SARIF、CSV 等）

#### Scenario: JavaScript/TypeScript 前端项目示例
- **WHEN** 用户需要扫描前端项目
- **THEN** 能够找到 JavaScript/TypeScript 查询套件示例
- **AND** 能够理解如何处理混合语言项目

### Requirement: Custom Query Suite Guide
文档 SHALL 提供创建自定义查询套件的详细指南。

#### Scenario: 创建自定义套件
- **WHEN** 用户需要创建符合团队规范的自定义查询套件
- **THEN** 能够找到创建 .qls 文件的步骤说明
- **AND** 能够理解如何组合和筛选查询

#### Scenario: 复用和扩展现有套件
- **WHEN** 用户想基于官方套件创建自定义版本
- **THEN** 能够找到继承和扩展官方套件的方法
- **AND** 能够理解如何添加自定义查询到套件中

### Requirement: Best Practices and FAQ
文档 SHALL 包含查询套件使用的最佳实践和常见问题解答。

#### Scenario: 性能优化建议
- **WHEN** 用户关心大型项目的扫描性能
- **THEN** 能够找到查询套件性能优化建议
- **AND** 能够理解如何平衡覆盖率和执行时间

#### Scenario: 故障排查
- **WHEN** 用户遇到查询套件执行错误
- **THEN** 能够在 FAQ 中找到常见错误的解决方案
- **AND** 能够理解错误信息的含义和调试方法
