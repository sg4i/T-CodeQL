# Change: Add CodeQL Query Suite Documentation

## Why
新手用户在使用 CodeQL 时经常遇到以下困惑：
- 不清楚什么是 query suite 以及它与单个查询的区别
- 不知道在不同场景下应该选择哪个查询套件（security、quality、code-scanning等）
- 缺乏对 query suite 内部实现和工作流程的理解
- 没有实际的使用示例和最佳实践参考

添加一个专门的文档可以帮助新人快速理解查询套件的概念、架构和使用方法，提升学习效率。

## What Changes
- 在 `docs/` 目录新增 `codeql-query-suite-guide.md` 文档
- 文档包含以下内容：
  - Query suite 的概念和使用场景说明
  - 内部实现源码分析（.qls 文件格式、查询选择机制）
  - 工作流程架构图（使用 Mermaid 格式）
  - 常见查询套件类型及其适用场景
  - 实际使用示例（针对不同语言和场景）
  - 自定义查询套件的方法
  - 最佳实践和常见问题

## Impact
- **Affected specs**: 新增 `query-suite-documentation` capability
- **Affected code**: 仅新增文档，不影响现有代码
- **User benefit**: 降低新手学习曲线，提供清晰的查询套件使用指南
- **Documentation**: 扩展教程体系，填补查询套件相关的文档空白
