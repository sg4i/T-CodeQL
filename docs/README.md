# CodeQL 新人入门指引

> 欢迎来到 CodeQL 的世界！这是一套完整的中文学习资料，帮助您从零开始掌握 CodeQL 代码分析技术。

## 📚 文档目录

### 🚀 快速开始
- **[快速入门](01-quick-start.md)** - 5分钟了解 CodeQL 并运行第一个查询
- **[环境搭建](02-setup.md)** - 详细的开发环境配置指南

### 📖 基础教程
- **[CodeQL 基础](03-basics.md)** - 核心概念、仓库结构、QL 语言入门
- **[查询编写](04-writing-queries.md)** - 从简单查询到复杂分析

### 🔧 进阶技术
- **[数据流分析](05-dataflow-analysis.md)** - 掌握数据流和污点追踪技术
- **[安全查询实战](06-security-queries.md)** - SQL注入、XSS等安全漏洞检测

### 🌍 多语言支持
- **[Python 场景](07-python.md)** - Python 代码分析完整指南
- **[Java 场景](08-java.md)** - Java/Kotlin 企业级应用分析
- **[JavaScript 场景](09-javascript.md)** - 前端和 Node.js 安全分析
- **[其他语言](10-other-languages.md)** - Go、C/C++、C#、Ruby、Swift、Rust

### 🛠️ 工具与实践
- **[开发工具](11-tools.md)** - CodeQL CLI、VS Code 扩展、CI/CD 集成
- **[最佳实践](12-best-practices.md)** - 性能优化、调试技巧、代码规范
- **[贡献指南](13-contributing.md)** - 如何为 CodeQL 项目贡献代码

### 📋 参考资料
- **[快速参考](14-quick-reference.md)** - QL 语法速查、常用模式、API 参考
- **[学习资源](15-learning-resources.md)** - 官方文档、教程、社区资源

## 🎯 学习路径推荐

### 初学者路径 (1-2周)
1. [快速入门](01-quick-start.md) → [环境搭建](02-setup.md)
2. [CodeQL 基础](03-basics.md) → [查询编写](04-writing-queries.md)
3. 选择您熟悉的语言：[Python](07-python.md) / [Java](08-java.md) / [JavaScript](09-javascript.md)
4. [快速参考](14-quick-reference.md) - 随时查阅

### 进阶路径 (2-4周)
1. [数据流分析](05-dataflow-analysis.md) → [安全查询实战](06-security-queries.md)
2. 学习其他语言场景：[其他语言](10-other-languages.md)
3. [开发工具](11-tools.md) → [最佳实践](12-best-practices.md)
4. [贡献指南](13-contributing.md) - 参与开源贡献

### 专家路径 (持续学习)
1. 深入研究特定领域的安全查询
2. 为开源项目贡献高质量查询
3. 参与社区讨论和技术分享
4. 探索前沿的代码分析技术

## 🔍 快速查找

| 我想... | 推荐阅读 |
|---------|----------|
| 快速了解 CodeQL | [快速入门](01-quick-start.md) |
| 安装配置环境 | [环境搭建](02-setup.md) |
| 学习 QL 语法 | [CodeQL 基础](03-basics.md) |
| 编写安全查询 | [安全查询实战](06-security-queries.md) |
| 分析 Python 代码 | [Python 场景](07-python.md) |
| 分析 Java 代码 | [Java 场景](08-java.md) |
| 分析 JavaScript 代码 | [JavaScript 场景](09-javascript.md) |
| 使用 VS Code 扩展 | [开发工具](11-tools.md) |
| 优化查询性能 | [最佳实践](12-best-practices.md) |
| 查找语法和 API | [快速参考](14-quick-reference.md) |
| 参与开源贡献 | [贡献指南](13-contributing.md) |

## 💡 使用建议

- **循序渐进**：按照推荐的学习路径，不要跳跃式学习
- **动手实践**：每个概念都要亲自编写代码验证
- **多看示例**：CodeQL 仓库中有大量优秀的查询示例
- **参与社区**：加入 GitHub Discussions，与其他开发者交流

## 📂 推荐的目录结构

为了便于学习和使用 CodeQL，我们推荐以下目录组织方式：

```
~/codeql-projects/              # 工作根目录
├── codeql/                     # CodeQL 标准库（克隆的官方仓库）
│   ├── python/
│   │   └── ql/
│   │       ├── lib/            # Python 库文件
│   │       └── src/            # 预定义查询
│   │           └── Security/
│   │               ├── CWE-089/
│   │               │   └── SqlInjection.ql
│   │               └── ...
│   ├── java/
│   ├── javascript/
│   └── ...
│
├── my-queries/                 # 您的自定义查询
│   ├── codeql-workspace.yml   # 工作空间配置
│   ├── queries/                # 查询文件
│   │   ├── security/
│   │   └── quality/
│   └── test/                   # 测试用例
│
└── my-projects/                # 要分析的项目
    ├── project1/
    │   ├── src/                # 源代码
    │   └── project1-db/        # CodeQL 数据库（自动生成）
    └── project2/
```

**关键点：**
- `codeql/`：包含所有语言的标准查询和库，从 GitHub 克隆
- `my-queries/`：存放您自己编写的查询
- `my-projects/`：存放要分析的项目和生成的数据库
- 所有目录在同一层级，便于管理和路径引用

详细说明请参考 [快速入门](01-quick-start.md) 和 [环境搭建](02-setup.md)。

## 🤝 获取帮助

- 📚 **官方文档**：https://codeql.github.com/docs/
- 💬 **社区讨论**：https://github.com/github/codeql/discussions
- 🐛 **问题反馈**：https://github.com/github/codeql/issues
- 🎓 **安全实验室**：https://securitylab.github.com/

## 📝 文档维护

本文档集合基于 CodeQL 开源仓库（https://github.com/github/codeql）创建，持续更新中。

- **最后更新**：2025-11-20
- **适用版本**：CodeQL 2.15+
- **许可证**：MIT License

---

**开始您的 CodeQL 学习之旅吧！** 🚀
