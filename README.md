# CodeQL 新手入门教程 - 多语言安全漏洞检测

欢迎来到 CodeQL 安全漏洞检测的完整入门教程！本教程将带您从零开始学习 CodeQL，通过分析真实的开源项目来掌握安全漏洞检测技能。

## 🎯 教程目标

- 掌握 CodeQL 的基本概念和工作原理
- 学会为不同编程语言创建 CodeQL 数据库
- 编写自定义查询来检测常见安全漏洞
- 分析和验证查询结果
- 在真实项目中应用 CodeQL 进行安全审计

## 📚 教程结构

### [01. 环境配置](./01-环境配置/setup.md)
- CodeQL CLI 安装（macOS）
- VS Code + CodeQL 扩展配置
- 基本命令介绍和验证

### [02. Java 安全漏洞检测](./02-Java教程/java-tutorial.md)
**目标项目**: [WebGoat](https://github.com/WebGoat/WebGoat) - OWASP 安全培训项目
- SQL 注入漏洞检测
- 命令注入漏洞检测
- 实战演练和结果验证

### [03. JavaScript/TypeScript 安全漏洞检测](./03-JavaScript教程/javascript-tutorial.md)
**目标项目**: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) - 故意存在漏洞的电商应用
- XSS (跨站脚本) 漏洞检测
- 原型污染漏洞检测
- TypeScript 项目分析技巧

### [04. Python 安全漏洞检测](./04-Python教程/python-tutorial.md)
**目标项目**: [DVPWA](https://github.com/anxolerd/dvpwa) - 故意存在漏洞的 Python Web 应用
- SQL 注入漏洞检测
- 命令注入漏洞检测
- Python 特有的安全问题

### [05. C/C++ 安全漏洞检测](./05-C-CPP教程/cpp-tutorial.md)
**目标项目**: 包含已知内存安全问题的 C/C++ 项目
- 缓冲区溢出检测
- Use-after-free 检测
- 内存安全问题分析

## 🚀 快速开始

### 前置要求

- macOS 系统（其他系统请参考官方文档调整命令）
- 至少 8GB 可用磁盘空间
- 稳定的网络连接
- Git 和基本的命令行操作知识

### 30秒快速体验

如果您已经安装了 CodeQL，可以通过以下命令快速体验：

```bash
# 克隆一个简单的测试项目
git clone https://github.com/WebGoat/WebGoat.git
cd WebGoat

# 创建 CodeQL 数据库
codeql database create webgoat-db --language=java

# 运行内置的安全查询
codeql database analyze webgoat-db java-security-and-quality.qls --format=table
```

### 完整学习路径

1. **第一步**: 按照 [环境配置指南](./01-环境配置/setup.md) 安装 CodeQL
2. **第二步**: 选择您感兴趣的编程语言教程开始学习
3. **第三步**: 跟随教程逐步完成实战练习
4. **第四步**: 尝试在自己的项目中应用 CodeQL

## 🎓 学习建议

### 适合人群

- **安全研究人员**: 学习自动化漏洞发现技术
- **开发人员**: 提高代码安全意识和技能
- **DevSecOps 工程师**: 集成安全检测到 CI/CD 流程
- **学生**: 学习静态代码分析和安全编程

### 学习顺序建议

1. **初学者**: 环境配置 → Java 教程 → JavaScript 教程
2. **有经验的开发者**: 直接选择您熟悉的编程语言教程
3. **安全研究人员**: 建议学习所有语言的教程以获得全面视角

### 预计学习时间

- **环境配置**: 30-60 分钟
- **单个语言教程**: 2-4 小时
- **完整教程**: 8-12 小时

## 📖 教程特色

### 真实项目实战

所有教程都基于真实的开源项目，这些项目包含已知的安全漏洞：

- **WebGoat**: OWASP 官方安全培训项目，包含 30+ 种常见漏洞
- **Juice Shop**: 现代化的 Web 应用，涵盖 OWASP Top 10 漏洞
- **DVPWA**: Python Web 应用安全测试平台
- **C/C++ 项目**: 包含典型的内存安全问题

### 渐进式学习

- 从基础概念开始，逐步深入
- 每个步骤都有详细的解释和截图
- 提供完整的可运行代码示例
- 包含故障排除和常见问题解答

### 实用查询库

每个教程都包含精心编写的 CodeQL 查询文件：

- 详细的代码注释
- 性能优化技巧
- 减少误报的方法
- 可直接在项目中使用

## 🔧 技术栈

- **CodeQL**: GitHub 的语义代码分析引擎
- **VS Code**: 推荐的集成开发环境
- **Git**: 版本控制和项目克隆
- **各语言构建工具**: Maven/Gradle (Java), npm (JavaScript), pip (Python), gcc/clang (C/C++)

## 📁 项目结构

```
codeql/
├── README.md                    # 本文件
├── 01-环境配置/
│   └── setup.md                 # 环境配置指南
├── 02-Java教程/
│   ├── java-tutorial.md         # Java 教程
│   ├── queries/                 # Java 查询文件
│   └── target-repo.md           # WebGoat 项目说明
├── 03-JavaScript教程/
│   ├── javascript-tutorial.md   # JavaScript 教程
│   ├── queries/                 # JavaScript 查询文件
│   └── target-repo.md           # Juice Shop 项目说明
├── 04-Python教程/
│   ├── python-tutorial.md       # Python 教程
│   ├── queries/                 # Python 查询文件
│   └── target-repo.md           # DVPWA 项目说明
└── 05-C-CPP教程/
    ├── cpp-tutorial.md          # C/C++ 教程
    ├── queries/                 # C/C++ 查询文件
    └── target-repo.md           # 目标项目说明
```

## 🤝 贡献指南

欢迎为本教程做出贡献！您可以：

- 报告错误或提出改进建议
- 添加新的查询示例
- 改进文档和说明
- 分享您的学习心得

## 📞 获取帮助

如果在学习过程中遇到问题：

1. 查看各教程的"故障排除"部分
2. 参考 [CodeQL 官方文档](https://codeql.github.com/docs/)
3. 访问 [GitHub Security Lab](https://securitylab.github.com/) 获取更多资源
4. 在 [CodeQL 社区论坛](https://github.com/github/codeql/discussions) 提问


## 🌟 致谢

感谢以下项目和组织：

- [GitHub CodeQL 团队](https://github.com/github/codeql)
- [OWASP 项目](https://owasp.org/)
- 各个开源漏洞测试项目的维护者

---

**准备好开始您的 CodeQL 安全之旅了吗？** 

👉 [点击这里开始环境配置](./01-环境配置/setup.md)
