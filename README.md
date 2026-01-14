# CodeQL 新手入门教程 - 多语言安全漏洞检测

欢迎来到 CodeQL 安全漏洞检测的完整入门教程！本教程将带您从零开始学习 CodeQL，通过分析真实的开源项目来掌握安全漏洞检测技能。

## note

```ql
/**
 *
 * Query metadata
 *
 */

import /* ... CodeQL libraries or modules ... */

/* ... Optional, define CodeQL classes and predicates ... */

from /* ... variable declarations ... */
where /* ... logical formula ... */
select /* ... expressions ... */
```

## codeql

- ql-language-reference: codeql/docs/codeql/ql-language-reference
- codeql-language-guides: codeql/docs/codeql/codeql-language-guides/abstract-syntax-tree-classes-for-working-with-go-programs.rst

## 📚 文档资源

### 项目文档
- [CodeQL Query Suite 完整指南](docs/codeql-query-suite-guide.md) - 查询套件使用场景、架构和最佳实践

### 外部参考
- https://github.com/GitHubSecurityLab/codeql-zero-to-hero
- https://codeql.github.com/docs/ql-language-reference/
- https://codeql.github.com/codeql-standard-libraries/
- https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/
- https://github.com/github/codeql/blob/main/docs/query-metadata-style-guide.md
- https://codeql.github.com/docs/writing-codeql-queries/metadata-for-codeql-queries/
- CodeQL Cheat Sheets: [https://codeql-agent-project.github.io/](https://codeql-agent-project.github.io/)
- [codeql检测shiro反序列化](https://cblog.gm7.org/docs/%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1/codeql/codeql%E6%A3%80%E6%B5%8Bshiro%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96)