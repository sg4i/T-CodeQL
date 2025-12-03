# Project Context

## Purpose
CodeQL tutorial project for learning security vulnerability detection across multiple programming languages. The project provides hands-on examples and queries for identifying common security issues in real-world codebases.

## Tech Stack
- **Primary**: CodeQL (query language for static code analysis)
- **Languages Covered**: Java, JavaScript, Python, C/C++
- **Tools**: CodeQL CLI, VS Code with CodeQL extension
- **Documentation**: Markdown
- **Version Control**: Git

## Project Conventions

### Code Style
- **Query Files**: Use `.ql` extension
- **Naming**:
  - Query files: kebab-case (e.g., `sql-injection.ql`, `xss-detection.ql`)
  - Directories: Language-specific with Chinese naming (e.g., `02-Java教程/`)
- **Query Structure**: Follow CodeQL metadata standards with proper `@name`, `@kind`, `@id` annotations
- **Comments**: Include explanatory comments in Chinese for educational purposes

### Architecture Patterns
- **Tutorial Organization**: Language-based directories (Java, JavaScript, Python, C/CPP)
- **Query Storage**: Each tutorial has a `queries/` subdirectory for vulnerability detection queries
- **Reference Materials**: Official CodeQL repository included as reference in `codeql/` directory
- **Project Examples**: Real-world vulnerable applications in `codeql-queries/` for practical testing

### Testing Strategy
- Test queries against intentionally vulnerable projects (DVPWA, etc.)
- Validate query results match expected vulnerability findings
- Use CodeQL database creation and query execution for verification
- Include both positive (finds vulnerabilities) and negative (no false positives) test cases

### Git Workflow
- **Main Branch**: `master`
- **Commit Style**: Concise, descriptive messages in English or Chinese
- **File Organization**: Keep queries organized by language and vulnerability type
- **Documentation**: Update README and tutorial docs with new examples

## Domain Context
- **Security Focus**: OWASP Top 10 vulnerabilities (SQL injection, XSS, command injection, etc.)
- **Educational Purpose**: Designed for security researchers and developers learning static analysis
- **CWE Coverage**: Queries target specific CWE (Common Weakness Enumeration) patterns
- **Language-Specific Patterns**: Each language has unique vulnerability patterns and detection methods

## Important Constraints
- Queries must follow CodeQL syntax and best practices
- Educational content should be beginner-friendly with progressive difficulty
- All examples must be runnable with standard CodeQL CLI
- Avoid complex meta-programming in introductory queries

## External Dependencies
- **CodeQL CLI**: Required for database creation and query execution
- **GitHub CodeQL Libraries**: Standard libraries for each language
- **VS Code Extension**: Recommended IDE integration
- **Target Projects**: External vulnerable applications for testing (DVPWA, etc.)
- **Reference Documentation**:
  - CodeQL Language Reference: https://codeql.github.com/docs/ql-language-reference/
  - CodeQL Standard Libraries: https://codeql.github.com/codeql-standard-libraries/
  - Query Metadata Guide: https://github.com/github/codeql/blob/main/docs/query-metadata-style-guide.md
