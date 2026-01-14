# Change: Analyze and Document CodeQL Python Concepts.qll

## Why

The `Concepts.qll` file in CodeQL's Python library defines framework-agnostic security concepts that serve as the foundation for detecting vulnerabilities across different frameworks. Framework developers need comprehensive documentation to understand these concepts, their design philosophy, usage patterns, and implementation constraints when building framework-specific security detectors.

Currently, there is no centralized documentation explaining:
- What security concepts are available
- How concepts are architected and why
- When and how to use each concept
- Design patterns and constraints

## What Changes

- Analyze the `codeql/python/ql/lib/semmle/python/Concepts.qll` implementation
- Create comprehensive documentation at `docs/codeql-concepts-analysis.md` covering:
  - Complete inventory of all security concepts
  - Architecture and design philosophy
  - Inheritance hierarchy and relationships
  - Usage scenarios for each concept
  - Implementation requirements and constraints
  - Best practices for framework modeling
  - Mermaid diagrams illustrating concept relationships and data flow
- Cross-reference with existing framework implementations as examples

## Impact

- **Affected specs**: New capability `concepts-documentation`
- **Affected code**: None (documentation only)
- **Benefits**:
  - Faster onboarding for framework modeling
  - Consistent implementation patterns across frameworks
  - Reduced errors from misunderstanding concept purposes
  - Clear reference for security concept selection
