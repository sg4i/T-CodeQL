# Concepts Documentation

## ADDED Requirements

### Requirement: Concepts Overview Documentation

The documentation SHALL provide a comprehensive overview of the Concepts.qll architecture, explaining its role as the foundation for framework-agnostic security vulnerability detection in CodeQL.

#### Scenario: 理解 Concepts.qll 的作用

- **GIVEN** a framework developer needs to implement security detection for a new Python framework
- **WHEN** they read the Concepts documentation overview section
- **THEN** they understand that Concepts defines abstract security patterns that frameworks implement concretely
- **AND** they understand the separation between framework-agnostic concepts and framework-specific implementations

#### Scenario: 理解设计哲学

- **GIVEN** a developer wants to understand why Concepts are structured the way they are
- **WHEN** they read the design philosophy section
- **THEN** they understand the principles of:
  - Separation of concerns between concept definition and implementation
  - The Range pattern for API modeling
  - Integration with DataFlow and TaintTracking
  - Thread-model based source filtering

### Requirement: Concept Inventory Table

The documentation SHALL include a complete inventory table listing all security concepts defined in Concepts.qll, with summaries and primary use cases.

#### Scenario: 快速查找所需概念

- **GIVEN** a developer needs to detect SQL injection vulnerabilities
- **WHEN** they scan the concept inventory table
- **THEN** they find `SqlConstruction` and `SqlExecution` concepts with brief descriptions
- **AND** they can navigate to detailed documentation for each concept

#### Scenario: 发现可用的安全概念

- **GIVEN** a developer wants to know what security patterns are available
- **WHEN** they review the inventory table
- **THEN** they see all 30+ concepts organized by category (command execution, file operations, data encoding, HTTP, cryptography, etc.)

### Requirement: Detailed Concept Analysis

For each major security concept, the documentation SHALL provide detailed analysis including purpose, class hierarchy, key methods, usage patterns, and implementation constraints.

#### Scenario: 实现 SystemCommandExecution 概念

- **GIVEN** a developer needs to model command execution in a new framework
- **WHEN** they read the SystemCommandExecution concept documentation
- **THEN** they learn:
  - The concept detects OS command execution (e.g., spawning processes)
  - Key methods: `getCommand()` and `isShellInterpreted(arg)`
  - How to extend `SystemCommandExecution::Range` for new APIs
  - Example implementations from existing frameworks

#### Scenario: 理解 Decoding 与污点传播

- **GIVEN** a developer needs to model deserialization operations
- **WHEN** they read the Decoding concept documentation
- **THEN** they understand:
  - Decoding automatically preserves taint from input to output
  - The `mayExecuteInput()` predicate flags dangerous decoders
  - How `DecodingAdditionalTaintStep` integrates with TaintTracking
  - The `getFormat()` method identifies decoder types (JSON, XML, pickle, etc.)

#### Scenario: 区分 SqlConstruction 和 SqlExecution

- **GIVEN** a developer is modeling database query APIs
- **WHEN** they read the SQL concept documentation
- **THEN** they understand:
  - `SqlConstruction` detects query building (useful even if not executed)
  - `SqlExecution` requires actual query execution
  - When to use each concept based on security query requirements

### Requirement: Architecture Diagrams

The documentation SHALL include mermaid diagrams illustrating concept relationships, inheritance hierarchies, and data flow patterns.

#### Scenario: 可视化类继承层次

- **GIVEN** a developer wants to understand how concepts relate to each other
- **WHEN** they view the class hierarchy diagram
- **THEN** they see:
  - Base concepts (DataFlow::Node) at the root
  - Concept classes extending Range classes
  - Module structure with inner Range definitions
  - Specialized concepts like FileSystemWriteAccess extending FileSystemAccess

#### Scenario: 理解数据流集成

- **GIVEN** a developer needs to understand how concepts integrate with taint tracking
- **WHEN** they view the data flow integration diagram
- **THEN** they see:
  - How Encoding/Decoding register additional taint steps
  - How RemoteFlowSource integrates with RouteSetup
  - How barrier guards work with Path.SafeAccessCheck
  - ThreatModelSource filtering with currentThreatModel

#### Scenario: 框架实现工作流程

- **GIVEN** a new contributor wants to add framework support
- **WHEN** they view the implementation workflow diagram
- **THEN** they see the step-by-step process:
  1. Identify security-relevant APIs in the framework
  2. Select appropriate concepts from Concepts.qll
  3. Extend Range classes with framework-specific logic
  4. Implement required predicates (getCommand, getSql, etc.)
  5. Test with example queries

### Requirement: Implementation Patterns and Best Practices

The documentation SHALL provide guidance on common implementation patterns, the Range extension pattern, and best practices for concept usage.

#### Scenario: 理解 Range 扩展模式

- **GIVEN** a developer is implementing their first concept
- **WHEN** they read the Range pattern section
- **THEN** they understand:
  - Why Range classes exist (for modeling new APIs)
  - When to extend Range vs the concept class (new APIs vs refining existing)
  - The `instanceof` pattern that connects them
  - How the two-layer design prevents modeling conflicts

#### Scenario: 集成 TaintTracking 和 DataFlow

- **GIVEN** a developer needs their concept to participate in taint analysis
- **WHEN** they read the integration patterns section
- **THEN** they learn:
  - How to use `DataFlow::Node` as the base type
  - When to create `AdditionalTaintStep` classes
  - How to use `DataFlow::BarrierGuard` for sanitizers
  - Best practices for source/sink modeling

#### Scenario: 测试概念实现

- **GIVEN** a developer has implemented a new concept for their framework
- **WHEN** they read the testing section
- **THEN** they learn:
  - How to write test queries that use the concept
  - How to create test databases with vulnerable code
  - How to verify concept detection with known true positives
  - Regression testing strategies

### Requirement: Cross-References and Examples

The documentation SHALL include practical code examples from existing framework implementations and cross-references to related files and queries.

#### Scenario: 学习 Flask 框架实现

- **GIVEN** a developer wants to see real-world concept implementations
- **WHEN** they read the examples section for HTTP concepts
- **THEN** they find:
  - Links to Flask framework modeling files
  - Code snippets showing how Flask implements RouteSetup
  - How Flask models RequestHandler and HttpResponse
  - References to queries that use these concepts

#### Scenario: 查找相关查询

- **GIVEN** a developer implemented a new SqlExecution concept
- **WHEN** they check the cross-references
- **THEN** they find:
  - Links to sql-injection.ql queries that use SqlExecution
  - Related queries for SqlConstruction
  - Test cases demonstrating concept usage

### Requirement: Chinese Language Support

The documentation SHALL include Chinese language content in scenarios, explanations, and comments where appropriate for the educational CodeQL tutorial context.

#### Scenario: 中文场景描述

- **GIVEN** the project targets Chinese-speaking developers
- **WHEN** developers read scenario headers and key sections
- **THEN** they see Chinese language used in:
  - Scenario titles (e.g., "理解 Concepts.qll 的作用")
  - Key explanations and summaries
  - Educational comments and notes
- **AND** English is used for:
  - Code examples
  - Technical API names
  - Formal requirement statements
