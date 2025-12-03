# Implementation Tasks: Add Flask SSTI Detection Documentation

## Task Checklist

### Phase 1: Content Research and Preparation
- [x] Read and understand `codeql/python/ql/src/Security/CWE-074/TemplateInjection.ql` query implementation
- [x] Read and understand `codeql/python/ql/lib/semmle/python/security/dataflow/TemplateInjectionCustomizations.qll`
- [x] Read and understand `codeql/python/ql/lib/semmle/python/security/dataflow/TemplateInjectionQuery.qll`
- [x] Review `codeql/python/ql/lib/semmle/python/Concepts.qll` for `TemplateConstruction` definition
- [x] Examine Flask.qll lines 725-735 for `FlaskTemplateConstruction` implementation
- [x] Examine Flask.qll lines 673-723 for flow summary implementations
- [x] Review test cases in `codeql/python/ql/test/query-tests/Security/CWE-074-TemplateInjection/`

### Phase 2: Documentation Structure Design
- [x] Design section outline for "5.5 模板注入（SSTI）检测"
- [x] Plan subsection hierarchy following existing document patterns
- [x] Identify code snippets to include from codebase
- [x] Design Mermaid diagram structure (3 diagrams planned)

### Phase 3: Content Writing
- [x] Write "5.5.1 SSTI 漏洞背景" subsection
  - Explain what SSTI is
  - Describe Flask's vulnerable functions
  - Reference CWE-074
- [x] Write "5.5.2 CodeQL 检测架构" subsection
  - Explain three-layer architecture
  - Show relationship between Query, Customizations, and Framework
- [x] Write "5.5.3 Flask.qll 中的 SSTI 支持" subsection
  - Explain `FlaskTemplateConstruction` class
  - Explain flow summaries for `render_template_string`
  - Show how `getSourceArg()` identifies template source
- [x] Write "5.5.4 检测流程串联" subsection
  - Explain source identification (flask.request)
  - Explain sink identification (render_template_string)
  - Explain taint tracking flow
- [x] Write "5.5.5 完整检测流程图" subsection with Mermaid diagrams
  - Diagram 1: High-level architecture (Query → Config → Framework)
  - Diagram 2: Detailed taint flow (Request → Taint Steps → Sink)
  - Diagram 3: Class relationship diagram
- [x] Write "5.5.6 代码示例" subsection
  - Vulnerable Flask application example
  - CodeQL query result interpretation
  - Step-by-step detection explanation

### Phase 4: Code References and Accuracy
- [x] Add file path references with line numbers where applicable
- [x] Verify all code snippets match actual source code
- [x] Ensure all class names and method names are accurate
- [x] Add links to referenced files using relative paths

### Phase 5: Diagram Creation
- [x] Create Mermaid diagram for detection architecture
- [x] Create Mermaid diagram for taint flow visualization
- [x] Create Mermaid diagram for class relationships
- [x] Test all Mermaid diagrams render correctly in GitHub/VS Code

### Phase 6: Integration and Polish
- [x] Insert new section into existing document at appropriate location (after section 5.4)
- [x] Update table of contents with new subsections
- [x] Ensure formatting consistency with existing document style
- [x] Verify Chinese language quality and terminology
- [x] Check internal document references and links

### Phase 7: Validation
- [x] Proofread entire new section
- [x] Verify technical accuracy against source code
- [x] Test all code examples for syntax correctness
- [x] Ensure Mermaid diagrams are syntactically valid
- [x] Check that section numbering is correct
- [x] Verify all file paths are correct and files exist

## Implementation Order
Tasks should be completed sequentially within each phase. Phases 1-2 must complete before Phase 3. Phase 3 can proceed in parallel subsections, but all content must complete before Phase 4. Phases 4-7 are sequential.

## Success Validation
After completing all tasks:
1. Document renders correctly in Markdown preview
2. All Mermaid diagrams display properly
3. All file references point to existing files
4. Section integrates seamlessly with existing content
5. Technical content is accurate per source code review

## Notes
- All content should be in Chinese to match existing document language
- Use existing document's formatting conventions (headings, code blocks, tables)
- Maintain educational tone appropriate for tutorial content
- Include both conceptual explanations and concrete code examples
