# Proposal: Add Flask SSTI Detection Documentation

## Change ID
`add-flask-ssti-detection-docs`

## Overview
Supplement the existing Flask.qll analysis documentation (`docs/python-flask-qll-analysis.md`) with comprehensive coverage of Server-Side Template Injection (SSTI) detection. This enhancement will explain the complete detection flow from query definition through Flask framework modeling, including concrete examples and visual flow diagrams.

## Motivation
The current documentation thoroughly covers Flask.qll's API modeling patterns but lacks explanation of how these models enable specific security vulnerability detection. SSTI (CWE-074) is a critical vulnerability in web applications, and understanding how CodeQL detects it through Flask framework modeling is essential for:

1. **Educational value**: Learners need to understand the end-to-end flow from user input to template injection sink
2. **Framework extension**: Developers adding support for new template engines need reference patterns
3. **Query development**: Security researchers writing custom SSTI queries benefit from understanding the underlying infrastructure

## Current State
- `docs/python-flask-qll-analysis.md` covers Flask.qll API modeling comprehensively
- References to `FlaskTemplateConstruction` exist but without context about SSTI detection
- No explanation of how `TemplateInjection.ql` query connects to Flask.qll modeling
- Missing visual representation of the detection flow

## Proposed Changes
Add new section **"5.5 模板注入（SSTI）检测"** to `docs/python-flask-qll-analysis.md` covering:

### Content Structure
1. **SSTI Vulnerability Background**
   - What is server-side template injection
   - Why Flask's `render_template_string()` is dangerous
   - CWE-074 context

2. **CodeQL Detection Architecture**
   - Overview of the taint tracking approach
   - Three-layer architecture: Query → Customizations → Framework modeling

3. **Flask.qll Implementation Details**
   - `FlaskTemplateConstruction` class explanation
   - How it extends `TemplateConstruction::Range`
   - The role of `getSourceArg()` in identifying vulnerable parameters
   - Flow summaries for `render_template_string` and `stream_template_string`

4. **Detection Flow Explanation**
   - Source: User input from `flask.request`
   - Sink: Template construction via `render_template_string()`
   - Taint tracking configuration
   - How `TemplateInjectionFlow` connects sources to sinks

5. **Mermaid Flow Diagrams**
   - High-level detection architecture diagram
   - Detailed taint flow diagram showing data propagation
   - Component interaction diagram

6. **Code Examples**
   - Vulnerable Flask code snippet
   - How CodeQL models each component
   - Query result interpretation

## Benefits
- **Complete learning path**: Students can trace from query to framework implementation
- **Reusable patterns**: Template for documenting other vulnerability types (XSS, SQLi, etc.)
- **Framework consistency**: Demonstrates how framework modeling enables security queries
- **Visual clarity**: Mermaid diagrams make complex flows understandable

## Scope
**In Scope:**
- Documentation additions only
- Chinese language content (matching existing doc style)
- Mermaid diagram integration
- Code reference examples from existing codebase

**Out of Scope:**
- Modifications to actual `.ql` or `.qll` files
- New query development
- Changes to CodeQL library code
- Translation to other languages

## Success Criteria
1. New section seamlessly integrates with existing document structure
2. All code references point to actual files in the codebase
3. Mermaid diagrams render correctly in Markdown viewers
4. Technical accuracy verified against CodeQL source code
5. Documentation follows existing style and formatting conventions

## Implementation Notes
- Will reference actual file paths: `codeql/python/ql/src/Security/CWE-074/TemplateInjection.ql`
- Will include line number references where appropriate
- Mermaid syntax should be GitHub-compatible
- Code snippets should include syntax highlighting markers

## Related Work
- Complements existing Flask.qll documentation structure
- Provides pattern for future security-focused documentation sections
- Aligns with project's educational mission for CodeQL learning

## Open Questions
None - the scope is well-defined as documentation enhancement based on existing implementation.
