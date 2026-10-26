# Supported capabilities and limits

| Area | Implemented | Limits |
| --- | --- | --- |
| Repository input | Arbitrary local project directories; nested manifest ownership; source/config/test inventory | No remote clone, dependency installation or application execution during analysis. |
| JavaScript / TypeScript | Bundled TypeScript AST syntax parsing; definitions, imports, exports, identifier locations; bounded rules | No full type checking, alias-aware call graph, framework lifecycle analysis or runtime proof. |
| Python | Isolated stdlib AST parser; definitions/imports/references and bounded checks | Local Python 3 required; syntax support follows that interpreter. No module imports or type analysis. |
| Other languages | Language classification, file inventory, manifest/version detection where implemented, generic fallback | No semantic parser or language-specific finding support is claimed. |
| Frameworks | Dependency declarations identify names and version constraints; package-lock entries identify locked versions | React, Next.js, Django, Spring and other framework semantics need additional expert adapters. |
| Architecture | Manifest-based modules, local import navigation, cycles and Mermaid graph | No complete service, call, state, error or data-flow reconstruction. |
| Correctness | Literal conditions, inclusive array-bound/index pattern, NaN equality, empty catch, Python bare except | Findings remain static evidence; caller assumptions and shadowing can affect impact. |
| Performance | Membership checks within loops and benchmark requirements | Input types and sizes require verification; no CPU, memory, query or browser profiling. |
| Security | Dynamic evaluation, dynamic HTML and pickle sinks; credential-shaped literal checks | Input control and reachability are not proven; no taint engine, live attack or vulnerability feed. |
| Quality | Token-identical JS/TS function blocks and conventional test associations | Identical blocks can have different closures; indirect tests can be missed. |
| Dependencies | Inspected declarations and basic locked-version metadata; unbounded declaration checks | No guarantee of installation or advisory/vulnerability status. |
| Incremental work | Content hashes, compatible parser reuse, changed/dependent selection, persistent stages | Complex build-system dependency invalidation is outside the local import graph. |
| Reports | Canonical finding schema, Markdown views, source hashes/lines, roadmap DAG, coverage | Business requirements and production metrics require external evidence. |
| Model integration | Four configurable REST families; offline default; exact-evidence validation | Model IDs vary by provider. Responses-only, Bedrock, Azure-specific deployment protocols and custom APIs need adapters. |
| Implementation | Explicitly approved task preparation and handoff | No autonomous editing, worktree creation, target test execution, merge or deployment engine. |

## Testing scope

Tests are deterministic and use intentionally buggy/correct repository fixtures and local mocked HTTP providers. They cover indexing, rules, workflow state, report/schema/link validation, dependency ordering and security boundaries. Mock API tests establish request/response contracts; they do not establish current availability, access permissions or quality for a live model.

## What zero findings means

No enabled check found a defensible issue in the inspected inputs. It does not mean complete repository understanding, complete test coverage, secure production operation or optimal performance. Read the machine-readable coverage ledger and source-specific uncertainty before making that inference.
