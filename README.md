# Codebase Intel

An offline-first CLI that indexes a repository, runs bounded static checks, records evidence-backed findings, and generates a dependency-aware engineering roadmap. It analyzes application source without changing it or executing its package scripts.

It accepts repositories of any project type. Deep support is deliberately narrower: JavaScript/TypeScript and Python have AST-based syntax analysis; other languages receive inventory-level coverage. Optional AI review supports configurable model IDs through four API families. These adapters do not guarantee compatibility with every model or API protocol.

## Install and audit

Requires Node.js 22 or newer and npm. Python 3 is optional and enables the Python AST adapter. Dependency installation needs access to the npm registry; the default audit itself works offline.

```sh
npm ci --ignore-scripts
npm run build
node dist/cli.js audit --target /path/to/repository --output /path/to/new-audit-output
```

Use a new or existing Codebase Intel output directory. The tool refuses a nonempty directory that it does not own. It writes reports and state below that root, never to the target source files. The output root may be inside the target; it is automatically excluded from the inventory.

The primary deliverable is:

```text
<output>/runs/<run-id>/12-implementation-roadmap/MASTER-IMPLEMENTATION-PLAN.md
```

The run README links the evidence, coverage, architecture, module reviews and canonical JSON records. Source references point to the original target checkout and include input hashes. Preserve that checkout or revalidate before acting on the findings.

## Commands

```sh
node dist/cli.js init
node dist/cli.js scan --target /repo --output /new/output
node dist/cli.js audit --target /repo --output /new/output
node dist/cli.js audit --target /repo --output /new/output --scope frontend
node dist/cli.js audit --target /repo --output /new/output --changed-only
node dist/cli.js resume --output /new/output --run <run-id>
node dist/cli.js report --output /new/output --run <run-id>
node dist/cli.js validate --output /new/output --run <run-id>
node dist/cli.js diff --output /new/output --from <older-run> --to <newer-run>
node dist/cli.js status --output /new/output
node dist/cli.js capabilities
node dist/cli.js query --output /new/output --run <run-id> --symbol functionName
node dist/cli.js implementation-plan --output /new/output --run <run-id> --task <task-id> --approve
```

Run `node dist/cli.js --help` for the exact options. Exit code `0` indicates a completed operation, `2` indicates partial analysis or an intentionally interrupted run, and `1` indicates a fatal error. Partial coverage is not hidden behind a clean result.

`--changed-only` compares file hashes with the preceding compatible audit and includes transitive local import dependents. It is not a Git diff. Scope selection restricts actionable findings while retaining an index for navigation and relationship analysis.

## Models and project types

The default provider is `none`. No model credential is needed for the deterministic audit. To use a remote or local model, choose a provider, model ID, API prefix and credential environment variable in `codebase-intel.json`. Both source-sharing permission and network permission must be explicit.

```json
{
  "target": "/path/to/repository",
  "output": "/path/to/new-audit-output",
  "network": {
    "enabled": true,
    "allowedOrigins": ["https://api.openai.com"]
  },
  "privacy": { "sendSource": true, "redact": true },
  "model": {
    "provider": "openai-compatible",
    "name": "YOUR_SUPPORTED_MODEL_ID",
    "baseUrl": "https://api.openai.com/v1",
    "apiKeyEnv": "MODEL_API_KEY"
  }
}
```

Supply the credential through your shell or secret manager. Do not put it in the JSON file. This configuration sends selected redacted source to the configured provider; review your repository's data handling requirements first. Redaction is a defensive filter, not a guarantee that every kind of sensitive information is removed.

| API family | Provider value | Example API prefix |
| --- | --- | --- |
| Chat Completions compatible | `openai-compatible` | `https://api.openai.com/v1` |
| Anthropic Messages | `anthropic` | `https://api.anthropic.com/v1` |
| Gemini generateContent | `gemini` | `https://generativelanguage.googleapis.com/v1beta` |
| Ollama chat | `ollama` | `http://127.0.0.1:11434` |

Any model ID accepted by one of these implemented request/response formats can be configured. Model families that require a different wire protocol need a new adapter. HTTPS is required except for explicitly allowlisted loopback HTTP. Redirects are rejected. Providers are covered by deterministic mocked contract tests; no live-provider behavior is implied by those tests.

Model suggestions must cite exact source evidence from the supplied context and remain `HYPOTHESIS`. A model cannot execute tools, change the repository, or turn a suggestion into a verified defect.

## Evidence and boundaries

- `SUPPORTED` records have strong static evidence; `HYPOTHESIS` records need investigation. `VERIFIED` requires successful direct validation.
- No project tests, package scripts, builds, profilers, vulnerability feeds or deployment commands execute by default.
- Performance findings do not contain invented timings or percentage gains. The roadmap requires measurement before setting targets.
- Business invariants, whole-program data flow, framework lifecycle semantics and runtime service boundaries are not fully reconstructed by the bundled checks.
- The implementation workflow prepares an explicitly approved task handoff. Autonomous code editing, worktree changes, test execution, merging and deployment are not implemented.

## Develop and verify

```sh
npm test
npm run check
npm run demo
```

The fixture demonstration contains intentional defects and should not be used as an application. See [the user guide](docs/user-guide.md), [configuration reference](docs/configuration.md), [architecture](docs/architecture.md), [support matrix](docs/support.md), [extension guide](docs/extending.md), and [security boundaries](docs/security.md).
