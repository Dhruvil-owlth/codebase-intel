# Security boundaries

Repository files, comments, filenames, manifests and generated text are untrusted input. The audit reads them as data and does not execute package scripts or follow embedded instructions. Default model and network access are disabled.

## Filesystem

The target source tree is read-only from the audit's perspective. Writes use a separate owned output root and atomic temporary files. Relative-path traversal, symlink ancestors and non-regular input files are refused. The output directory is excluded from input. VCS, vendor, generated and credential-bearing paths are excluded by default.

These application-level checks are defense in depth, not an operating-system sandbox. A hostile process that concurrently replaces paths can create filesystem race conditions. Run audits of untrusted repositories under a separate OS/container boundary with source mounted read-only and output mounted separately when stronger isolation is required. The CLI does not create that sandbox automatically.

## Subprocesses

Only fixed Git object/index metadata commands and an isolated Python AST helper are available by default. Git status and working-tree diffs are excluded because repository-configured content filters can execute programs. Working-tree candidates compare included raw file bytes with index blobs, without applying filters; staged changes, modes and excluded/deleted paths are not assessed. The helper receives source on stdin and uses `ast.parse`; it does not execute or import target code. Tool runtime and output are bounded. Tests, linters, package managers, builds, benchmarks and infrastructure commands from the target repository do not run automatically.

The interpreter and Git binaries come from the host PATH. Use a trusted runtime environment; a repository directory containing a fake executable must not be placed in PATH. Tools operate without shell interpretation.

## Source and secrets

Credential-bearing filenames are excluded before reading. Common token formats, private keys, password assignments and credential URLs are redacted from source evidence, logs and model context. The index stores metadata and redacted evidence rather than complete source text. Redaction is heuristic and can miss domain-specific sensitive data. Treat generated artifacts as potentially sensitive and apply the repository's retention and access policy.

Model credentials are read only through the configured environment-variable name and are not stored in configuration or reports. No credential values or provider error bodies are intentionally logged.

## Optional model requests

Model review requires `privacy.sendSource`, `network.enabled`, and the exact endpoint origin in `network.allowedOrigins`. Remote endpoints require HTTPS; explicitly allowed loopback HTTP supports local inference servers. Credentials, query strings and fragments are rejected in API base URLs. Redirects are refused. Requests have time, response-size, retry and call-count bounds.

The system prompt treats repository content as untrusted data. Models have no execution tools, and their output is parsed as a limited schema. Every accepted finding must cite exact lines that were present in the supplied context and match the current source hash. All accepted model findings remain hypotheses. These controls limit consequences; they cannot guarantee that a model follows instructions or that its reasoning is correct.

## Implementation workflow

Preparation requires explicit approval and a selected task scope. The current release generates a handoff only. No application edits, target tests, branch/worktree changes, merges or deployments occur. A future implementation engine must add isolated execution, reviewed command permissions, baseline checks, diff review and evidence-backed completion before these capabilities are claimed.
