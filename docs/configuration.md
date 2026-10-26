# Configuration reference

Configuration is JSON validated with Zod. Unknown top-level keys are rejected. Omitted values use defaults. `init` emits the complete default configuration; it does not edit target source.

| Setting | Default | Purpose |
| --- | --- | --- |
| `schemaVersion` | `1` | Configuration contract version. |
| `target` | `.` | Repository directory; resolved against the working directory. |
| `output` | `docs/codebase-intelligence` | Dedicated owned output root, resolved against the working directory. |
| `include` | `["**/*"]` | Included glob patterns. |
| `exclude` | `[]` | Additional exclusion globs. |
| `depth` | `standard` | `inventory`, `standard`, or `deep`; inventory skips source parsing. |
| `specialists` | All categories | Enabled categories: correctness, performance, security, testing, maintainability, architecture, dependencies, model-review. |
| `concurrency` | `4` | Parsing worker limit, from 1 to 16. |
| `tools.git` | `true` | Permit fixed read-only Git metadata commands. |
| `tools.python` | `true` | Permit isolated Python AST parsing. |
| `privacy.sendSource` | `false` | Permit selected redacted source to leave the process for configured model review. |
| `privacy.redact` | `true` | Required; cannot be disabled. |
| `network.enabled` | `false` | Permit optional model HTTP requests. |
| `network.allowedOrigins` | `[]` | Exact allowed API origins, including scheme and port. |
| `model.provider` | `none` | `none`, `openai-compatible`, `anthropic`, `gemini`, or `ollama`. |
| `model.name` | Empty | Provider-specific model ID; required for enabled model requests. |
| `model.baseUrl` | Empty | API prefix without credentials, query or fragment. |
| `model.apiKeyEnv` | `MODEL_API_KEY` | Name of the environment variable containing a credential. |
| `model.timeoutMs` | `30000` | Per-request timeout, at most 60000 ms. |
| `model.maxRetries` | `1` | Bounded retries for HTTP 429 and server failures, at most 3. |
| `retention` | `20` | Maximum recent runs displayed by `status`; stored history is never automatically deleted. |
| `verbosity` | `detailed` | Reserved report preference; canonical evidence is retained regardless. |
| `resume` | `reuse-unchanged` | `reuse-unchanged` permits compatible hash-based parser reuse; `restart` disables reuse. |

`standard` and `deep` currently share the implemented deterministic checks. Selecting deep does not enable whole-program semantics or prove additional framework support. Model context remains bounded regardless of depth.

## Budgets

| `budgets` key | Default |
| --- | --- |
| `maxFiles` | 30000 |
| `maxFileBytes` | 1048576 |
| `maxTotalBytes` | 150000000 |
| `maxRunSeconds` | 600 |
| `contextTokens` | 12000 estimated tokens |
| `maxModelCalls` | 8 actual HTTP attempts, including retries |
| `toolTimeoutMs` | 15000, at most 60000 |

Token accounting uses a conservative character estimate, not a provider tokenizer. Large source files and binary assets are excluded before parsing. Time and entry limits yield visible coverage failures rather than a claim of complete inspection.

## Priority weights

Defaults are severity 5, confidence 2, security 2, effort 1, risk 1. The generated roadmap records the exact formula and thresholds. The current score uses severity, confidence, a security-category bonus and fixed effort/uncertainty penalties. It is an explainable triage aid; it does not infer actual business impact, implementation duration or financial benefit.

## Ignored and sensitive inputs

Built-in exclusions prune VCS directories, dependency/vendor directories, generated/build/cache outputs and credential-bearing filenames. Nested `.gitignore` and `.intelignore` files contribute inventory rules. Symbolic links are not followed. The configured output root is excluded from analyzed input.

An exclusion record for a directory represents a pruned subtree, not an enumeration of every descendant. Configuration cannot disable the built-in source-write boundary or credential redaction.

## Local model example

```json
{
  "network": { "enabled": true, "allowedOrigins": ["http://127.0.0.1:11434"] },
  "privacy": { "sendSource": true, "redact": true },
  "model": {
    "provider": "ollama",
    "name": "YOUR_INSTALLED_MODEL_ID",
    "baseUrl": "http://127.0.0.1:11434"
  }
}
```

The model server must already be running and its model installed; the agent does not install or start inference servers. Local HTTP is restricted to loopback. Remote HTTPS review also requires the environment's outbound network policy to permit the origin; the configuration cannot bypass that policy.
