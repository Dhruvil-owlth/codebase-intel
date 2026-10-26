# User guide

## First audit

Install dependencies and build the CLI as described in the project README. An audit accepts a target repository and a dedicated output directory:

```sh
node dist/cli.js audit --target /repo --output /audits/my-project
```

Open the run's README, then read `12-implementation-roadmap/MASTER-IMPLEMENTATION-PLAN.md`. Review `00-execution/scope-and-limitations.md` before treating the backlog as an engineering commitment. Findings are source-specific records with stable IDs, classifications, source hashes, exact line bounds, test requirements and uncertainty.

Output directories carry a Codebase Intel ownership marker. A nonempty arbitrary directory is refused. Reports for separate runs remain in separate `runs/<id>/` directories. Do not point output at an existing application source directory.

## Initialize and configure

`node dist/cli.js init` writes `codebase-intel.json` in the current directory and refuses to overwrite an existing configuration. CLI target/output options override the corresponding JSON settings. See the configuration reference for model, budget and privacy settings.

The audit's analysis mode is read-only with respect to application source. File reads, deterministic parsing, fixed read-only Git metadata commands, and the isolated Python AST helper are the default execution surface. Repository instructions are data and cannot authorize script execution.

## Scope and incremental audits

`--scope frontend` selects matching directory components; path prefixes and glob patterns can also select files. The index still records repository relationships needed for context. Scope omissions appear in coverage.

`--changed-only` compares content hashes against the previous compatible run and expands the selected set to local import dependents. Removed files invalidate their previous dependents. The first audit has no previous baseline, so all included inputs are new. Parser metadata for unchanged inputs may be reused; cross-file graph analysis is recomputed. This is a content-hash workflow, not an automatic interpretation of uncommitted Git changes.

## Resume and retry

Runs persist stage state, attempts, input hashes, findings, errors and model-call counts. Resume using the original output root and ID:

```sh
node dist/cli.js resume --output /audits/my-project --run <run-id>
```

Read the command's status and failure list afterward. A successful earlier stage does not hide a failed parser or optional model stage. If source has changed since the checkpoint, the run must refresh evidence rather than reuse stale findings. Interrupted or partially failed audits can still contain useful reports, but their limitations remain visible.

## Retrieve and compare

Use `query` for exact symbol lookup, path-aware retrieval and keyword navigation without loading the whole repository into model context. Use `diff --from <id> --to <id>` to compare recorded findings between audits. Stable IDs are based on rule, source identity and evidence content; changing the evidence can change an ID.

`report` regenerates Markdown from canonical records. `validate` checks schemas, source references, relative links and roadmap dependencies. Moving the checkout or report tree can make source links invalid; regenerate or revalidate against the intended source snapshot.

## Read classifications correctly

| Classification | Meaning |
| --- | --- |
| VERIFIED | Successful direct validation supports the issue. |
| SUPPORTED | Strong static/source evidence; no dynamic reproduction is implied. |
| HYPOTHESIS | Plausible concern requiring investigation. |
| NOT_EVALUATED | Reliable assessment was not possible. |

An import cycle is a graph fact, but it does not prove an initialization failure. A dynamic evaluation sink does not prove attacker-controlled input reaches it. A missing conventional test association does not prove missing integration coverage. Each finding includes these limits.

## Prepare implementation

Select a stable roadmap task ID and explicitly approve preparation:

```sh
node dist/cli.js implementation-plan --output /audits/my-project --run <run-id> --task <task-id> --approve
```

This produces a reviewable implementation handoff and checks the available prerequisites. It does not apply edits, create a worktree, run the target test suite, merge or deploy. A coding agent or engineer must implement the reviewed task in a separately controlled workflow and capture baseline, targeted, regression and benchmark evidence.

## Diagnose partial results

Read coverage failures and unsupported paths, then inspect captured analyzer results. Common causes include unsupported syntax, unavailable Python, excluded generated/vendor trees, file size budgets, a time limit, a model rate limit or evidence that changed after indexing. Increase a budget or add an adapter only when justified by the intended scope. Do not interpret zero findings as proof of a healthy repository.
