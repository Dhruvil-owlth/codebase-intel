# Extending adapters

The programmatic index API accepts an `AdapterRegistry`. The CLI currently builds the bundled registry; it does not dynamically load arbitrary repository plugins. This preserves the rule that analyzed repository code is never executed as an analyzer.

An adapter declares its ID, languages, version boundaries, analyzer recommendations, pitfalls, conventions, performance/security/test strategies and official reference entry points. Its `parse(context)` method fills the file's parser status, errors, symbols, imports, exports, references and optional complete finding records. Register a functioning parser and add fixtures before claiming deep support for a new ecosystem.

## Wrap an existing AST adapter

The following optional script adds a conservative organization-specific review candidate for unusually long exported JavaScript/TypeScript symbols. It reuses actual AST definitions and does not claim that length alone proves poor design. Save it as `work/custom-scan.mjs` in a built checkout and invoke it with an absolute target path and a new output path. It indexes in memory; it does not run the complete report pipeline.

```js
import { AdapterRegistry, buildIndex, loadConfig } from '../dist/index.js';
import { javascriptAdapter, pythonAdapter } from '../dist/adapters.js';
import { makeFinding } from '../dist/findings.js';

const config = await loadConfig(undefined, {
  target: process.argv[2],
  output: process.argv[3],
});
const reviewAdapter = {
  ...javascriptAdapter,
  id: 'organization-javascript',
  async parse(context) {
    await javascriptAdapter.parse(context);
    for (const symbol of context.file.symbols) {
      if (!symbol.exported || symbol.lineEnd - symbol.lineStart < 300) continue;
      context.file.findings.push(makeFinding(context.file, context.source, {
        rule: 'organization-long-export',
        title: 'Long exported definition warrants responsibility review',
        category: 'maintainability',
        severity: 'low',
        status: 'HYPOTHESIS',
        confidence: 0.4,
        symbol: symbol.name,
        lineStart: symbol.lineStart,
        lineEnd: symbol.lineEnd,
        description: 'The exported definition spans at least 301 source lines; responsibility and complexity have not been established.',
        recommendation: 'Review responsibilities and callers. Split the definition only if that improves a verified maintenance problem.',
        tests: ['Preserve the exported API and existing boundary behavior if any refactoring is accepted.'],
      }));
    }
  },
};
const registry = new AdapterRegistry()
  .register(reviewAdapter)
  .register(pythonAdapter);
const index = await buildIndex(config, undefined, { registry });
console.log(JSON.stringify({
  files: index.files.length,
  candidates: index.files.flatMap(file => file.findings).length,
  unsupported: index.coverage.unsupported.length,
}));
```

Register specialized adapters before broad adapters that match the same language. Registry selection uses the first compatible non-generic adapter. Duplicate adapter IDs are rejected; unmatched languages use the inventory-only fallback.

The example uses checkout-relative internal imports for `makeFinding`; the supported package exports expose the primary lifecycle, registry and schema APIs. A future plugin loader should use explicit trusted configuration and must not auto-load code from the target repository.

## Add a language

Use an existing mature AST parser or language-server protocol where practical. Treat parser input as untrusted data, bound memory/time/output, capture failures and expose unsupported syntax. Populate actual source locations; do not use lexical matches to claim semantic understanding. Add correct-code, buggy-code, import-resolution, broken-source, incremental and malicious-content fixtures.

## Add a model protocol

Arbitrary IDs already work within supported API families. A new wire protocol requires extending the configuration enum, endpoint/request/response adapter and mocked contract tests. Preserve exact-origin and source-sharing gates, credential selection, redirect rejection, response bounds, attempt budgeting and exact-evidence checks. No adapter may promote model suggestions above HYPOTHESIS.
