import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConfigSchema, FindingSchema } from '../dist/schema.js';
import { buildIndex } from '../dist/indexer.js';
import { analyze, stronglyConnected } from '../dist/analysis.js';
import { prioritize } from '../dist/findings.js';
import { retrieve } from '../dist/retrieval.js';
import { defaultRegistry, languageOf, AdapterRegistry } from '../dist/adapters.js';
import { atomicWrite, safeRead, relativePath, redact, hash } from '../dist/safety.js';
import { runTool } from '../dist/tools.js';
import { initConfig, loadConfig } from '../dist/config.js';

const fixture = name => fileURLToPath(new URL(`./fixtures/${name}/`, import.meta.url));

async function setup(t, name = 'polyglot', overrides = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'codebase-intel-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const target = path.join(root, 'repository');
  await fs.cp(fixture(name), target, { recursive: true });
  const config = ConfigSchema.parse({ target, output: path.join(root, 'reports'), tools: { git: false, python: true }, ...overrides });
  return { root, target, config };
}

test('adapter registry exposes real language support and an explicit fallback', () => {
  const registry = defaultRegistry();
  assert.equal(registry.forLanguage('TypeScript').id, 'javascript-typescript');
  assert.equal(registry.forLanguage('JavaScript').id, 'javascript-typescript');
  assert.equal(registry.forLanguage('Python').id, 'python');
  assert.equal(registry.forLanguage('Go').id, 'generic');
  assert.equal(languageOf('thing.tsx'), 'TypeScript');
  assert.equal(languageOf('thing.go'), 'Go');
  assert.throws(() => new AdapterRegistry().register(registry.forLanguage('Python')).register(registry.forLanguage('Python')), /Duplicate/);
});

test('AST indexing and specialists identify representative issues with genuine evidence', async t => {
  const { config } = await setup(t);
  const index = await buildIndex(config);
  const findings = await analyze(index, config);
  const rules = new Set(findings.map(f => f.rule));
  for (const expected of ['array-off-by-one', 'nan-equality', 'loop-membership', 'dynamic-html', 'dynamic-eval', 'python-bare-except', 'duplicate-function-body', 'unbounded-dependency', 'test-association-gap', 'import-cycle']) {
    assert.ok(rules.has(expected), `Missing expected rule ${expected}`);
  }
  assert.equal(findings.filter(f => f.path === 'src/correct.ts').length, 0, 'Correct fixture source and comments must not trigger source findings');
  assert.ok(index.files.find(f => f.path === 'src/main.ts').symbols.some(s => s.name === 'inclusiveSum'));
  assert.ok(index.edges.some(e => e.from === 'src/main.ts' && e.to === 'src/a.ts'));
  assert.ok(index.files.find(f => f.path === 'tests/correct.test.ts').testsFor.includes('src/correct.ts'));
  assert.ok(index.technologies.some(x => x.name === 'Python' && x.version === '>=3.10'));
  assert.ok(index.technologies.some(x => x.name === 'Go' && x.adapter === 'generic'));
  assert.ok(index.coverage.unsupported.some(x => x.includes('Go')));
  for (const finding of findings) {
    assert.equal(FindingSchema.safeParse(finding).success, true, finding.id);
    assert.notEqual(finding.status, 'VERIFIED', 'Static source inspection must not claim dynamic reproduction');
    for (const evidence of finding.evidence) {
      const source = await safeRead(config.target, evidence.path);
      assert.equal(hash(source), evidence.hash);
      assert.ok(evidence.lineStart >= 1 && evidence.lineEnd <= source.split(/\r?\n/).length);
      assert.ok(redact(source.split(/\r?\n/).slice(evidence.lineStart - 1, evidence.lineEnd).join('\n')).startsWith(evidence.snippet));
    }
  }
  assert.ok(findings.filter(f => f.category === 'performance').every(f => f.benchmarks.length && f.measurement !== 'measured'));
});

test('a correct fixture produces no fabricated defect or missing-test report', async t => {
  const { config } = await setup(t, 'correct');
  const index = await buildIndex(config);
  assert.deepEqual(await analyze(index, config), []);
  assert.equal(index.coverage.failed.length, 0);
});

test('finding IDs remain stable and priority weights are explainable/configurable', async t => {
  const { config } = await setup(t);
  const index = await buildIndex(config);
  const first = await analyze(index, config);
  const second = await analyze(index, config);
  assert.deepEqual(first.map(f => f.id), second.map(f => f.id));
  const ranked = prioritize(structuredClone(first), config);
  assert.ok(ranked.every((f, i) => i === 0 || ranked[i - 1].score >= f.score));
  const boost = ConfigSchema.parse({ ...config, weights: { ...config.weights, security: 100 } });
  assert.equal(prioritize(structuredClone(first), boost)[0].category, 'security');
  assert.equal(ConfigSchema.safeParse({ weights: { severity: -1 } }).success, false);
  const incomplete = { ...first[0] }; delete incomplete.evidence;
  assert.equal(FindingSchema.safeParse(incomplete).success, false);
});

test('local import cycles are found without inventing cycles in a DAG', () => {
  const edges = [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }, { from: 'c', to: 'b' }, { from: 'd', to: 'a' }];
  assert.deepEqual(stronglyConnected(['a', 'b', 'c', 'd'], edges), [['b', 'c']]);
  assert.deepEqual(stronglyConnected(['a', 'b', 'c', 'd'], edges.filter(e => e.from !== 'c')), []);
  const names = Array.from({ length: 15000 }, (_, i) => `m${i}`);
  assert.deepEqual(stronglyConnected(names, names.slice(1).map((to, i) => ({ from: names[i], to }))), []);
});

test('incremental indexing reuses unchanged ASTs and invalidates transitive dependents', async t => {
  const { target, config } = await setup(t);
  const first = await buildIndex(config);
  const unchanged = await buildIndex(config, first);
  assert.equal(unchanged.coverage.reused, first.files.length);
  assert.deepEqual(unchanged.coverage.changed, []);
  await fs.appendFile(path.join(target, 'src/b.ts'), '\nexport const changed = 1;\n');
  const changed = await buildIndex(config, first, { changedOnly: true });
  assert.ok(changed.coverage.changed.includes('src/b.ts'));
  assert.ok(changed.coverage.invalidated.includes('src/a.ts'));
  assert.ok(changed.coverage.invalidated.includes('src/main.ts'));
  assert.ok(changed.coverage.scopedOut.includes('src/correct.ts'));
  const scopedFindings = await analyze(changed, config);
  assert.ok(scopedFindings.every(f => !changed.coverage.scopedOut.includes(f.path)));
  await fs.rm(path.join(target, 'src/b.ts'));
  const deleted = await buildIndex(config, changed, { changedOnly: true });
  assert.ok(deleted.coverage.changed.includes('src/b.ts'));
  assert.ok(deleted.coverage.invalidated.includes('src/a.ts'));
  assert.ok(!deleted.files.some(f => f.path === 'src/b.ts'));
});

test('path scope includes selected subsystem and excludes unrelated finding sources', async t => {
  const { config } = await setup(t);
  const index = await buildIndex(config, undefined, { scope: 'python' });
  const findings = await analyze(index, config);
  assert.ok(findings.length > 0);
  assert.ok(findings.every(f => f.path.startsWith('python/')));
  assert.ok(index.coverage.scopedOut.includes('src/main.ts'));
});

test('retrieval supports exact symbols, path filters, keywords and bounded related context', async t => {
  const { config } = await setup(t);
  const index = await buildIndex(config);
  const direct = await retrieve(index, config, { symbol: 'inclusiveSum', path: 'src/**' });
  assert.equal(direct.items.length, 1);
  assert.equal(direct.items[0].path, 'src/main.ts');
  assert.ok(direct.items[0].source.includes('i <= values.length'));
  const related = await retrieve(index, config, { path: 'src/a.ts', related: true, tokens: 512 });
  assert.ok(related.items.some(x => x.path === 'src/b.ts'));
  assert.ok(related.estimatedTokens <= 512);
  const keyword = await retrieve(index, config, { keyword: 'suppliedHtml', path: 'src/main.ts' });
  assert.ok(keyword.items.length > 0);
  await assert.rejects(retrieve(index, config, {}), /Provide/);
  await fs.appendFile(path.join(config.target, 'src/main.ts'), '\n// changed\n');
  await assert.rejects(retrieve(index, config, { symbol: 'inclusiveSum' }), /stale/);
});

test('parser errors remain visible while valid files continue to be analyzed', async t => {
  const { target, config } = await setup(t);
  await fs.writeFile(path.join(target, 'src/broken.ts'), 'export function broken( {\n');
  await fs.writeFile(path.join(target, 'python/broken.py'), 'def broken(:\n');
  const index = await buildIndex(config);
  assert.ok(index.coverage.failed.some(x => x.path === 'src/broken.ts'));
  assert.ok(index.coverage.failed.some(x => x.path === 'python/broken.py'));
  assert.ok((await analyze(index, config)).some(x => x.rule === 'array-off-by-one'));
});

test('a failing registered adapter is isolated and its failure remains visible', async t => {
  const { config } = await setup(t);
  const registry = defaultRegistry();
  const generic = registry.forLanguage('Go');
  registry.register({ ...generic, id: 'failing-go-test-adapter', languages: ['Go'], compatible: language => language === 'Go',
    async parse() { throw new Error('Intentional adapter failure'); }
  });
  const index = await buildIndex(config, undefined, { registry });
  assert.ok(index.coverage.failed.some(f => f.path === 'go/main.go' && f.reason.includes('Intentional adapter failure')));
  assert.equal(index.files.find(f => f.path === 'go/main.go').parser, 'failed');
  assert.ok((await analyze(index, config)).some(f => f.rule === 'array-off-by-one'));
});

test('disabled Python analyzer and inventory depth never claim semantic coverage', async t => {
  const { config } = await setup(t, 'polyglot', { tools: { git: false, python: false } });
  const noPython = await buildIndex(config);
  assert.ok(noPython.coverage.failed.some(x => x.path === 'python/worker.py'));
  assert.equal(noPython.files.find(f => f.path === 'python/worker.py').parser, 'unavailable');
  const inventoryConfig = ConfigSchema.parse({ ...config, depth: 'inventory' });
  const inventory = await buildIndex(inventoryConfig);
  assert.equal(inventory.coverage.parsed.length, 0);
  assert.deepEqual(await analyze(inventory, inventoryConfig), []);
});

test('untrusted instructions, package scripts, ignored paths and credential files are inert', async t => {
  const { target, config } = await setup(t);
  await fs.mkdir(path.join(target, 'ignored'), { recursive: true });
  await fs.writeFile(path.join(target, 'ignored/hidden.ts'), 'export const hidden = eval(input);');
  await fs.writeFile(path.join(target, '.env'), 'SECRET=do-not-read-or-disclose');
  await fs.writeFile(path.join(target, 'id_rsa'), 'do-not-read-or-disclose');
  const index = await buildIndex(config);
  await analyze(index, config);
  assert.ok(index.coverage.excluded.some(x => x.path === '.env' && /Credential/.test(x.reason)));
  assert.ok(index.coverage.excluded.some(x => x.path === 'ignored'));
  assert.ok(!index.files.some(x => x.path.startsWith('ignored/') || x.path === '.env' || x.path === 'id_rsa'));
  await assert.rejects(fs.access(path.join(target, 'DANGEROUS_EXECUTED')));
  await assert.rejects(runTool('git', ['status'], target, undefined, config), /allowlisted/);
});

test('path traversal, symlink reads and symlink output writes are rejected', async t => {
  const { root, target } = await setup(t, 'correct');
  const outside = path.join(root, 'outside.txt'); await fs.writeFile(outside, 'outside secret');
  await fs.symlink(outside, path.join(target, 'linked.ts'));
  await fs.symlink(root, path.join(target, 'linked-directory'));
  assert.throws(() => relativePath(target, '../outside.txt'), /escapes/);
  assert.throws(() => relativePath(target, '/etc/passwd'), /Unsafe/);
  await assert.rejects(safeRead(target, 'linked.ts'), /Symlink/);
  await assert.rejects(safeRead(target, 'linked-directory/outside.txt'), /Symlink/);
  await assert.rejects(atomicWrite(target, 'linked.ts', 'overwritten'), /Symlink/);
  assert.equal(await fs.readFile(outside, 'utf8'), 'outside secret');
  const config = ConfigSchema.parse({ target, output: path.join(root, 'reports'), tools: { git: false, python: false } });
  const index = await buildIndex(config);
  assert.ok(index.coverage.excluded.some(x => x.path === 'linked.ts'));
  assert.ok(!index.files.some(x => x.path.startsWith('linked')));
});

test('redaction removes recognized credentials, passwords, query secrets and private keys', () => {
  const text = [
    'const apiKey = "sk-examplecredential12345678901234567890";',
    'password="not-public"',
    'https://name:password@example.invalid/x?token=not-public',
    '-----BEGIN PRIVATE KEY-----\nnot-public\n-----END PRIVATE KEY-----'
  ].join('\n');
  const output = redact(text);
  assert.ok(!output.includes('not-public'));
  assert.ok(!output.includes('sk-examplecredential'));
  assert.ok(output.includes('REDACTED'));
});

test('all canonical evidence snippets redact credential-shaped values, including duplicate peers', async t => {
  const { target, config } = await setup(t, 'correct');
  const token = 'sk-fixturecredential123456789012345678901234';
  const body = `\n  const apiKey = "${token}";\n  const size = apiKey.length;\n  const marker = size + 1;\n  return marker;\n`;
  await fs.writeFile(path.join(target, 'credentials.ts'), `export function firstSecret() {${body}}\nexport function secondSecret() {${body}}\n`);
  const index = await buildIndex(config);
  const findings = await analyze(index, config);
  assert.ok(findings.some(f => f.rule === 'credential-pattern'));
  assert.ok(findings.some(f => f.rule === 'duplicate-function-body'));
  assert.ok(!JSON.stringify(findings).includes(token), 'Any evidence field containing the original credential is a disclosure');
});

test('configuration initializes once, validates schema and refuses unowned output roots', async t => {
  const { root, target } = await setup(t, 'correct');
  const file = await initConfig(root);
  assert.equal(JSON.parse(await fs.readFile(file, 'utf8')).model.provider, 'none');
  await assert.rejects(initConfig(root), /already exists/);
  const config = await loadConfig(file, { target, output: path.join(root, 'reports') });
  assert.equal(config.target, await fs.realpath(target));
  await fs.mkdir(path.join(root, 'existing')); await fs.writeFile(path.join(root, 'existing/user.md'), 'keep me');
  await assert.rejects(loadConfig(file, { target, output: path.join(root, 'existing') }), /not an owned/);
  await assert.rejects(loadConfig(file, { target, output: target }), /must not equal/);
  assert.equal(ConfigSchema.safeParse({ privacy: { redact: false } }).success, false);
});
