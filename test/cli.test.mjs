import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ConfigSchema } from '../dist/schema.js';
import { hash } from '../dist/safety.js';

const fixture = name => fileURLToPath(new URL(`./fixtures/${name}/`, import.meta.url));
const cliFile = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
async function setup(t, name = 'polyglot') {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'codebase-intel-e2e-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const target = path.join(root, 'repository');
  await fs.cp(fixture(name), target, { recursive: true });
  const config = ConfigSchema.parse({ target, output: path.join(root, 'reports'), tools: { git: false, python: true } });
  return { root, target, config };
}
async function sourceHashes(directory) {
  const result = {};
  const walk = async relative => {
    for (const entry of await fs.readdir(path.join(directory, relative), { withFileTypes: true })) {
      const p = path.join(relative, entry.name);
      if (entry.isDirectory()) await walk(p);
      else if (entry.isFile()) result[p] = hash(await fs.readFile(path.join(directory, p)));
    }
  };
  await walk('');
  return result;
}
async function cli(args, cwd) {
  return await new Promise((resolve, reject) => {
    const env = { ...process.env };
    // An application subprocess is not a nested Node test-runner worker.
    delete env.NODE_TEST_CONTEXT;
    const child = spawn(process.execPath, [cliFile, ...args], { cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => stdout += chunk.toString());
    child.stderr.on('data', chunk => stderr += chunk.toString());
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('CLI smoke test timeout')); }, 20000);
    child.on('error', error => { clearTimeout(timeout); reject(error); });
    child.on('close', code => { clearTimeout(timeout); resolve({ code, stdout, stderr }); });
  });
}
function assertTaskGraph(roadmap, findings) {
  const ids = new Set(roadmap.tasks.map(task => task.id));
  assert.equal(ids.size, roadmap.tasks.length);
  const findingIds = new Set(findings.map(finding => finding.id));
  for (const task of roadmap.tasks) {
    for (const dependency of task.dependencies) assert.ok(ids.has(dependency), `Unknown task dependency ${dependency}`);
    for (const finding of task.findings) assert.ok(findingIds.has(finding), `Unknown finding reference ${finding}`);
    assert.ok(task.steps.length && task.tests.length && task.done.length, `Task ${task.id} must be actionable`);
  }
  const visited = new Set(), visiting = new Set();
  function visit(id) {
    assert.ok(!visiting.has(id), `Dependency cycle at ${id}`);
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of roadmap.tasks.find(task => task.id === id).dependencies) visit(dependency);
    visiting.delete(id); visited.add(id);
  }
  for (const id of ids) visit(id);
  for (const group of roadmap.parallelGroups) {
    for (const id of group) assert.ok(!roadmap.tasks.find(task => task.id === id).dependencies.some(d => group.includes(d)));
  }
}

test('end-to-end audit generates validated evidence, task graph and reports without changing source', async t => {
  const { target, config } = await setup(t);
  const { audit, loadRun } = await import('../dist/orchestrator.js');
  const { validateRun } = await import('../dist/verify.js');
  const before = await sourceHashes(target);
  const run = await audit(config);
  assert.ok(['complete', 'partial'].includes(run.status));
  assert.ok(run.findings.length > 0);
  assert.ok(run.documents.some(p => p.endsWith('MASTER-IMPLEMENTATION-PLAN.md')));
  assert.ok(run.documents.some(p => p.endsWith('findings.json')));
  assert.ok(run.roadmap.tasks.length > 0);
  assertTaskGraph(run.roadmap, run.findings);
  assert.equal((await validateRun(run)).valid, true);
  assert.equal((await loadRun(config.output, run.id)).id, run.id);
  assert.deepEqual(await sourceHashes(target), before);
  await assert.rejects(fs.access(path.join(target, 'DANGEROUS_EXECUTED')));
});

test('interrupted audit resumes persisted tasks and unchanged evidence', async t => {
  const { config } = await setup(t, 'correct');
  const { audit, resumeRun, loadRun } = await import('../dist/orchestrator.js');
  const interrupted = await audit(config, { stopAfter: 'discovery' });
  const checkpoint = await loadRun(config.output, interrupted.id);
  assert.equal(checkpoint.tasks.discovery.status, 'complete');
  assert.notEqual(checkpoint.tasks.verification.status, 'complete');
  const resumed = await resumeRun(config.output, interrupted.id);
  assert.equal(resumed.id, interrupted.id);
  assert.equal(resumed.tasks.verification.status, 'complete');
  assert.equal(resumed.validation.valid, true);
  assert.equal(resumed.tasks.discovery.attempts, checkpoint.tasks.discovery.attempts);
});

test('resuming after target changes refreshes stale source findings', async t => {
  const { target, config } = await setup(t);
  const { audit, resumeRun } = await import('../dist/orchestrator.js');
  const stopped = await audit(config, { stopAfter: 'specialists' });
  assert.ok(stopped.findings.some(f => f.rule === 'array-off-by-one'));
  const main = path.join(target, 'src/main.ts');
  await fs.writeFile(main, (await fs.readFile(main, 'utf8')).replace('i <= values.length', 'i < values.length'));
  const resumed = await resumeRun(config.output, stopped.id);
  assert.equal(resumed.id, stopped.id);
  assert.ok(!resumed.findings.some(f => f.rule === 'array-off-by-one'));
  assert.equal(resumed.index.files.find(f => f.path === 'src/main.ts').hash, hash(await fs.readFile(main)));
  assert.equal(resumed.validation.valid, true);
});

test('verification rejects tampered source ranges and roadmap dependency cycles', async t => {
  const { config } = await setup(t);
  const { audit } = await import('../dist/orchestrator.js');
  const { validateRun } = await import('../dist/verify.js');
  const run = await audit(config);
  const badEvidence = structuredClone(run);
  badEvidence.findings[0].lineEnd = 1000000;
  badEvidence.findings[0].evidence[0].lineEnd = 1000000;
  assert.equal((await validateRun(badEvidence)).valid, false);
  const cycle = structuredClone(run);
  cycle.roadmap.tasks[0].dependencies.push(cycle.roadmap.tasks[1].id);
  cycle.roadmap.tasks[1].dependencies.push(cycle.roadmap.tasks[0].id);
  assert.equal((await validateRun(cycle)).valid, false);
  const duplicate = structuredClone(run);
  duplicate.findings.push(structuredClone(duplicate.findings[0]));
  assert.equal((await validateRun(duplicate)).valid, false);
});

test('verification rejects corrupt generated canonical JSON artifacts', async t => {
  const { config } = await setup(t, 'correct');
  const { audit, runRoot } = await import('../dist/orchestrator.js');
  const { validateRun } = await import('../dist/verify.js');
  const run = await audit(config);
  const findingsFile = path.join(runRoot(run), '13-machine-readable/findings.json');
  await fs.writeFile(findingsFile, '{"not":"the findings schema"}\n');
  const invalid = await validateRun(run);
  assert.equal(invalid.valid, false, 'Validation must inspect generated JSON records, not only the in-memory run');
});

test('source strings containing Markdown-looking links cannot invalidate canonical JSON artifacts', async t => {
  const { target, config } = await setup(t, 'correct');
  const { audit } = await import('../dist/orchestrator.js');
  await fs.writeFile(path.join(target, 'markup.ts'), 'export function flagged() { if (false) return "[source example](../../../../etc/passwd)"; }\n');
  const run = await audit(config);
  assert.equal(run.validation.valid, true, JSON.stringify(run.validation.errors));
});

test('CLI initialize and one-command audit complete with useful exit status', async t => {
  const { root, target, config } = await setup(t, 'correct');
  const initialized = await cli(['init'], root);
  assert.equal(initialized.code, 0, initialized.stderr);
  assert.equal(JSON.parse(await fs.readFile(path.join(root, 'codebase-intel.json'), 'utf8')).model.provider, 'none');
  const audited = await cli(['audit', '--target', target, '--output', config.output], root);
  assert.equal(audited.code, 0, audited.stderr + audited.stdout);
  assert.ok(audited.stdout.length + audited.stderr.length > 0);
  const status = await cli(['status', '--output', config.output], root);
  assert.equal(status.code, 0, status.stderr);
});

test('CLI invalid commands and unsafe output roots fail without destructive writes', async t => {
  const { root, target } = await setup(t, 'correct');
  const invalid = await cli(['definitely-not-a-command'], root);
  assert.equal(invalid.code, 1);
  assert.match(invalid.stderr, /Unknown command/);
  const unsafe = await cli(['audit', '--target', target, '--output', target], root);
  assert.equal(unsafe.code, 1);
  assert.ok((await fs.readFile(path.join(target, 'sum.ts'), 'utf8')).includes('export function sum'));
});

test('CLI JSON audit, query, validate, report and history diff work together', async t => {
  const { root, target, config } = await setup(t, 'correct');
  const args = ['--target', target, '--output', config.output, '--json'];
  const audited = await cli(['audit', ...args], root);
  assert.equal(audited.code, 0, audited.stderr + audited.stdout);
  const first = JSON.parse(audited.stdout);
  const queried = await cli(['query', '--run', first.id, '--symbol', 'sum', ...args], root);
  assert.equal(queried.code, 0, queried.stderr);
  assert.ok(JSON.parse(queried.stdout).items.some(item => item.source.includes('export function sum')));
  const validated = await cli(['validate', '--run', first.id, ...args], root);
  assert.equal(validated.code, 0, validated.stderr);
  assert.equal(JSON.parse(validated.stdout).valid, true);
  const reported = await cli(['report', '--run', first.id, ...args], root);
  assert.equal(reported.code, 0, reported.stderr);
  assert.ok(JSON.parse(reported.stdout).report.endsWith('README.md'));
  await fs.appendFile(path.join(target, 'sum.ts'), '\n// source revision\n');
  const secondRun = await cli(['audit', ...args], root);
  assert.equal(secondRun.code, 0, secondRun.stderr);
  const second = JSON.parse(secondRun.stdout);
  const compared = await cli(['diff', '--from', first.id, '--to', second.id, ...args], root);
  assert.equal(compared.code, 0, compared.stderr);
  assert.ok(JSON.parse(compared.stdout).changedFiles.includes('sum.ts'));
  const listed = await cli(['status', ...args], root);
  assert.equal(listed.code, 0, listed.stderr);
  assert.equal(JSON.parse(listed.stdout).length, 2);
});

test('CLI scan checkpoints resume and polyglot audits surface partial coverage', async t => {
  const { root, target, config } = await setup(t);
  const args = ['--target', target, '--output', config.output, '--json'];
  const scanned = await cli(['scan', ...args], root);
  assert.equal(scanned.code, 2, scanned.stderr);
  const scan = JSON.parse(scanned.stdout);
  assert.ok(scan.files > 0 && scan.index.endsWith('index.json'));
  const resumed = await cli(['resume', '--run', scan.id, ...args], root);
  assert.equal(resumed.code, 2, resumed.stderr + resumed.stdout);
  const summary = JSON.parse(resumed.stdout);
  assert.equal(summary.status, 'partial');
  assert.ok(summary.unsupported > 0);
  assert.equal(summary.validation, true);
});

test('implementation handoff requires approval and never edits repository source', async t => {
  const { target, config } = await setup(t, 'polyglot');
  const { audit, runRoot } = await import('../dist/orchestrator.js');
  const { prepareImplementation } = await import('../dist/implementation.js');
  const run = await audit(config);
  const task = run.roadmap.tasks.find(task => task.phase === 1);
  assert.ok(task);
  const before = await sourceHashes(target);
  await assert.rejects(prepareImplementation(run, task.id, false), /explicit --approve/);
  const handoff = await prepareImplementation(run, task.id, true);
  assert.equal(handoff.ready, false, 'A selected remediation must wait for baseline prerequisites');
  assert.ok(handoff.blockers.some(b => /Prerequisite/.test(b)));
  const record = JSON.parse(await fs.readFile(path.join(runRoot(run), `implementation/${task.id}.json`), 'utf8'));
  assert.equal(record.lifecycle, 'PREPARATION_ONLY');
  assert.equal(record.engineImplemented, false);
  assert.deepEqual(await sourceHashes(target), before);
});
