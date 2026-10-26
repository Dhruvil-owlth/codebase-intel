import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ConfigSchema } from '../dist/schema.js';
import { audit, resumeRun, persistRun } from '../dist/orchestrator.js';
import { AdapterRegistry, javascriptAdapter } from '../dist/adapters.js';
import { buildIndex } from '../dist/indexer.js';
import { makeFinding } from '../dist/findings.js';
import { synthesize, topologicalGroups } from '../dist/planner.js';
import { hash } from '../dist/safety.js';

async function fixture(t,files){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'intel-independent-review-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const target=path.join(root,'repository');await fs.mkdir(target);
  for(const [name,content] of Object.entries(files)){
    await fs.mkdir(path.dirname(path.join(target,name)),{recursive:true});await fs.writeFile(path.join(target,name),content);
  }
  return {root,target,config:ConfigSchema.parse({target,output:path.join(root,'reports'),tools:{git:false,python:false}})};
}

test('resuming an audit never follows an event-log symlink into application source',async t=>{
  const source='export const value = 1;\n';const {target,config}=await fixture(t,{'app.js':source});
  const run=await audit(config,{stopAfter:'discovery'});
  const log=path.join(config.output,'runs',run.id,'events.jsonl');await fs.unlink(log);await fs.symlink(path.join(target,'app.js'),log);
  // Rejecting the unsafe log or safely replacing it are both acceptable; following it is not.
  try{await resumeRun(config.output,run.id,{stopAfter:'specialists'});}catch{}
  assert.equal(await fs.readFile(path.join(target,'app.js'),'utf8'),source,'ANALYZE_ONLY must leave application source byte-for-byte unchanged');
});

test('transient parser failures are retried even when source bytes are unchanged',async t=>{
  const {config}=await fixture(t,{'app.js':'export const value = 1;\n'});let calls=0;
  const adapter={...javascriptAdapter,id:'transient-test-parser',async parse(ctx){calls++;if(calls===1)throw new Error('Transient parser failure');await javascriptAdapter.parse(ctx);}};
  const registry=new AdapterRegistry().register(adapter);
  const first=await buildIndex(config,undefined,{registry});assert.equal(first.files[0].parser,'failed');
  const retried=await buildIndex(config,first,{registry});
  assert.equal(calls,2,'A failed cache entry must not suppress retry');assert.equal(retried.files[0].parseErrors.length,0);
  assert.match(retried.files[0].parser,/typescript/);
});

test('private URL credentials never survive in persisted audit metadata',async t=>{
  const privateUrl='https://alice:review-private-password@example.invalid/private.js';
  const {config}=await fixture(t,{'app.js':`import remote from '${privateUrl}';\nexport const value = remote;\n`,
    'package.json':JSON.stringify({name:'review-fixture',dependencies:{privateDependency:privateUrl}},null,2)});
  const run=await audit(config,{stopAfter:'discovery'});
  const state=await fs.readFile(path.join(config.output,'runs',run.id,'run.json'),'utf8');
  assert.ok(!state.includes('review-private-password'),'Credentials embedded in import/dependency URLs must be redacted before persistence');
});

test('valid cross-phase finding prerequisites produce an acyclic implementation roadmap',()=>{
  const config=ConfigSchema.parse({});const source='export const value = 1;\n';const file={path:'app.js',hash:hash(source),module:'.'};
  const security=makeFinding(file,source,{rule:'review-security',title:'Constrain the public boundary',category:'security',lineStart:1,
    description:'A boundary change requires the shared module first.',recommendation:'Use the new shared boundary.',tests:['Check rejected requests.']});
  const architecture=makeFinding(file,source,{rule:'review-architecture',title:'Extract the shared boundary',category:'architecture',lineStart:1,
    description:'A shared module enables the security correction.',recommendation:'Extract the shared module.',tests:['Check callers.']});
  security.dependencies=[architecture.id];
  const {roadmap}=synthesize([security,architecture],config);
  assert.doesNotThrow(()=>topologicalGroups(roadmap.tasks));
  const task=roadmap.tasks.find(t=>t.findings.includes(security.id)&&t.id!=='T-HARDEN');
  assert.ok(task.dependencies.includes(`T-${architecture.id.slice(2)}`));
});

test('resume preserves a failed model-review status when its request budget is exhausted',async t=>{
  const {config}=await fixture(t,{'app.js':'export const value = 1;\n'});
  config.network={enabled:true,allowedOrigins:['http://127.0.0.1:1']};config.privacy.sendSource=true;
  config.model={provider:'ollama',name:'test-only',baseUrl:'http://127.0.0.1:1',apiKeyEnv:'UNUSED_TEST_KEY',timeoutMs:100,maxRetries:0};
  config.budgets.maxModelCalls=1;
  const run=await audit(config,{stopAfter:'specialists'});
  run.modelCalls=1;run.tasks['model-review']={status:'failed',attempts:1,error:'Simulated transient provider failure'};
  run.errors.push({stage:'model-review',message:'Simulated transient provider failure'});await persistRun(run);
  // No server is needed: an exhausted budget must prevent every request.
  const resumed=await resumeRun(config.output,run.id);
  assert.equal(resumed.status,'partial','An unreviewed module must not become a complete audit merely by resuming');
  assert.equal(resumed.tasks['model-review'].status,'failed');
});

test('source read-budget failures are surfaced as partial coverage',async t=>{
  const {config}=await fixture(t,{'app.js':'export const value = 1;\n'});config.budgets.maxFileBytes=10;
  const run=await audit(config);
  assert.equal(run.status,'partial','A resource limit must not disguise omitted application source as a complete audit');
  assert.ok(run.index.coverage.failed.some(f=>f.path==='app.js'));
});
