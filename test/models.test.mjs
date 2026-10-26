import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ConfigSchema } from '../dist/schema.js';
import { hash } from '../dist/safety.js';
import { parseSuggestions, requestReview, reviewWithModels } from '../dist/models.js';

async function server(t,handler){
  const instance=http.createServer(handler);instance.listen(0,'127.0.0.1');
  await new Promise(resolve=>instance.once('listening',resolve));
  t.after(()=>new Promise(resolve=>instance.close(resolve)));
  return `http://127.0.0.1:${instance.address().port}`;
}
async function body(req){let s='';for await(const part of req)s+=part;return JSON.parse(s);}
function config(origin,provider='openai-compatible'){
  return ConfigSchema.parse({network:{enabled:true,allowedOrigins:[origin]},privacy:{sendSource:true},
    model:{provider,name:'test-model',baseUrl:origin,apiKeyEnv:'CODEBASE_INTEL_TEST_KEY',maxRetries:0}});
}

test('model requests require separate network and source-disclosure authorization',async()=>{
  const c=config('http://127.0.0.1:1');c.network.enabled=false;
  await assert.rejects(requestReview(c,'system','source'),/network.enabled/);
  c.network.enabled=true;c.privacy.sendSource=false;
  await assert.rejects(requestReview(c,'system','source'),/privacy.sendSource/);
  c.privacy.sendSource=true;c.network.allowedOrigins=[];
  await assert.rejects(requestReview(c,'system','source'),/allowlisted/);
  c.network.allowedOrigins=['http://127.0.0.1:1'];c.model.baseUrl='http://127.0.0.1:1/?token=bad';
  await assert.rejects(requestReview(c,'system','source'),/query/);
  c.model.baseUrl='http://example.invalid';c.network.allowedOrigins=['http://example.invalid'];
  await assert.rejects(requestReview(c,'system','source'),/HTTPS/);
});

test('four provider adapters send documented shapes and parse response envelopes',async t=>{
  const previous=process.env.CODEBASE_INTEL_TEST_KEY;process.env.CODEBASE_INTEL_TEST_KEY='private-test-key';
  t.after(()=>{if(previous===undefined)delete process.env.CODEBASE_INTEL_TEST_KEY;else process.env.CODEBASE_INTEL_TEST_KEY=previous;});
  let expected='';let calls=0;
  const origin=await server(t,async(req,res)=>{
    const payload=await body(req);calls++;assert.equal(payload.stream??false,false);
    res.setHeader('content-type','application/json');
    if(expected==='openai-compatible'){
      assert.equal(req.url,'/v1/chat/completions');assert.equal(req.headers.authorization,'Bearer private-test-key');
      assert.equal(payload.model,'test-model');assert.equal(payload.messages[0].role,'system');
      res.end(JSON.stringify({choices:[{message:{content:'{"summary":"openai","findings":[]}'}}]}));
    }else if(expected==='anthropic'){
      assert.equal(req.url,'/v1/messages');assert.equal(req.headers['x-api-key'],'private-test-key');
      assert.equal(payload.system,'system');assert.ok(payload.max_tokens>0);
      res.end(JSON.stringify({content:[{type:'text',text:'{"summary":"anthropic","findings":[]}'}]}));
    }else if(expected==='gemini'){
      assert.equal(req.url,'/v1/models/test-model:generateContent');assert.equal(req.headers['x-goog-api-key'],'private-test-key');
      assert.equal(payload.systemInstruction.parts[0].text,'system');assert.equal(payload.contents[0].parts[0].text,'source');
      res.end(JSON.stringify({candidates:[{content:{parts:[{text:'{"summary":"gemini","findings":[]}'}]}}]}));
    }else{
      assert.equal(req.url,'/api/chat');assert.equal(payload.format,'json');assert.equal(payload.messages[1].content,'source');
      res.end(JSON.stringify({message:{content:'{"summary":"ollama","findings":[]}'}}));
    }
  });
  for(const provider of ['openai-compatible','anthropic','gemini','ollama']){
    expected=provider;const c=config(origin,provider);if(provider!=='ollama')c.model.baseUrl+='/v1';
    const result=parseSuggestions(await requestReview(c,'system','source'));assert.equal(result.findings.length,0);
  }
  assert.equal(calls,4);
});

test('provider failures withhold response content, reject redirects, and bound retries',async t=>{
  let calls=0;let mode='retry';
  const origin=await server(t,async(req,res)=>{
    await body(req);calls++;
    if(mode==='redirect'){res.writeHead(302,{location:'http://example.invalid/steal'});res.end('secret-in-error');return;}
    if(calls===1){res.writeHead(429);res.end('secret-in-error');return;}
    res.setHeader('content-type','application/json');res.end(JSON.stringify({choices:[{message:{content:'{}'}}]}));
  });
  const c=config(origin);c.model.maxRetries=1;
  assert.equal(await requestReview(c,'system','source'),'{}');assert.equal(calls,2);
  mode='redirect';await assert.rejects(requestReview(c,'system','source'),e=>e.message.includes('302')&&!e.message.includes('secret-in-error'));
  assert.equal(calls,3);
});

test('model parser permits fenced JSON and rejects malformed suggestion records',()=>{
  assert.equal(parseSuggestions('```json\n{"summary":"safe","findings":[]}\n```').summary,'safe');
  assert.throws(()=>parseSuggestions('{"summary":"x","findings":[{"title":"invented"}]}'),/schema/);
  assert.throws(()=>parseSuggestions('not JSON'),/schema/);
});

test('model findings require matching indexed evidence and remain hypotheses',async t=>{
  const target=await fs.mkdtemp(path.join(os.tmpdir(),'intel-model-'));t.after(()=>fs.rm(target,{recursive:true,force:true}));
  const source='export function run(input) {\n  return eval(input);\n}\n';await fs.writeFile(path.join(target,'app.js'),source);
  const suggestion={title:'Dynamic code requires input trust review',category:'security',severity:'high',path:'app.js',symbol:'run',
    lineStart:2,lineEnd:2,evidence:'  return eval(input);',description:'Input is passed into eval.',rootCause:'Input trust is unknown.',
    currentBehavior:'The function calls eval.',expectedBehavior:'Use a constrained data parser if arbitrary code is not intended.',
    impact:'Untrusted input could execute code.',recommendation:'Trace input provenance and remove eval when unnecessary.',
    tests:['Ensure malicious input is rejected after remediation.'],completionCriteria:['Input provenance is verified.']};
  let transmitted='';
  const origin=await server(t,async(req,res)=>{
    const payload=await body(req);transmitted=payload.messages[1].content;
    res.end(JSON.stringify({choices:[{message:{content:JSON.stringify({summary:'Static review only.',findings:[suggestion,
      {...suggestion,title:'Wrong evidence',evidence:'imaginary'}, {...suggestion,title:'Wrong path',path:'../../private'}]})}}]}));
  });
  const c=config(origin);c.target=target;
  const file={path:'app.js',hash:hash(source),module:'.',kind:'source',findings:[]};
  const run={config:c,target,index:{files:[file],modules:[{path:'.'}],coverage:{limitations:[],unresolvedEvidence:[]}},
    findings:[],modelCalls:0,modelReviews:[],errors:[],tools:[]};
  let checkpoints=0;await reviewWithModels(run,async()=>{checkpoints++;});
  assert.equal(run.modelCalls,1);assert.equal(run.findings.length,1);assert.equal(run.findings[0].status,'HYPOTHESIS');
  assert.equal(run.findings[0].origin,'model');assert.equal(run.findings[0].evidence[0].snippet,suggestion.evidence);
  assert.equal(run.index.coverage.unresolvedEvidence.length,1);assert.ok(transmitted.includes('2:   return eval(input);'));
  assert.equal(checkpoints,2);assert.equal(run.tools[0].status,'ok');
  await reviewWithModels(run,async()=>{});assert.equal(run.modelCalls,1,'completed module reviews are resumable');
});

test('offline model review makes no requests and model failures remain visible',async()=>{
  const run={config:ConfigSchema.parse({}),modelCalls:0,modelReviews:[],findings:[],errors:[],tools:[]};
  await reviewWithModels(run,async()=>{});assert.equal(run.modelCalls,0);
});

test('model review captures malformed provider output as partial failure without discarding findings',async t=>{
  const target=await fs.mkdtemp(path.join(os.tmpdir(),'intel-model-fail-'));t.after(()=>fs.rm(target,{recursive:true,force:true}));
  const source='export const safe = 1;\n';await fs.writeFile(path.join(target,'safe.js'),source);
  const origin=await server(t,async(req,res)=>{await body(req);res.end(JSON.stringify({choices:[{message:{content:'I refuse the JSON schema'}}]}));});
  const c=config(origin);c.target=target;
  const run={config:c,target,index:{files:[{path:'safe.js',hash:hash(source),module:'.',kind:'source',findings:[]}],
    modules:[{path:'.'}],coverage:{limitations:[],unresolvedEvidence:[]}},findings:[{id:'existing'}],modelCalls:0,modelReviews:[],errors:[],tools:[]};
  await reviewWithModels(run,async()=>{});
  assert.equal(run.findings.length,1);assert.equal(run.errors.length,1);assert.equal(run.tools[0].status,'failed');
  assert.equal(run.modelReviews.length,0);assert.equal(run.modelCalls,1);
});

test('provider response size is bounded before consuming an oversized body',async t=>{
  const origin=await server(t,async(req,res)=>{await body(req);res.writeHead(200,{'content-length':'2000001'});res.end('too large');});
  await assert.rejects(requestReview(config(origin),'system','source'),/size limit/);
});

test('model context respects audit scope, changed-only exclusions, and excluded input',async t=>{
  const target=await fs.mkdtemp(path.join(os.tmpdir(),'intel-model-scope-'));t.after(()=>fs.rm(target,{recursive:true,force:true}));
  await fs.mkdir(path.join(target,'frontend'));await fs.mkdir(path.join(target,'backend'));
  const entries=[['frontend/main.js','export const visible = 1;\n'],['frontend/unchanged.js','export const omitted = 1;\n'],
    ['frontend/excluded.js','export const privateFile = 1;\n'],['backend/api.js','export const outside = 1;\n']];
  for(const [name,source]of entries)await fs.writeFile(path.join(target,name),source);
  let sent;
  const origin=await server(t,async(req,res)=>{const payload=await body(req);sent=JSON.parse(payload.messages[1].content);
    res.end(JSON.stringify({choices:[{message:{content:'{"summary":"Scoped review","findings":[]}'}}]}));});
  const c=config(origin);c.target=target;
  const run={config:c,target,scope:'frontend',index:{files:entries.map(([p,s])=>({path:p,hash:hash(s),module:'.',kind:'source',findings:[]})),
    modules:[{path:'.'}],coverage:{limitations:[],unresolvedEvidence:[],scopedOut:['frontend/unchanged.js'],excluded:[{path:'frontend/excluded.js',reason:'user exclusion'}]}},
    findings:[],modelCalls:0,modelReviews:[],errors:[],tools:[]};
  await reviewWithModels(run,async()=>{});assert.deepEqual(sent.files.map(f=>f.path),['frontend/main.js']);assert.equal(run.modelCalls,1);
});
