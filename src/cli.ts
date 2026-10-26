#!/usr/bin/env node
import path from 'node:path';
import { parseArgs } from 'node:util';
import { audit, diffRuns, listRuns, loadRun, persistRun, resumeRun, runRoot } from './orchestrator.js';
import { initConfig, loadConfig } from './config.js';
import { defaultRegistry } from './adapters.js';
import { modelProviders } from './models.js';
import { toolRegistry } from './tools.js';
import { validateRun } from './verify.js';
import { generateReports } from './reports.js';
import { retrieve } from './retrieval.js';
import { prepareImplementation } from './implementation.js';
import { errorText, safeRead, writeJson } from './safety.js';
import { stages, type Run, type Stage } from './schema.js';

const HELP=`Codebase Intel — evidence-backed repository audits (ANALYZE_ONLY)

Usage: codebase-intel <command> [options]

  init                          Create codebase-intel.json without overwriting
  audit --target /repo          Run the complete audit and roadmap pipeline
  scan --target /repo           Inventory/index checkpoint only
  resume --run ID               Continue a checkpoint; invalidate changed source
  report --run ID               Re-render reports from canonical records
  validate --run ID             Verify schemas, source evidence, links and DAG
  diff --from ID --to ID        Compare findings, coverage and input hashes
  status                        Show recent runs (history is preserved)
  query --run ID --symbol NAME  Retrieve bounded, redacted source evidence
  capabilities                  Show implemented adapters and tool policies
  implementation-plan --run ID --task ID --approve
                                Prepare a scoped handoff; never edit source

Common options:
  --config FILE  --target PATH  --output PATH  --scope PATH_OR_GLOB
  --changed-only  --depth inventory|standard|deep  --json
  --stop-after discovery|specialists|model-review|synthesis|documentation|verification
Query options: --symbol NAME --path GLOB --keyword TEXT --related --tokens NUMBER

Default output: docs/codebase-intelligence/runs/<id>/
Exit codes: 0 complete/valid, 2 partial/stopped/invalid, 1 fatal error.
Models are optional. Configure API family, model name, explicit origin and source-sharing permission.
`;
async function main():Promise<void>{
  const {values:v,positionals}=parseArgs({allowPositionals:true,strict:true,options:{
    help:{type:'boolean',short:'h'},version:{type:'boolean'},config:{type:'string'},target:{type:'string'},output:{type:'string'},
    run:{type:'string'},from:{type:'string'},to:{type:'string'},scope:{type:'string'},depth:{type:'string'},json:{type:'boolean'},
    'changed-only':{type:'boolean'},'stop-after':{type:'string'},symbol:{type:'string'},path:{type:'string'},keyword:{type:'string'},related:{type:'boolean'},
    tokens:{type:'string'},task:{type:'string'},approve:{type:'boolean'},
  }});
  if(v.version){process.stdout.write('0.1.0\n');return;}
  if(v.help||!positionals.length){process.stdout.write(HELP);return;}
  if(positionals.length!==1)throw new Error('Provide exactly one command; paths belong in --target or --output');
  const command=positionals[0]!;const print=(value:unknown)=>process.stdout.write((typeof value==='string'?value:JSON.stringify(value,null,2))+'\n');
  const progress=v.json?()=>{}:(message:string)=>process.stderr.write(message+'\n');
  if(command==='init'){const file=await initConfig(process.cwd());print(v.json?{config:file}:`Created ${file}`);return;}
  if(command==='capabilities'){print({mode:'ANALYZE_ONLY',providers:modelProviders,adapters:defaultRegistry().list().map(({parse,compatible,...metadata})=>metadata),tools:toolRegistry,
    implementationEngine:'Preparation-only handoff; editing, arbitrary analyzer execution, deployment and merging are not implemented.'});return;}
  const config=await loadConfig(v.config,{target:v.target,output:v.output,depth:v.depth});
  const selectedRun=async(id=v.run):Promise<Run>=>{if(!id)throw new Error('--run is required');return loadRun(config.output,id);};
  const showRun=(run:Run)=>{
    const summary={id:run.id,status:run.status,findings:run.findings.length,indexed:run.index?.files.length??0,
      parsed:run.index?.coverage.parsed.length??0,unsupported:run.index?.coverage.unsupported.length??0,
      failures:run.index?.coverage.failed.length??0,validation:run.validation?.valid??false,
      report:run.documents.length?path.join(runRoot(run),'README.md'):null,
      roadmap:run.roadmap?path.join(runRoot(run),'12-implementation-roadmap/MASTER-IMPLEMENTATION-PLAN.md'):null,
      state:path.join(runRoot(run),'run.json'),errors:run.errors};
    print(v.json?summary:`Run: ${run.id}\nStatus: ${run.status}\nFindings: ${summary.findings}; indexed: ${summary.indexed}; parsed: ${summary.parsed}; unsupported: ${summary.unsupported}; failures: ${summary.failures}\nReport: ${summary.report??'not generated; resume this run'}\nState: ${summary.state}`);
    if(run.status!=='complete')process.exitCode=run.status==='failed'?1:2;
  };
  const stopAfter=v['stop-after'];if(stopAfter&&!stages.includes(stopAfter as Stage))throw new Error('Invalid --stop-after stage');
  switch(command){
    case 'audit':case 'scan':{
      const run=await audit(config,{scope:v.scope,changedOnly:v['changed-only'],stopAfter:command==='scan'?'discovery':stopAfter as Stage|undefined,progress});
      if(command==='scan'){await writeJson(runRoot(run),'13-machine-readable/index.json',run.index);if(v.json)print({id:run.id,status:run.index?.coverage.failed.length||run.index?.coverage.unsupported.length?'indexed-partial':'indexed',files:run.index?.files.length,
        unsupported:run.index?.coverage.unsupported.length??0,failures:run.index?.coverage.failed.length??0,index:path.join(runRoot(run),'13-machine-readable/index.json')});
        else print(`Indexed ${run.index?.files.length??0} files. Run ${run.id}; continue with resume --run ${run.id}.`);if(run.status==='failed')process.exitCode=1;
        else if(run.index?.coverage.failed.length||run.index?.coverage.unsupported.length)process.exitCode=2;}
      else showRun(run);break;}
    case 'resume':showRun(await resumeRun(config.output,(await selectedRun()).id,{stopAfter:stopAfter as Stage|undefined,progress}));break;
    case 'status':{
      const runs=(await listRuns(config.output)).slice(0,config.retention);print(v.json?runs.map(r=>({id:r.id,status:r.status,stage:r.stage,findings:r.findings.length,target:r.target})):
        runs.length?runs.map(r=>`${r.id}  ${r.status.padEnd(8)}  ${r.findings.length} findings  ${r.target}`).join('\n'):'No runs yet.');break;}
    case 'report':{const run=await selectedRun();if(!run.roadmap)throw new Error('Resume the run through synthesis before reporting');
      run.documents=await generateReports(run);await persistRun(run);print(v.json?{id:run.id,report:path.join(runRoot(run),'README.md')}:path.join(runRoot(run),'README.md'));break;}
    case 'validate':{const run=await selectedRun();const result=await validateRun(run);run.validation=result;await persistRun(run);print(result);if(!result.valid)process.exitCode=2;break;}
    case 'diff':{if(!v.from||!v.to)throw new Error('--from and --to are required');print(diffRuns(await selectedRun(v.from),await selectedRun(v.to)));break;}
    case 'query':{const run=await selectedRun();if(!run.index)throw new Error('Run has no index');const tokens=v.tokens?Number(v.tokens):undefined;
      if(tokens!==undefined&&(!Number.isFinite(tokens)||tokens<=0))throw new Error('--tokens must be a positive finite number');
      print(await retrieve(run.index,run.config,{symbol:v.symbol,path:v.path,keyword:v.keyword,related:v.related,tokens}));break;}
    case 'implementation-plan':{if(!v.task)throw new Error('--task is required');const run=await selectedRun();const result=await prepareImplementation(run,v.task,v.approve??false);
      print({...result,file:path.join(runRoot(run),result.file),engine:'PREPARATION_ONLY'});if(!result.ready)process.exitCode=2;break;}
    default:throw new Error(`Unknown command: ${command}. Use --help.`);
  }
}
main().catch(e=>{process.stderr.write(`codebase-intel: ${errorText(e)}\n`);process.exitCode=1;});
