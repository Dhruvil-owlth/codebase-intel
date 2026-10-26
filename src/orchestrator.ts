import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { ConfigSchema, ENGINE_VERSION, VERSION, stages, type Config, type Run, type Stage } from './schema.js';
import { atomicWrite, errorText, hash, inside, md, noSymlinkAncestors, safeRead, writeJson, redact } from './safety.js';
import { buildIndex } from './indexer.js';
import { analyze } from './analysis.js';
import { reviewWithModels } from './models.js';
import { reconcileSpecialistDocuments, synthesize } from './planner.js';
import { generateReports } from './reports.js';
import { validateRun } from './verify.js';

export type AuditOptions={scope?:string;changedOnly?:boolean;stopAfter?:Stage;progress?:(message:string)=>void};
export const runRoot=(run:Run):string=>path.join(run.output,'runs',run.id);
export function validRunId(id:string):boolean{return /^\d{8}T\d{6}Z-[a-f0-9]{8}$/.test(id);}
export async function loadRun(output:string,id:string):Promise<Run>{
  if(!validRunId(id))throw new Error('Invalid run ID');const root=path.resolve(output);await noSymlinkAncestors(root);
  const run:Run=JSON.parse(await safeRead(root,`runs/${id}/run.json`,200000000));
  if(run.id!==id||path.resolve(run.output)!==root||run.schemaVersion!==1)throw new Error('Invalid run state identity');
  run.config=ConfigSchema.parse(run.config);
  if(run.target!==run.config.target||run.output!==run.config.output)throw new Error('Run state and configuration roots disagree');
  if(run.output===run.target||inside(run.output,run.target))throw new Error('Run output overlaps source root');
  if(!Array.isArray(run.findings)||!run.tasks||!Array.isArray(run.documents))throw new Error('Incomplete run state');
  await noSymlinkAncestors(run.target);return run;
}
export async function listRuns(output:string):Promise<Run[]> {
  let entries:string[];try{entries=await fs.readdir(path.join(output,'runs'));}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return [];throw e;}
  const result:Run[]=[];
  for(const id of entries.filter(validRunId).sort().reverse())result.push(await loadRun(output,id));
  return result;
}
async function outputRoot(config:Config):Promise<void>{
  await noSymlinkAncestors(config.output);
  try{const entries=await fs.readdir(config.output);if(entries.length&&!entries.includes('.codebase-intel-output'))throw new Error('Refusing to use a nonempty unowned output directory');}
  catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  await fs.mkdir(config.output,{recursive:true});
  try{await fs.writeFile(path.join(config.output,'.codebase-intel-output'),'Codebase Intel generated audit root, schema 1\n',{flag:'wx',mode:0o600});}
  catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;}
}
async function withOutputLock<T>(output:string,fn:()=>Promise<T>):Promise<T>{
  const lock=path.join(output,'.lock');await noSymlinkAncestors(lock);
  for(let attempt=0;;attempt++){
    try{await fs.writeFile(lock,JSON.stringify({pid:process.pid,host:os.hostname(),createdAt:new Date().toISOString()}),{flag:'wx',mode:0o600});break;}
    catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST'||attempt)throw e;
      const data=JSON.parse(await safeRead(output,'.lock',1000));
      if(data.host!==os.hostname())throw new Error('Output is locked on another host; review the lock before removing it');
      try{process.kill(data.pid,0);throw new Error('Another audit is using this output root');}
      catch(alive){if((alive as NodeJS.ErrnoException).code!=='ESRCH')throw alive;}
      await fs.unlink(lock);
    }
  }
  try{return await fn();}finally{await fs.unlink(lock).catch(()=>{});}
}
export async function persistRun(run:Run):Promise<void>{
  run.updatedAt=new Date().toISOString();await writeJson(run.output,`runs/${run.id}/run.json`,run);
}
function analysisConfigHash(config:Config):string {
  return hash(JSON.stringify({engine:ENGINE_VERSION,target:config.target,include:config.include,exclude:config.exclude,depth:config.depth,specialists:config.specialists,tools:config.tools,budgets:config.budgets}));
}
async function specialistViews(run:Run):Promise<void>{
  for(const category of run.config.specialists){const selected=run.findings.filter(f=>f.category===category);
    await atomicWrite(runRoot(run),`intermediate/${category}.md`,`# ${category} specialist review\n\nCanonical records: ../13-machine-readable/findings.json\n\n`+
      (selected.length?selected.map(f=>`## ${f.id}\n\n${md(f.title)}\n\n${md(f.description)}\n\nStatus: ${f.status}. Source: ${md(f.path)}:${f.lineStart}–${f.lineEnd}.\n\nRecommendation: ${md(f.recommendation)}\n`).join('\n'):
        'No actionable finding from enabled implemented checks. This is not proof of absence.\n'));
  }
}
function partial(run:Run):boolean {
  const c=run.index?.coverage;
  return !!(run.errors.length||c?.failed.length||c?.unsupported.length||c?.unresolvedEvidence.length||c?.scopedOut.length||!run.validation?.valid);
}
async function execute(run:Run,options:AuditOptions,previous?:Run):Promise<Run>{
  const start=Date.now();const deadline=start+run.config.budgets.maxRunSeconds*1000;
  const progress=options.progress??(()=>{});
  await fs.mkdir(runRoot(run),{recursive:true});
  const log=async(stage:string,message:string)=>{
    progress(message);const file=path.join(runRoot(run),'events.jsonl');await noSymlinkAncestors(file);
    const handle=await fs.open(file,constants.O_WRONLY|constants.O_CREAT|constants.O_APPEND|(constants.O_NOFOLLOW??0),0o600);
    try{await handle.writeFile(JSON.stringify({at:new Date().toISOString(),stage,message:redact(message)})+'\n');}finally{await handle.close();}
  };
  for(const stage of stages){
    if(run.tasks[stage].status==='complete')continue;
    run.stage=stage;run.tasks[stage].status='running';run.tasks[stage].attempts++;
    run.errors=run.errors.filter(e=>e.stage!==stage);await persistRun(run);await log(stage,`[${stage}] started`);
    try{
      if(Date.now()>deadline)throw new Error('Run time budget exhausted before stage; resume to continue');
      switch(stage){
        case 'discovery':
          run.index=await buildIndex(run.config,previous?.configHash===run.configHash?previous.index:run.index,{scope:run.scope,changedOnly:run.changedOnly,deadline});
          await log(stage,`Indexed ${run.index.files.length} files; ${run.index.coverage.reused} reused; ${run.index.coverage.failed.length} failures.`);break;
        case 'specialists':run.findings=await analyze(run.index!,run.config);await specialistViews(run);break;
        case 'model-review':await reviewWithModels(run,()=>persistRun(run));await specialistViews(run);break;
        case 'synthesis':{
          await reconcileSpecialistDocuments(run);const result=synthesize(run.findings,run.config);run.findings=result.findings;run.roadmap=result.roadmap;break;}
        case 'documentation':run.documents=await generateReports(run);break;
        case 'verification':run.validation=await validateRun(run);if(!run.validation.valid)throw new Error(`Report validation failed: ${run.validation.errors.join('; ')}`);break;
      }
      const optionalErrors=run.errors.filter(e=>e.stage===stage);
      run.tasks[stage].status=optionalErrors.length?'failed':'complete';delete run.tasks[stage].error;
      if(optionalErrors.length)run.tasks[stage].error=optionalErrors.map(e=>e.message).join('; ');
      await log(stage,`[${stage}] ${run.tasks[stage].status}`);
    }catch(e){const message=errorText(e);run.errors.push({stage,message});run.tasks[stage].status='failed';run.tasks[stage].error=message;await log(stage,`[${stage}] failed: ${message}`);
      if(stage==='discovery'||stage==='specialists'||stage==='synthesis'||stage==='documentation'){
        run.status='failed';await persistRun(run);return run;
      }
    }
    await persistRun(run);
    if(options.stopAfter===stage){run.status='partial';await persistRun(run);return run;}
  }
  run.status=partial(run)?'partial':'complete';
  // Final rendering includes the actual terminal state and validation results.
  if(run.roadmap){run.documents=await generateReports(run);run.validation=await validateRun(run);if(!run.validation.valid)run.status='partial';}
  await persistRun(run);await writeJson(run.output,'latest.json',{id:run.id,status:run.status,report:`runs/${run.id}/README.md`});
  return run;
}
export async function audit(config:Config,options:AuditOptions={}):Promise<Run>{
  config=ConfigSchema.parse(config);config.target=await fs.realpath(path.resolve(config.target));config.output=path.resolve(config.output);
  if(config.output===config.target||inside(config.output,config.target))throw new Error('Output must not equal or contain target');
  await outputRoot(config);
  return withOutputLock(config.output,async()=>{
    const id=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z/,'Z')+'-'+randomUUID().slice(0,8);
    const previous=(await listRuns(config.output)).find(r=>r.target===config.target&&r.index);
    const run:Run={schemaVersion:1,id,version:VERSION,engineVersion:ENGINE_VERSION,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),
      target:config.target,output:config.output,config,scope:options.scope,changedOnly:options.changedOnly??false,previous:previous?.id,status:'running',stage:'discovery',
      tasks:Object.fromEntries(stages.map(s=>[s,{status:'pending',attempts:0}])) as Run['tasks'],errors:[],findings:[],documents:[],
      modelCalls:0,modelReviews:[],tools:[],configHash:analysisConfigHash(config)};
    return execute(run,options,previous);
  });
}
export async function resumeRun(output:string,id:string,options:AuditOptions={}):Promise<Run>{
  const run=await loadRun(output,id);
  return withOutputLock(run.output,async()=>{
    const current=await buildIndex(run.config,run.index,{scope:run.scope,changedOnly:run.changedOnly});
    const parserFingerprint=(r:Run['index'])=>hash(JSON.stringify(r?.files.map(f=>[f.path,f.parser,f.parseErrors,f.symbols,f.imports])));
    const sourceChanged=!!run.index&&current.fingerprint!==run.index.fingerprint;
    const parsingChanged=!!run.index&&parserFingerprint(current)!==parserFingerprint(run.index);
    if(run.index&&(sourceChanged||parsingChanged)){
      await writeJson(run.output,`runs/${id}/history/${Date.now()}-before-source-change.json`,run);
      run.index=current;run.findings=[];run.modelReviews=[];run.modelCalls=0;run.errors=[];delete run.roadmap;delete run.validation;
      for(const stage of stages)run.tasks[stage]={status:stage==='discovery'?'complete':'pending',attempts:run.tasks[stage].attempts};
      options.progress?.('Source or parser results changed since checkpoint; preserved old state and invalidated dependent analysis.');
    }else if(!run.index){run.index=current;run.tasks.discovery.status='complete';}
    // A failed earlier stage can change all downstream records when retried.
    const first=stages.findIndex(s=>run.tasks[s].status!=='complete');
    if(first>=0)for(const stage of stages.slice(first))if(run.tasks[stage].status==='complete')run.tasks[stage].status='pending';
    run.status='running';return execute(run,options);
  });
}
export function diffRuns(from:Run,to:Run):{added:string[];resolved:string[];persisting:string[];changedFiles:string[];coverage:{from:number;to:number}}{
  const before=new Set(from.findings.map(f=>f.id)),after=new Set(to.findings.map(f=>f.id));const files=new Map(from.index?.files.map(f=>[f.path,f.hash])??[]);
  return {added:[...after].filter(id=>!before.has(id)),resolved:[...before].filter(id=>!after.has(id)),persisting:[...after].filter(id=>before.has(id)),
    changedFiles:[...new Set([...(to.index?.files.filter(f=>files.get(f.path)!==f.hash).map(f=>f.path)??[]),...(from.index?.files.filter(f=>!to.index?.files.some(n=>n.path===f.path)).map(f=>f.path)??[])])],
    coverage:{from:from.index?.coverage.parsed.length??0,to:to.index?.coverage.parsed.length??0}};
}
