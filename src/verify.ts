import fs from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { FindingSchema, type Run } from './schema.js';
import { errorText, hash, inside, noSymlinkAncestors, redact, safeRead } from './safety.js';
import { topologicalGroups } from './planner.js';

export function headingIds(markdown:string):Set<string> {
  const ids=new Set<string>();const counts=new Map<string,number>();
  for(const match of markdown.matchAll(/^#{1,6}\s+(.+?)\s*#*$/gm)){
    const slug=match[1]!.replace(/\\([\W_])/g,'$1').replace(/<[^>]*>/g,'').toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu,'').replace(/\s/g,'-');
    const count=counts.get(slug)??0;counts.set(slug,count+1);ids.add(slug+(count?`-${count}`:''));
  }
  for(const match of markdown.matchAll(/\bid=["']([^"']+)["']/g))ids.add(match[1]!);
  return ids;
}
export async function validateMarkdown(markdown:string,document:string,allowedRoots:string[]):Promise<string[]> {
  const errors:string[]=[];
  // Generated reports do not use reference-style links. Ignore fenced source examples.
  const text=markdown.replace(/^(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\1[ \t]*$/gm,'');
  for(const match of text.matchAll(/\[(?:\\.|[^\]\\])*\]\(([^\s)]+)\)/g)){
    let target=match[1]!;if(target.startsWith('<')&&target.endsWith('>'))target=target.slice(1,-1);
    if(/^(?:https?:|mailto:)/i.test(target))continue;
    if(/^[a-z][a-z0-9+.-]*:/i.test(target)){errors.push(`${document}: unsupported link scheme`);continue;}
    const [encoded,fragment]=target.split('#');let decoded:string;
    try{decoded=decodeURIComponent(encoded??'');}catch{errors.push(`${document}: invalid URL encoding`);continue;}
    const absolute=decoded?path.resolve(path.dirname(document),decoded):document;
    if(!allowedRoots.some(root=>inside(root,absolute))){errors.push(`${document}: link escapes source and report roots`);continue;}
    try{
      await noSymlinkAncestors(absolute);const stat=await fs.stat(absolute);
      if(fragment&&stat.isFile()){
        if(/^L\d+(?:-L?\d+)?$/.test(fragment)){
          const line=Number(fragment.slice(1).split('-')[0]);const source=await fs.readFile(absolute,'utf8');
          if(line<1||line>source.split('\n').length)errors.push(`${document}: source link line is out of range`);
        }else if(absolute.endsWith('.md')){
          const linked=absolute===document?markdown:await fs.readFile(absolute,'utf8');
          if(!headingIds(linked).has(decodeURIComponent(fragment)))errors.push(`${document}: missing heading fragment ${fragment}`);
        }
      }
    }catch(e){errors.push(`${document}: broken or unsafe local link ${target}: ${errorText(e)}`);}
  }
  return errors;
}

export async function validateRun(run:Run):Promise<{valid:boolean;errors:string[];warnings:string[]}> {
  const errors:string[]=[],warnings:string[]=[];const ids=new Set<string>();const files=new Map(run.index?.files.map(f=>[f.path,f])??[]);
  const sources=new Map<string,string>();
  const read=async(p:string)=>{if(!sources.has(p))sources.set(p,await safeRead(run.target,p,run.config.budgets.maxFileBytes));return sources.get(p)!;};
  for(const f of run.findings){
    const parsed=FindingSchema.safeParse(f);if(!parsed.success){errors.push(`Invalid finding schema: ${f.id}`);continue;}
    if(ids.has(f.id))errors.push(`Duplicate finding ID ${f.id}`);ids.add(f.id);
    if(f.lineEnd<f.lineStart)errors.push(`${f.id}: inverted source line range`);
    if(!f.evidence.some(e=>e.path===f.path&&e.lineStart===f.lineStart&&e.lineEnd===f.lineEnd))errors.push(`${f.id}: primary source attribution is missing`);
    if(f.origin==='model'&&(f.status!=='HYPOTHESIS'||f.confidence>0.5))errors.push(`${f.id}: unsupported model confidence or verification claim`);
    if(f.status==='VERIFIED')errors.push(`${f.id}: no direct reproduction engine is implemented; VERIFIED is not admissible without recorded validation`);
    if(f.measurement==='measured')errors.push(`${f.id}: no captured profiler/benchmark evidence supports a measured claim`);
    for(const e of f.evidence){
      const indexed=files.get(e.path);
      if(!indexed){errors.push(`${f.id}: evidence file is not indexed`);continue;}
      if(e.hash!==indexed.hash)errors.push(`${f.id}: indexed evidence hash mismatch`);
      try{const source=await read(e.path);if(hash(source)!==e.hash){errors.push(`${f.id}: stale evidence: ${e.path}`);continue;}
        const lines=source.split(/\r?\n/);if(e.lineStart<1||e.lineEnd<e.lineStart||e.lineEnd>lines.length)errors.push(`${f.id}: evidence range is out of bounds`);
        else {const actual=redact(lines.slice(e.lineStart-1,e.lineEnd).join('\n'));
          if(!e.snippet||!actual.startsWith(e.snippet))errors.push(`${f.id}: evidence snippet does not match source`);}
      }catch(e){errors.push(`${f.id}: evidence cannot be read: ${errorText(e)}`);}
    }
    if(f.status==='HYPOTHESIS'&&f.confidence>0.9)warnings.push(`${f.id}: high confidence still needs direct validation`);
  }
  for(const f of run.findings)for(const id of [...f.related,...f.dependencies])if(!ids.has(id))errors.push(`${f.id}: unknown finding reference ${id}`);
  if(run.roadmap){
    try{topologicalGroups(run.roadmap.tasks);}catch(e){errors.push(errorText(e));}
    const taskIds=new Set<string>();
    for(const task of run.roadmap.tasks){
      taskIds.add(task.id);if(!task.steps.length||!task.tests.length||!task.done.length||!task.rollback)errors.push(`${task.id}: incomplete task contract`);
      if(!Number.isInteger(task.phase)||task.phase<0||task.phase>7)errors.push(`${task.id}: invalid phase`);
      for(const id of task.findings)if(!ids.has(id))errors.push(`${task.id}: unknown finding ${id}`);
    }
    for(const f of run.findings)if(!run.roadmap.tasks.some(t=>t.findings.includes(f.id)&&t.id!=='T-HARDEN'))errors.push(`${f.id}: no implementation task`);
    for(const cause of run.roadmap.rootCauses)for(const id of cause.findings)if(!ids.has(id))errors.push(`${cause.id}: unknown root-cause finding`);
  }else errors.push('Missing roadmap');
  const runRoot=path.join(run.output,'runs',run.id);const documentSet=new Set(run.documents);
  if(documentSet.size!==run.documents.length)errors.push('Duplicate document paths');
  for(const document of run.documents){
    try{const markdown=await safeRead(runRoot,document,32000000);
      if(document.endsWith('.json')){
        let data:unknown;try{data=JSON.parse(markdown);}catch{errors.push(`${document}: invalid JSON`);continue;}
        const canonical:Record<string,unknown>={'13-machine-readable/findings.json':run.findings,
          '13-machine-readable/roadmap.json':run.roadmap,'13-machine-readable/coverage.json':run.index?.coverage,'13-machine-readable/index.json':run.index};
        if(document in canonical&&!isDeepStrictEqual(data,JSON.parse(JSON.stringify(canonical[document]))))errors.push(`${document}: saved structured record differs from canonical run state`);
        if(document==='13-machine-readable/findings.json'){
          if(!Array.isArray(data)||!data.every(f=>FindingSchema.safeParse(f).success))errors.push(`${document}: findings schema invalid`);
        }
        if(document==='13-machine-readable/run-manifest.json'){
          const m=data as Record<string,unknown>;
          if(m.id!==run.id||m.schemaVersion!==1||m.mode!=='ANALYZE_ONLY'||m.fingerprint!==run.index?.fingerprint)errors.push(`${document}: manifest identity or fingerprint mismatch`);
        }
        continue;
      }
      errors.push(...await validateMarkdown(markdown,path.join(runRoot,document),[runRoot,run.target]));
      const withoutFences=markdown.replace(/^(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\1[ \t]*$/gm,'');
      if(/^(`{3,}|~{3,})/m.test(withoutFences))errors.push(`${document}: unclosed code fence`);
      if(/(?:```|~~~)mermaid/.test(markdown)&&!/(?:```|~~~)mermaid\s*\n(?:flowchart|graph|sequenceDiagram|classDiagram)/.test(markdown))errors.push(`${document}: unexpected Mermaid diagram type`);
    }catch(e){errors.push(`Cannot validate report ${document}: ${errorText(e)}`);}
  }
  warnings.push('Mermaid receives basic structural checks; no Mermaid renderer is installed.',
    'Static evidence validates source observations, not business impact, runtime reachability or benchmark gains.');
  if(run.index?.coverage.failed.length)warnings.push(`${run.index.coverage.failed.length} file or inventory failures limit coverage.`);
  if(run.index?.coverage.unsupported.length)warnings.push(`${run.index.coverage.unsupported.length} source files have inventory-only support.`);
  if(run.index?.coverage.unresolvedEvidence.length)warnings.push(...run.index.coverage.unresolvedEvidence);
  return {valid:errors.length===0,errors:[...new Set(errors)],warnings:[...new Set(warnings)]};
}
