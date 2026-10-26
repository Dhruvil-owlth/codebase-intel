import path from 'node:path';
import ts from 'typescript';
import { type Finding, type Index, type Config } from './schema.js';
import { hash, safeRead, redact } from './safety.js';
import { makeFinding } from './findings.js';

// Iterative Kosaraju avoids recursion depth failures on long import chains.
export function stronglyConnected(nodes:string[],edges:{from:string;to:string}[]):string[][] {
  const forward=new Map(nodes.map(n=>[n,[] as string[]]));const reverse=new Map(nodes.map(n=>[n,[] as string[]]));
  for(const e of edges){forward.get(e.from)?.push(e.to);reverse.get(e.to)?.push(e.from);}
  const seen=new Set<string>();const order:string[]=[];
  for(const start of nodes){if(seen.has(start))continue;const stack:[string,boolean][]=[[start,false]];
    while(stack.length){const [n,done]=stack.pop()!;if(done){order.push(n);continue;}if(seen.has(n))continue;seen.add(n);stack.push([n,true]);for(const to of forward.get(n)??[])if(!seen.has(to))stack.push([to,false]);}
  }
  seen.clear();const groups:string[][]=[];
  for(const start of order.reverse()){if(seen.has(start))continue;const group:string[]=[];const stack=[start];seen.add(start);
    while(stack.length){const n=stack.pop()!;group.push(n);for(const to of reverse.get(n)??[])if(!seen.has(to)){seen.add(to);stack.push(to);}}
    if(group.length>1)groups.push(group.sort());
  }
  return groups;
}
export async function analyze(index:Index,config:Config):Promise<Finding[]> {
  const scopedOut=new Set(index.coverage.scopedOut);const active=index.files.filter(f=>!scopedOut.has(f.path));
  const findings:Finding[]=active.flatMap(f=>f.findings.filter(x=>config.specialists.includes(x.category)));
  if(config.depth==='inventory')return [];
  const content=new Map<string,string>();
  const read=async(p:string):Promise<string>=>{if(!content.has(p))content.set(p,await safeRead(config.target,p,config.budgets.maxFileBytes));return content.get(p)!;};
  if(config.specialists.includes('architecture'))for(const group of stronglyConnected(index.files.map(f=>f.path),index.edges)){
    if(!group.some(p=>!scopedOut.has(p)))continue;
    const file=index.files.find(f=>f.path===group.find(p=>!scopedOut.has(p)))!;
    const source=await read(file.path);const edge=index.edges.find(e=>e.from===file.path&&group.includes(e.to))!;
    const finding=makeFinding(file,source,{rule:'import-cycle',title:'Local import graph contains a dependency cycle',category:'architecture',
      severity:'medium',confidence:0.99,lineStart:edge.line,kind:'graph',
      description:`Indexed imports form a strongly connected group: ${group.join(', ')}. A cycle is structurally present; runtime initialization harm is not established.`,
      recommendation:'Review the group’s ownership and initialization requirements. Extract a shared interface or invert a dependency only if the cycle causes coupling or initialization failures.',
      rootCause:'Bidirectional ownership between locally resolved modules.',tests:['Test module initialization in both import orders and cover the public boundary.']});
    for(const p of group.filter(p=>p!==file.path).slice(0,30)){
      const peer=index.files.find(f=>f.path===p)!;const link=index.edges.find(e=>e.from===p&&group.includes(e.to))!;
      const peerSource=await read(p);finding.evidence.push({path:p,lineStart:link.line,lineEnd:link.line,hash:peer.hash,snippet:redact(peerSource.split(/\r?\n/)[link.line-1]??''),kind:'graph'});
    }
    findings.push(finding);
  }
  if(config.specialists.includes('dependencies'))for(const f of active.filter(f=>path.posix.basename(f.path)==='package.json')){
    const source=await read(f.path);let pkg:Record<string,any>;try{pkg=JSON.parse(source);}catch{continue;}
    for(const [name,version] of Object.entries({...pkg.dependencies,...pkg.devDependencies})){
      if(typeof version!=='string'||!['*','latest'].includes(version))continue;
      const lines=source.split(/\r?\n/);const line=Math.max(1,lines.findIndex(l=>l.includes(JSON.stringify(name)))+1);
      findings.push(makeFinding(f,source,{rule:'unbounded-dependency',title:`Unbounded dependency declaration: ${name}`,category:'dependencies',lineStart:line,kind:'manifest',
        description:`The manifest declares ${name} with ${version}. New resolutions can select incompatible major versions; lockfiles may constrain a particular installation. This is not a vulnerability claim.`,
        recommendation:'Select a supported, tested version range and commit the appropriate lockfile. Verify clean installs in CI without silently updating the lock.',
        rootCause:'Dependency update policy permits unconstrained resolution.',tests:['Resolve from a clean checkout using the lockfile and run compatibility tests for the chosen dependency.']}));
    }
  }
  if(config.specialists.includes('testing')){
    const untested=new Set(index.coverage.untestedPaths);
    for(const f of active.filter(f=>untested.has(f.path)&&f.kind==='source'&&f.symbols.some(s=>s.exported))){
      const source=await read(f.path);const symbol=f.symbols.find(s=>s.exported)!;
      findings.push(makeFinding(f,source,{rule:'test-association-gap',title:'Exported source has no identified test association',category:'testing',severity:'low',confidence:0.55,status:'HYPOTHESIS',
        lineStart:symbol.lineStart,symbol:symbol.name,
        description:'No indexed test imports this file or matches its conventional basename. This heuristic does not prove the absence of integration, dynamic or external tests.',
        recommendation:'Check existing indirect coverage, then add high-value boundary tests for the exported behavior if coverage is missing.',
        rootCause:'Public behavior lacks an identifiable local regression boundary.',tests:['Verify indirect coverage and test boundary inputs plus one failure path for the exported API.']}));
    }
  }
  if(config.specialists.includes('security'))for(const f of active.filter(f=>f.kind==='source'||f.kind==='config')){
    const source=await read(f.path);const lines=source.split(/\r?\n/);
    for(let i=0;i<lines.length;i++)if(/\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b/.test(lines[i]!)){
      findings.push(makeFinding(f,source,{rule:'credential-pattern',title:'Credential-shaped literal requires verification',category:'security',severity:'high',confidence:0.75,status:'HYPOTHESIS',lineStart:i+1,kind:'source',
        description:'A source literal matches a recognized credential format. The value is redacted; validity and exposure are not tested.',
        recommendation:'Verify through the credential owner. If real, revoke and rotate it, remove it from source, and use supported secret injection.',
        rootCause:'Potential credential material is stored in versioned source.',tests:['Confirm the rotated credential is injected securely and secret scanning rejects future credential-shaped literals.']}));
    }
  }
  if(config.specialists.includes('maintainability')){
    const bodies=new Map<string,{path:string;name:string;start:number;end:number}[]>();
    for(const f of index.files.filter(f=>['TypeScript','JavaScript'].includes(f.language)&&f.kind==='source'&&!f.parseErrors.length)){
      const source=await read(f.path);const ast=ts.createSourceFile(f.path,source,ts.ScriptTarget.Latest,true);
      const visit=(node:ts.Node):void=>{
        if(ts.isFunctionDeclaration(node)||ts.isMethodDeclaration(node)||ts.isArrowFunction(node)||ts.isFunctionExpression(node)){
          if(node.body&&ts.isBlock(node.body)&&node.body.statements.length>=3){
            const scanner=ts.createScanner(ts.ScriptTarget.Latest,true,ts.LanguageVariant.Standard,node.body.getText(ast));
            const tokens:string[]=[];let token:ts.SyntaxKind;
            while((token=scanner.scan())!==ts.SyntaxKind.EndOfFileToken)tokens.push(`${token}:${scanner.getTokenText()}`);
            const normalized=tokens.join('|');if(normalized.length>=120){const digest=hash(normalized);const group=bodies.get(digest)??[];
              group.push({path:f.path,name:node.name?.getText(ast)??'<anonymous>',start:ast.getLineAndCharacterOfPosition(node.getStart(ast)).line+1,end:ast.getLineAndCharacterOfPosition(node.end).line+1});bodies.set(digest,group);}
          }
        }
        ts.forEachChild(node,visit);
      };visit(ast);
    }
    for(const group of bodies.values())if(group.length>1&&group.some(g=>!scopedOut.has(g.path))){
      const first=group.find(g=>!scopedOut.has(g.path))!;const f=index.files.find(f=>f.path===first.path)!;const source=await read(first.path);
      const finding=makeFinding(f,source,{rule:'duplicate-function-body',title:'Function block has an identical token sequence elsewhere',category:'maintainability',severity:'low',confidence:0.95,
        lineStart:first.start,lineEnd:first.end,symbol:first.name,
        description:`The function block’s tokens repeat at ${group.filter(g=>g!==first).map(g=>`${g.path}:${g.start}`).join(', ')}. Different closures or receiver state can still change behavior.`,
        recommendation:'Compare responsibilities and captured variables. Consolidate a shared operation only if the functions should evolve together.',
        rootCause:'Repeated implementation blocks may require coordinated maintenance.',tests:['Run equivalent cases for each original function and preserve receiver/captured-state behavior.']});
      for(const peer of group.filter(g=>g!==first)){
        const pf=index.files.find(f=>f.path===peer.path)!;const ps=await read(peer.path);finding.evidence.push({path:peer.path,lineStart:peer.start,lineEnd:peer.end,hash:pf.hash,snippet:redact(ps.split(/\r?\n/).slice(peer.start-1,peer.end).join('\n')).slice(0,2500),kind:'source'});
      }findings.push(finding);
    }
  }
  return findings;
}
