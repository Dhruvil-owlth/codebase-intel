import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import ignore, { type Ignore } from 'ignore';
import { minimatch } from 'minimatch';
import { type Config, type Coverage, type FileRecord, type Index, type Technology, ENGINE_VERSION } from './schema.js';
import { defaultRegistry, languageOf, parseFile, type AdapterRegistry } from './adapters.js';
import { errorText, hash, inside, posix, safeRead, redact } from './safety.js';
import { runTool } from './tools.js';

const excludedDirs=new Set(['.git','.svn','.hg','node_modules','vendor','.venv','venv','__pycache__','.next','.nuxt','dist','build','target','coverage','.terraform','.cache']);
const secretPath=(p:string):boolean=> /(?:^|\/)(?:\.env(?:\..*)?|\.npmrc|\.pypirc|credentials(?:\.json)?|id_rsa|id_ed25519|[^/]*\.(?:pem|p12|pfx|key))$/i.test(p);
const binaryPath=(p:string):boolean=>/\.(?:png|jpe?g|gif|webp|ico|pdf|woff2?|ttf|eot|zip|gz|tar|mp[34]|mov|wav|sqlite3?|db|exe|dll|so|wasm|class|jar|lockb)$/i.test(p);
const manifests=new Set(['package.json','pyproject.toml','setup.py','requirements.txt','Cargo.toml','go.mod','pom.xml','build.gradle','composer.json','Gemfile','pubspec.yaml','CMakeLists.txt']);
function classify(p:string,language:string):FileRecord['kind'] {
  if(/(?:^|\/)(?:__tests__|tests?|spec)(?:\/|\.)|(?:\.test|\.spec|_test|_spec)\.|(?:^|\/)test_[^/]+\.py$/.test(p))return 'test';
  if(/\.(?:md|rst|txt)$/.test(p)&&!p.endsWith('requirements.txt'))return 'documentation';
  if(manifests.has(path.posix.basename(p))||/\.(?:json|ya?ml|toml|xml)$/.test(p)||/(?:^|\/)(?:Dockerfile|Makefile|\.github\/|\.gitignore|\.intelignore)/.test(p))return 'config';
  if(!['Unknown','JSON','YAML','TOML','Markdown','XML'].includes(language))return 'source';
  return 'other';
}
function selected(p:string,config:Config):boolean{return config.include.some(g=>minimatch(p,g,{dot:true}))&&!config.exclude.some(g=>minimatch(p,g,{dot:true}));}
type IgnoreRule={base:string;matcher:Ignore};
async function inventory(config:Config,coverage:Coverage,deadline:number):Promise<{path:string;source:string;bytes:number}[]> {
  const files:{path:string;source:string;bytes:number}[]=[];let totalBytes=0,visited=0;
  const outputRelative=inside(config.target,config.output)?posix(path.relative(config.target,config.output)):undefined;
  let stopped=false;
  const walk=async (directory:string,rules:IgnoreRule[]):Promise<void>=>{
    if(Date.now()>deadline){coverage.failed.push({path:directory||'.',reason:'Run time budget exhausted; subtree unvisited'});stopped=true;return;}
    const absolute=path.join(config.target,directory);
    for(const name of ['.gitignore','.intelignore']){
      const p=posix(path.join(directory,name));
      try {const text=await safeRead(config.target,p,100000);rules=[...rules,{base:directory,matcher:ignore().add(text)}];}
      catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')coverage.excluded.push({path:p,reason:'Ignore rules unreadable or unsafe'});}
    }
    let entries;
    try{entries=await fs.readdir(absolute,{withFileTypes:true});}catch(e){coverage.failed.push({path:directory||'.',reason:errorText(e)});return;}
    entries.sort((a,b)=>a.name.localeCompare(b.name));
    for(const entry of entries){
      if(stopped)break;
      const p=posix(path.join(directory,entry.name));visited++;
      if(visited>config.budgets.maxFiles*10){coverage.failed.push({path:p,reason:'Inventory entry budget exhausted; remaining paths unvisited'});stopped=true;break;}
      let reason='';
      if(entry.isSymbolicLink())reason='Symbolic links are never followed';
      else if(entry.isDirectory()&&excludedDirs.has(entry.name))reason='Generated, vendor, cache or VCS directory; subtree pruned';
      else if(outputRelative&&(p===outputRelative||p.startsWith(outputRelative+'/')))reason='Configured output root; subtree pruned';
      else if(secretPath(p))reason='Credential-bearing filename excluded before reading';
      else if(binaryPath(p))reason='Binary or asset extension';
      else if(config.exclude.some(g=>minimatch(p,g,{dot:true})||entry.isDirectory()&&minimatch(p+'/',g,{dot:true})))reason='Configured exclusion';
      else if(rules.some(r=>{const rel=posix(path.relative(r.base||'.',p));return !rel.startsWith('../')&&r.matcher.ignores(rel+(entry.isDirectory()?'/':''));}))reason='Git or Intel ignore rule; directory subtrees pruned';
      if(!reason&&redact(p)!==p)reason='Credential-shaped filename excluded before reading';
      if(reason){coverage.excluded.push({path:redact(p),reason});continue;}
      if(entry.isDirectory()){await walk(p,rules);continue;}
      if(!entry.isFile()){coverage.excluded.push({path:p,reason:'Non-regular file'});continue;}
      if(!selected(p,config)){coverage.excluded.push({path:p,reason:'Outside include patterns'});continue;}
      if(files.length>=config.budgets.maxFiles){coverage.failed.push({path:p,reason:'File count budget exhausted; remaining paths unvisited'});stopped=true;break;}
      if(Date.now()>deadline){coverage.failed.push({path:p,reason:'Run time budget exhausted; remaining paths unvisited'});stopped=true;break;}
      try {
        const source=await safeRead(config.target,p,config.budgets.maxFileBytes);const bytes=Buffer.byteLength(source);
        if(source.includes('\0')){coverage.excluded.push({path:p,reason:'Binary NUL content'});continue;}
        if(totalBytes+bytes>config.budgets.maxTotalBytes){coverage.failed.push({path:p,reason:'Total byte budget exhausted; remaining paths unvisited'});stopped=true;break;}
        totalBytes+=bytes;files.push({path:p,source,bytes});
      }catch(e){const reason=errorText(e);coverage.excluded.push({path:p,reason});coverage.failed.push({path:p,reason:`Input could not be analyzed: ${reason}`});}
    }
  };
  await walk('',[]);return files;
}
function owningModule(p:string,moduleRoots:string[]):string {
  return moduleRoots.filter(root=>root==='.'||p.startsWith(root+'/')).sort((a,b)=>b.length-a.length)[0]??'.';
}
function lineOf(source:string,value:string):number {const i=source.indexOf(value);return i<0?1:source.slice(0,i).split('\n').length;}
function technologies(raw:{path:string;source:string}[],coverage:Coverage):Technology[] {
  const result:Technology[]=[]; const map=new Map(raw.map(f=>[f.path,f.source]));
  const push=(name:string,version:string,kind:Technology['versionKind'],p:string,s:string,adapter:string,refs:string[]=[])=>result.push({name:redact(name),version:redact(version),versionKind:kind,path:p,line:lineOf(s,name),adapter,references:refs});
  for(const f of raw){const base=path.posix.basename(f.path);
    if(base==='package.json'){
      try {const pkg=JSON.parse(f.source); push('Node.js',pkg.engines?.node??'not declared','declared',f.path,f.source,'javascript-typescript',['https://nodejs.org/api/']);
        let lock:Record<string,{version?:string}>|undefined;
        try{const lockSource=map.get(path.posix.join(path.posix.dirname(f.path),'package-lock.json'));if(lockSource)lock=JSON.parse(lockSource).packages;}catch{coverage.limitations.push(`Could not parse lockfile for ${f.path}`);}
        for(const [name,version] of Object.entries({...pkg.dependencies,...pkg.devDependencies,...pkg.peerDependencies})){
          const locked=lock?.[`node_modules/${name}`]?.version;
          push(name,locked??String(version),locked?'locked':'declared',f.path,f.source,'javascript-typescript');
        }
      }catch{coverage.failed.push({path:f.path,reason:'Invalid package.json; technology detection incomplete'});}
    }else if(base==='pyproject.toml'||base==='requirements.txt'){
      push('Python',base==='pyproject.toml'?f.source.match(/requires-python\s*=\s*["']([^"']+)/)?.[1]??'not declared':'not declared','declared',f.path,f.source,'python',['https://docs.python.org/3/']);
      for(const name of ['django','fastapi','flask','sqlalchemy','pytest']){const m=f.source.match(new RegExp(`\\b${name}\\s*([=<>!~^]+[^\\s,"'\\]]+)?`,'i'));if(m)push(name,m[1]??'unspecified','declared',f.path,f.source,'python');}
    } else {
      const tech:Record<string,[string,string]>={'go.mod':['Go',f.source.match(/^go\s+(\S+)/m)?.[1]??'not declared'],'Cargo.toml':['Rust',f.source.match(/rust-version\s*=\s*"([^"]+)/)?.[1]??'not declared'],
        'pom.xml':['Java','not declared'],'build.gradle':['Gradle','not declared'],'composer.json':['PHP','not declared'],'Gemfile':['Ruby','not declared'],'pubspec.yaml':['Dart','not declared'],'Dockerfile':['Docker','not declared']};
      if(tech[base]){const [name,version]=tech[base];push(name,version,'detected',f.path,f.source,'generic');}
    }
  }
  for(const language of new Set(raw.map(f=>languageOf(f.path))))if(['JavaScript','TypeScript','Python'].includes(language)&&!result.some(t=>t.name===language)){
    const f=raw.find(f=>languageOf(f.path)===language)!;push(language,'not declared','detected',f.path,f.source,language==='Python'?'python':'javascript-typescript');
  }
  return result;
}
function resolveImports(index:Index,raw:Map<string,string>):void {
  const all=new Set(index.files.map(f=>f.path)); const packageRoots=new Map<string,string>();
  for(const f of index.files.filter(f=>path.posix.basename(f.path)==='package.json'))try{const p=JSON.parse(raw.get(f.path)!);if(typeof p.name==='string')packageRoots.set(p.name,path.posix.dirname(f.path));}catch{}
  const candidates=(base:string,language:string):string[]=>language==='Python'?[
    `${base}.py`,path.posix.join(base,'__init__.py')]:[base,...['.ts','.tsx','.mts','.cts','.js','.jsx','.mjs','.cjs','.json'].map(ext=>base+ext),
      ...['index.ts','index.tsx','index.js','index.mjs'].map(n=>path.posix.join(base,n)),...['.ts','.tsx'].map(ext=>base.replace(/\.[mc]?js$/,ext))];
  for(const f of index.files){
    for(const imp of f.imports){
      const bases:string[]=[];
      if(f.language==='Python'){
        const dots=imp.specifier.match(/^\.+/)?.[0].length??0;
        let directory=dots?path.posix.dirname(f.path):'.';for(let i=1;i<dots;i++)directory=path.posix.dirname(directory);
        bases.push(path.posix.join(directory,imp.specifier.slice(dots).replaceAll('.','/')));
        if(!dots)bases.push(path.posix.join(f.module,imp.specifier.replaceAll('.','/')));
      } else if(imp.specifier.startsWith('.'))bases.push(path.posix.normalize(path.posix.join(path.posix.dirname(f.path),imp.specifier)));
      else {
        for(const [name,root] of packageRoots)if(imp.specifier===name||imp.specifier.startsWith(name+'/')){
          if(imp.specifier!==name)bases.push(path.posix.join(root,imp.specifier.slice(name.length+1)));
          else {const pkg=JSON.parse(raw.get(path.posix.join(root,'package.json'))!);bases.push(path.posix.join(root,typeof pkg.main==='string'?pkg.main:'index'),path.posix.join(root,'src/index'));}
        }
        // Restricted tsconfig path mapping: JSON only, no extends resolution or code execution.
        const configs=index.files.filter(c=>/tsconfig[^/]*\.json$/.test(c.path)&&f.path.startsWith(path.posix.dirname(c.path)==='.'?'':path.posix.dirname(c.path)+'/'));
        for(const cfg of configs)try{const parsed=JSON.parse(raw.get(cfg.path)!);const options=parsed.compilerOptions??{};
          for(const [pattern,targets] of Object.entries(options.paths??{})){
            const [prefix,suffix='']=pattern.split('*');const middle=pattern.includes('*')&&imp.specifier.startsWith(prefix!)&&imp.specifier.endsWith(suffix)?imp.specifier.slice(prefix!.length,imp.specifier.length-suffix.length):pattern===imp.specifier?'':undefined;
            if(middle===undefined||!Array.isArray(targets))continue;
            for(const t of targets)if(typeof t==='string')bases.push(path.posix.join(path.posix.dirname(cfg.path),options.baseUrl??'.',t.replace('*',middle)));
          }
        }catch{}
      }
      imp.resolved=bases.flatMap(base=>candidates(base,f.language)).find(p=>all.has(p));
      if(imp.resolved)index.edges.push({from:f.path,to:imp.resolved,line:imp.line});
    }
  }
}
export async function buildIndex(config:Config,previous?:Index,options:{scope?:string;changedOnly?:boolean;registry?:AdapterRegistry;deadline?:number}={}):Promise<Index> {
  const coverage:Coverage={included:[],excluded:[],parsed:[],failed:[],analyzedModules:[],depth:config.depth,tools:[],untestedPaths:[],unsupported:[],
    unresolvedEvidence:[],limitations:['Static analysis is partial. Business invariants, data flow, runtime behavior, accessibility, vulnerabilities and performance are not proven.',
      'No package scripts, tests, builds, network research, profilers, dependency vulnerability feeds or MCP services run during default analysis.',
      'Imports resolve against indexed local files and basic JSON tsconfig paths; dynamic imports, framework containers and complex resolver plugins may be unresolved.',
      'Git ignores are used for inventory, including nested files; ignored directories are pruned.'],reused:0,changed:[],invalidated:[],scopedOut:[]};
  const deadline=options.deadline??Date.now()+config.budgets.maxRunSeconds*1000;
  const raw=await inventory(config,coverage,deadline);
  const moduleRoots=[...new Set(['.',...raw.filter(f=>manifests.has(path.posix.basename(f.path))||/\.(?:csproj|sln)$/.test(f.path)).map(f=>path.posix.dirname(f.path))])];
  const registry=options.registry??defaultRegistry();const old=new Map(previous?.files.map(f=>[f.path,f])??[]);
  const index:Index={version:ENGINE_VERSION,files:[],technologies:technologies(raw,coverage),edges:[],modules:[],coverage,git:{},fingerprint:''};
  let cursor=0;
  const worker=async()=>{
    while(cursor<raw.length){const item=raw[cursor++]!;const digest=hash(item.source);const prior=old.get(item.path);
      const file:FileRecord={path:item.path,hash:digest,bytes:item.bytes,lines:item.source.split('\n').length,language:languageOf(item.path),kind:classify(item.path,languageOf(item.path)),
        module:owningModule(item.path,moduleRoots),parser:'inventory-only',parseErrors:[],symbols:[],imports:[],exports:[],references:[],configFor:[],testsFor:[],cacheHit:false,findings:[]};
      if(prior?.hash===digest&&previous?.version===ENGINE_VERSION&&config.resume==='reuse-unchanged'&&prior.parseErrors.length===0&&!['unavailable','failed'].includes(prior.parser)){
        Object.assign(file,structuredClone(prior),{cacheHit:true,module:file.module,configFor:[],testsFor:[]});for(const imp of file.imports)delete imp.resolved;
        coverage.reused++;
      }else{
        coverage.changed.push(item.path);
        if(Date.now()>deadline)file.parseErrors.push('Parsing skipped: run time budget exhausted');
        else if(file.kind==='source'||file.kind==='test')await parseFile({file,source:item.source,config,tools:coverage.tools},registry);
      }
      file.imports=file.imports.map(i=>({...i,specifier:redact(i.specifier)}));
      file.symbols=file.symbols.map(s=>({...s,name:redact(s.name)}));
      file.exports=file.exports.map(redact);file.references=file.references.map(r=>({...r,name:redact(r.name)}));
      if(file.parseErrors.length)coverage.failed.push(...file.parseErrors.map(reason=>({path:file.path,reason})));
      if(!['inventory-only','unavailable','failed'].includes(file.parser)&&!file.parseErrors.length)coverage.parsed.push(file.path);
      if(file.kind==='source'&&file.parser==='inventory-only')coverage.unsupported.push(`${file.language}: inventory only (${file.path})`);
      index.files.push(file);coverage.included.push(file.path);
    }
  };
  await Promise.all(Array.from({length:config.concurrency},worker));index.files.sort((a,b)=>a.path.localeCompare(b.path));
  resolveImports(index,new Map(raw.map(f=>[f.path,f.source])));
  const changed=new Set([...coverage.changed,...(previous?.files.filter(f=>!index.files.some(n=>n.path===f.path)).map(f=>f.path)??[])]);
  const affected=new Set(changed);let didChange=true;
  while(didChange){didChange=false;for(const edge of [...index.edges,...(previous?.edges??[])])if(affected.has(edge.to)&&!affected.has(edge.from)){affected.add(edge.from);didChange=true;}}
  coverage.changed=[...changed].sort();coverage.invalidated=[...affected].filter(p=>!changed.has(p)).sort();
  for(const file of index.files){
    const stem=path.posix.basename(file.path).replace(/^(?:test_|spec_)/,'').replace(/(?:\.test|\.spec|_test|_spec)?\.[^.]+$/,'');
    if(file.kind==='test')file.testsFor=[...new Set([...index.edges.filter(e=>e.from===file.path).map(e=>e.to),...index.files.filter(f=>f.kind==='source'&&
      path.posix.basename(f.path).replace(/\.[^.]+$/,'')===stem).map(f=>f.path)])];
    if(file.kind==='config')file.configFor=index.files.filter(f=>f.module===file.module&&f.kind==='source').map(f=>f.path);
    const scope=options.scope;
    const inScope=!scope||file.path.startsWith(scope.replace(/\/$/,'')+'/')||file.path===scope||file.path.split('/').includes(scope)||minimatch(file.path,scope,{dot:true});
    if(!inScope||options.changedOnly&&!affected.has(file.path))coverage.scopedOut.push(file.path);
  }
  coverage.untestedPaths=index.files.filter(f=>f.kind==='source'&&!index.files.some(t=>t.testsFor.includes(f.path))).map(f=>f.path);
  index.modules=moduleRoots.map(root=>({path:root,files:index.files.filter(f=>f.module===root).map(f=>f.path),
    entryPoints:index.files.filter(f=>f.module===root&&/(?:^|\/)(?:index|main|app|server|cli|__main__)\.[^.]+$/.test(f.path)).map(f=>f.path)})).filter(m=>m.files.length);
  coverage.analyzedModules=index.modules.filter(m=>m.files.some(p=>!coverage.scopedOut.includes(p))).map(m=>m.path);
  if(config.tools.git){
    const commands=[['--version'],['-c','core.fsmonitor=false','rev-parse','--verify','HEAD'],['-c','core.fsmonitor=false','symbolic-ref','--short','HEAD'],
      ['-c','core.fsmonitor=false','ls-files','--stage','-z'],['-c','core.fsmonitor=false','rev-parse','--show-object-format']];
    const results=await Promise.all(commands.map(args=>runTool('git',args,config.target,undefined,config)));coverage.tools.push(...results);
    if(results[1]?.status==='ok')index.git.head=results[1].stdout.trim();
    if(results[2]?.status==='ok')index.git.branch=results[2].stdout.trim();
    if(results[3]?.status==='ok'){
      const tracked=new Map<string,string>();
      for(const entry of results[3].stdout.split('\0')){const m=entry.match(/^\d+ ([a-f0-9]+) [0-3]\t([\s\S]+)$/);if(m)tracked.set(m[2]!,m[1]!);}
      const algorithm=results[4]?.stdout.trim()==='sha256'?'sha256':'sha1';
      index.git.dirty=[];
      for(const file of raw){const stored=tracked.get(file.path);
        if(!stored){index.git.dirty.push(`Untracked candidate: ${file.path}`);continue;}
        const bytes=Buffer.from(file.source);const blob=createHash(algorithm).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
        if(blob!==stored)index.git.dirty.push(`Raw content differs from index (attributes not evaluated): ${file.path}`);
      }
      coverage.limitations.push('Working-tree awareness compares included raw file bytes with Git index blobs. Git status, content filters, staged-vs-HEAD changes, file modes, excluded and deleted paths are not evaluated.');
    }
  }
  index.fingerprint=hash(index.files.map(f=>`${f.path}:${f.hash}`).join('\n'));return index;
}
