import { minimatch } from 'minimatch';
import { type Index, type Config } from './schema.js';
import { hash, redact, safeRead } from './safety.js';

export type Query={symbol?:string;path?:string;keyword?:string;related?:boolean;tokens?:number};
export type ContextPackage={estimatedTokens:number;truncated:boolean;items:{path:string;lineStart:number;lineEnd:number;hash:string;source:string}[]};
export async function retrieve(index:Index,config:Config,query:Query):Promise<ContextPackage> {
  if(!query.symbol&&!query.path&&!query.keyword)throw new Error('Provide a symbol, path pattern or keyword');
  const budget=Math.max(128,Math.min(query.tokens??config.budgets.contextTokens,config.budgets.contextTokens));
  const hits=new Map<string,{start:number;end:number}[]>();
  for(const f of index.files){
    if(query.path&&!minimatch(f.path,query.path,{dot:true}))continue;
    const ranges:{start:number;end:number}[]=[];
    if(query.symbol)ranges.push(...f.symbols.filter(s=>s.name===query.symbol||s.name.split('.').at(-1)===query.symbol).map(s=>({start:s.lineStart,end:s.lineEnd})));
    if(query.keyword){const source=await safeRead(config.target,f.path,config.budgets.maxFileBytes);if(hash(source)!==f.hash)throw new Error(`Index stale for ${f.path}`);
      const lines=source.split(/\r?\n/);for(let i=0;i<lines.length;i++)if(lines[i]!.includes(query.keyword))ranges.push({start:Math.max(1,i-2),end:Math.min(lines.length,i+4)});}
    if(!query.symbol&&!query.keyword)ranges.push({start:1,end:f.lines});
    if(ranges.length)hits.set(f.path,ranges);
  }
  if(query.related)for(const p of [...hits.keys()])for(const e of index.edges)if(e.from===p||e.to===p){const other=e.from===p?e.to:e.from;if(!hits.has(other))hits.set(other,[{start:1,end:60}]);}
  const result:ContextPackage={estimatedTokens:0,truncated:false,items:[]};let remaining=budget*4;
  for(const [p,ranges] of hits){const f=index.files.find(f=>f.path===p)!;const source=await safeRead(config.target,p,config.budgets.maxFileBytes);
    if(hash(source)!==f.hash)throw new Error(`Index stale for ${p}`);const lines=source.split(/\r?\n/);
    for(const range of ranges){if(remaining<100){result.truncated=true;break;}
      const chosen:string[]=[];let used=p.length+100;let end=range.start-1;
      for(let i=range.start-1;i<Math.min(range.end,lines.length);i++){const line=redact(lines[i]!);if(used+line.length+1>remaining){result.truncated=true;break;}chosen.push(line);used+=line.length+1;end=i+1;}
      if(chosen.length){result.items.push({path:p,lineStart:range.start,lineEnd:end,hash:f.hash,source:chosen.join('\n')});remaining-=used;}
    }
  }
  result.estimatedTokens=Math.ceil((budget*4-remaining)/4);return result;
}
