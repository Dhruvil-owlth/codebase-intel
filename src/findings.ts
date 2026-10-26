import { FindingSchema, type Finding, type FileRecord, type Config } from './schema.js';
import { hash, redact } from './safety.js';

export type Candidate = {rule:string; title:string; category:Finding['category']; lineStart:number;lineEnd?:number;
  symbol?:string;severity?:Finding['severity'];confidence?:number;status?:Finding['status'];
  description:string; recommendation:string;tests:string[];rootCause?:string;benchmarks?:string[];kind?:Finding['evidence'][number]['kind']};
export function makeFinding(file:Pick<FileRecord,'path'|'hash'|'module'>,source:string,c:Candidate):Finding {
  const lines=source.split(/\r?\n/); const lineEnd=Math.max(c.lineStart,Math.min(c.lineEnd??c.lineStart,lines.length));
  const symbol=c.symbol??'<module>'; const snippet=redact(lines.slice(c.lineStart-1,lineEnd).join('\n')).slice(0,2500);
  const phase= c.category==='correctness'?1:c.category==='security'||c.category==='dependencies'?2:
    c.category==='performance'?4:c.category==='architecture'||c.category==='maintainability'?5:6;
  return FindingSchema.parse({
    id:`F-${hash(`${c.rule}:${file.path}:${symbol}:${snippet}`).slice(0,12)}`,rule:c.rule,title:c.title,
    category:c.category,severity:c.severity??'medium',priority:'P2',score:0,confidence:c.confidence??0.85,
    status:c.status??'SUPPORTED',measurement:c.category==='performance'?'statically-inferred':'not-applicable',
    module:file.module,path:file.path,symbol,lineStart:c.lineStart,lineEnd,
    description:c.description,evidence:[{path:file.path,lineStart:c.lineStart,lineEnd,hash:file.hash,snippet,kind:c.kind??'ast'}],
    rootCause:c.rootCause??`${c.rule}: ${c.description}`,currentBehavior:c.description,
    expectedBehavior:c.recommendation,impact:`Potential ${c.category} impact; runtime reachability and business impact require project-owner validation.`,
    reproduction:['Inspect the cited source and identify reachable callers.',...c.tests],recommendation:c.recommendation,
    alternatives:['Retain the implementation if representative tests establish that the behavior is intentional; document the invariant.'],
    tradeoffs:['Additional validation or a changed implementation can alter edge-case behavior and maintenance cost.'],
    compatibility:'Preserve the current runtime and public API; verify the installed dependency versions before selecting replacement APIs.',
    regressionRisks:['Callers may rely on the current behavior.'],tests:c.tests,benchmarks:c.benchmarks??[],
    effort:{estimate:'0.5–2 engineering days, subject to caller and test review',uncertainty:'high'},
    dependencies:[],related:[],phase,completionCriteria:['The cited condition is resolved or documented with reproducible evidence.',...c.tests],
    references:[],origin:'deterministic',
  });
}
export function prioritize(findings:Finding[],config:Config):Finding[] {
  const severity={critical:5,high:4,medium:3,low:2,info:1}; const w=config.weights;
  for(const f of findings) {
    f.score=Math.round((severity[f.severity]*w.severity+f.confidence*w.confidence+
      (f.category==='security'?w.security:0)-w.effort-(f.status==='HYPOTHESIS'?2:1)*w.risk)*100)/100;
    f.priority=f.score>=24?'P0':f.score>=19?'P1':f.score>=12?'P2':'P3';
  }
  return findings.sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id));
}
