import { type Config, type Finding, type Roadmap, type Run, type Task } from './schema.js';
import { hash, md, safeRead, redact } from './safety.js';
import { prioritize } from './findings.js';

export const phaseNames=['Baseline and safety','Critical correctness','Security and reliability','Performance quick wins',
  'Logic and algorithms','Architecture and refactoring','Scalability and future readiness','Verification and hardening'];

export function topologicalGroups(tasks:Task[]):string[][] {
  const byId=new Map(tasks.map(t=>[t.id,t]));if(byId.size!==tasks.length)throw new Error('Duplicate roadmap task ID');
  for(const task of tasks)for(const dependency of task.dependencies)if(!byId.has(dependency))throw new Error(`Missing prerequisite ${dependency}`);
  const remaining=new Set(byId.keys());const done=new Set<string>();const groups:string[][]=[];
  while(remaining.size){const group=[...remaining].filter(id=>byId.get(id)!.dependencies.every(d=>done.has(d))).sort();
    if(!group.length)throw new Error('Roadmap dependency cycle');groups.push(group);for(const id of group){remaining.delete(id);done.add(id);}}
  return groups;
}
export function synthesize(input:Finding[],config:Config):{findings:Finding[];roadmap:Roadmap} {
  const unique=new Map<string,Finding>();
  for(const finding of input){const prior=unique.get(finding.id);
    if(prior){prior.related=[...new Set([...prior.related,...finding.related])];continue;}
    // A model duplicate never supersedes deterministic evidence.
    const overlap=[...unique.values()].find(f=>f.path===finding.path&&f.rule===finding.rule&&f.symbol===finding.symbol&&f.lineStart===finding.lineStart);
    if(overlap){overlap.related=[...new Set([...overlap.related,...finding.related])];continue;}
    unique.set(finding.id,structuredClone(finding));
  }
  const findings=prioritize([...unique.values()],config);
  const rootGroups=new Map<string,Finding[]>();
  for(const f of findings){const key=f.origin==='model'?`${f.rule}:${f.category}:${f.rootCause}`:f.rule;rootGroups.set(key,[...(rootGroups.get(key)??[]),f]);}
  const rootCauses=[...rootGroups].map(([rule,group])=>({id:`RC-${hash(rule).slice(0,8)}`,
    cause:`${group[0]!.rootCause} ${group.length>1?'Shared rule signatures suggest a recurring mechanism; a single organizational cause is not established.':''}`,findings:group.map(f=>f.id)}));
  const conflicts:Roadmap['conflicts']=[];
  const byPath=new Map<string,Finding[]>();for(const f of findings)byPath.set(f.path,[...(byPath.get(f.path)??[]),f]);
  for(const group of byPath.values())for(const performance of group.filter(f=>f.category==='performance')){
    const risks=group.filter(f=>f.id!==performance.id&&['correctness','security'].includes(f.category)&&f.lineStart<=performance.lineEnd+10&&f.lineEnd>=performance.lineStart-10);
    if(risks.length){performance.dependencies=[...new Set([...performance.dependencies,...risks.map(f=>f.id)])];
      // Precedence follows phase ordering; an optimization waits for the earlier safety correction.
      for(const risk of risks)performance.phase=Math.max(performance.phase,risk.phase) as Finding['phase'];
      conflicts.push({findings:[performance.id,...risks.map(f=>f.id)],reason:'Performance and safety findings affect neighboring source ranges; changes may interact.',
        resolution:'Resolve the safety findings first, preserve regression tests, then benchmark the optimization. This is a potential interaction, not a proven contradictory recommendation.'});}
  }
  for(const group of rootGroups.values())for(const f of group) {
    const canonical=findings.find(x=>x.id===f.id);if(canonical)canonical.related=[...new Set([...canonical.related,...group.filter(p=>p.id!==f.id).map(p=>p.id)])];
  }
  const baseline:Task={id:'T-BASELINE',phase:0,title:'Establish reproducible baselines and a rollback point',findings:[],dependencies:[],files:[],
    steps:['Review coverage exclusions, parser failures and unsupported technologies before accepting the roadmap.',
      'Confirm project requirements, reachable behavior and the relevant installed versions with project owners.',
      'Record a clean Git commit or preserve the exact working tree without modifying unrelated work.',
      'In an isolated environment, explicitly review and authorize the project’s baseline tests and representative benchmarks.'],
    tests:['Capture baseline test results and document existing failures.'],benchmarks:['Measure representative latency, throughput, memory or input-size curves before setting numeric targets.'],
    rollback:'Return to the reviewed commit or restore the preserved working tree; do not discard unrelated work.',
    done:['A reproducible baseline, approved scope, test commands and rollback point are recorded.'],risk:'low',status:'pending'};
  const tasks:Task[]=[baseline];
  const taskFor=(id:string)=>`T-${id.slice(2)}`;
  for(const f of findings){
    tasks.push({id:taskFor(f.id),phase:f.phase,title:f.title,findings:[f.id],dependencies:['T-BASELINE',...f.dependencies.map(taskFor)],files:[...new Set(f.evidence.map(e=>e.path))],
      steps:[`Reinspect ${f.path}:${f.lineStart} (${f.symbol}) and confirm the ${f.status.toLowerCase()} finding against callers.`,
        ...f.tests.map(t=>`Establish regression protection: ${t}`),
        f.recommendation,`Compatibility review: ${f.compatibility}`,
        'Apply the smallest reviewed change in an isolated branch or worktree, then inspect the resulting diff.',
        'Run the approved targeted and regression checks, record evidence, and update the finding status.'],
      tests:f.tests,benchmarks:f.benchmarks,
      rollback:`Revert the isolated change for ${f.id}; restore the recorded baseline and rerun its regression checks.`,
      done:f.completionCriteria,risk:f.status==='HYPOTHESIS'||f.phase>=4?'medium':'low',status:'pending'});
  }
  // Explicit phase barriers give conservative, explainable ordering. Parallel groups are suggestions,
  // and a human still needs to check overlapping files before concurrent implementation.
  // Explicit prerequisites take precedence over the default phase classification.
  for(const group of topologicalGroups(tasks))for(const id of group){
    const task=tasks.find(t=>t.id===id)!;
    task.phase=Math.max(task.phase,...task.dependencies.map(d=>tasks.find(t=>t.id===d)!.phase));
    for(const findingId of task.findings){const f=findings.find(f=>f.id===findingId);if(f)f.phase=task.phase as Finding['phase'];}
  }
  for(const t of tasks.filter(t=>t.phase>0)){
    const previousPhase=Math.max(0,...tasks.filter(p=>p.phase<t.phase).map(p=>p.phase));
    t.dependencies=[...new Set([...t.dependencies,...tasks.filter(p=>p.phase===previousPhase).map(p=>p.id)])];
  }
  tasks.push({id:'T-HARDEN',phase:7,title:'Verify the combined changes and update engineering documentation',findings:findings.map(f=>f.id),
    dependencies:tasks.map(t=>t.id),files:[...new Set(tasks.flatMap(t=>t.files))],
    steps:['Review the combined diff and confirm scope with project owners.',
      'Run approved regression, security and operational checks, with representative performance comparisons where relevant.',
      'Repeat the audit, explain remaining findings and compare coverage with the baseline.',
      'Update architecture and operating documentation and preserve the change report.'],
    tests:['No unexplained regression relative to the recorded baseline.'],benchmarks:['Document measured differences and uncertainty; reject regressions beyond agreed budgets.'],
    rollback:'Revert the reviewed change set using the baseline rollback plan. Do not deploy or merge automatically.',
    done:['All task criteria have evidence, residual risks have owners, and documentation reflects the final state.'],risk:'medium',status:'pending'});
  const parallelGroups=topologicalGroups(tasks);
  return {findings,roadmap:{tasks,rootCauses,conflicts,scoring:`score = severity(1–5) × ${config.weights.severity} + confidence × ${config.weights.confidence} + security bonus ${config.weights.security} − effort penalty ${config.weights.effort} − uncertainty/risk penalty (${config.weights.risk} or ${2*config.weights.risk}). P0≥24, P1≥19, P2≥12, else P3. Scores are triage aids, not measured business impact.`,parallelGroups}};
}

/** Reconcile persisted specialist views with canonical records before planning. */
export async function reconcileSpecialistDocuments(run:Run):Promise<void> {
  const directory=`runs/${run.id}/intermediate`;
  const expected=new Set(run.findings.map(f=>f.id));const seen=new Set<string>();
  for(const category of run.config.specialists){
    let document:string;
    try{document=await safeRead(run.output,`${directory}/${category}.md`,8000000);}catch{continue;}
    for(const match of document.matchAll(/F-[a-f0-9]{12}/g)){
      if(expected.has(match[0]))seen.add(match[0]);else run.index?.coverage.unresolvedEvidence.push(`Specialist document references unknown finding ${match[0]}`);
    }
  }
  for(const id of expected)if(!seen.has(id))run.index?.coverage.unresolvedEvidence.push(`Finding ${id} missing from specialist views`);
}
