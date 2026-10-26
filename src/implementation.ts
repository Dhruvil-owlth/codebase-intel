import { type Run, type Task } from './schema.js';
import { atomicWrite, hash, md, safeRead, writeJson } from './safety.js';
import { runRoot } from './orchestrator.js';

/** Scope approval and handoff only. This release never edits application code or runs commands. */
export async function prepareImplementation(run:Run,taskId:string,approved:boolean):Promise<{file:string;ready:boolean;blockers:string[]}> {
  if(!approved)throw new Error('Implementation preparation requires explicit --approve for the selected task scope; no source edits are performed');
  if(!run.roadmap)throw new Error('The run has no validated roadmap');
  const task=run.roadmap.tasks.find(t=>t.id===taskId);if(!task)throw new Error('Unknown roadmap task ID');
  if(!/^[A-Za-z0-9-]+$/.test(taskId))throw new Error('Unsafe roadmap task ID');
  const blockers:string[]=[];
  if(!run.validation?.valid)blockers.push('Audit artifacts have not passed validation.');
  for(const dependency of task.dependencies){const pre=run.roadmap.tasks.find(t=>t.id===dependency);if(pre?.status!=='completed')blockers.push(`Prerequisite ${dependency} has no recorded completion evidence.`);}
  const sourceHashes:Record<string,string>={};
  for(const p of task.files){const indexed=run.index?.files.find(f=>f.path===p);if(!indexed){blockers.push(`Unindexed task file ${p}`);continue;}
    try{sourceHashes[p]=hash(await safeRead(run.target,p,run.config.budgets.maxFileBytes));if(sourceHashes[p]!==indexed.hash)blockers.push(`Source changed since audit: ${p}`);}
    catch{blockers.push(`Task source cannot be read safely: ${p}`);}
  }
  const file=`implementation/${taskId}.md`;const planHash=hash(JSON.stringify({task,sourceHashes,run:run.id}));
  const record={schemaVersion:1,lifecycle:'PREPARATION_ONLY',run:run.id,taskId,approvedScope:true,approvedAt:new Date().toISOString(),planHash,
    sourceHashes,readyForHumanHandoff:blockers.length===0,blockers,task,engineImplemented:false,
    requiredLifecycle:['Confirm scope and prerequisites','Capture approved baseline tests and metrics','Create an isolated branch or worktree',
      'Apply reviewed changes with an external coding agent or engineer','Run targeted and regression checks','Measure relevant performance',
      'Review the diff and rollback strategy','Record completion evidence and update the roadmap'],
    prohibitedAutomaticActions:['source edits','arbitrary commands','merge','deploy','destructive operations']};
  await writeJson(runRoot(run),`implementation/${taskId}.json`,record);
  await atomicWrite(runRoot(run),file,`# Approved scope handoff: ${md(task.id)}\n\n${md(task.title)}\n\n`+
    `Lifecycle: **PREPARATION ONLY**. The code-editing and command-execution engine is not implemented.\n\nPlan fingerprint: ${planHash}\n\n`+
    `## Prerequisites\n\n${blockers.length?blockers.map(b=>`- ${md(b)}`).join('\n'):'No unresolved recorded prerequisites; a human still must establish the baseline.'}\n\n`+
    `## Ordered work\n\n${record.requiredLifecycle.map((s,i)=>`${i+1}. ${md(s)}`).join('\n')}\n\n`+
    `## Task changes\n\n${task.steps.map((s,i)=>`${i+1}. ${md(s)}`).join('\n')}\n\n`+
    `## Tests and completion\n\n${[...task.tests,...task.done].map(t=>`- [ ] ${md(t)}`).join('\n')}\n\n`+
    `## Rollback\n\n${md(task.rollback)}\n\nNo source files have been changed by this handoff.\n`);
  return {file,ready:blockers.length===0,blockers};
}
