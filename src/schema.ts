import { z } from 'zod';

export const VERSION = '0.1.0';
export const ENGINE_VERSION = '1';
export const categories = ['correctness', 'performance', 'security', 'testing', 'maintainability', 'architecture', 'dependencies', 'model-review'] as const;
export const FindingSchema = z.object({
  id: z.string().regex(/^F-[a-f0-9]{12}$/), rule: z.string().min(1), title: z.string().min(1),
  category: z.enum(categories), severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  priority: z.enum(['P0', 'P1', 'P2', 'P3']), score: z.number().finite(), confidence: z.number().min(0).max(1),
  status: z.enum(['VERIFIED', 'SUPPORTED', 'HYPOTHESIS', 'NOT_EVALUATED']),
  measurement: z.enum(['measured', 'statically-inferred', 'hypothetical', 'not-applicable']),
  module: z.string(), path: z.string().min(1), symbol: z.string(),
  lineStart: z.number().int().positive(), lineEnd: z.number().int().positive(),
  description: z.string().min(1), evidence: z.array(z.object({
    path: z.string(), lineStart: z.number().int().positive(), lineEnd: z.number().int().positive(),
    hash: z.string().regex(/^[a-f0-9]{64}$/), snippet: z.string(), kind: z.enum(['ast', 'manifest', 'graph', 'source', 'model']),
  })).min(1),
  rootCause: z.string(), currentBehavior: z.string(), expectedBehavior: z.string(), impact: z.string(),
  reproduction: z.array(z.string()), recommendation: z.string(), alternatives: z.array(z.string()),
  tradeoffs: z.array(z.string()), compatibility: z.string(), regressionRisks: z.array(z.string()),
  tests: z.array(z.string()).min(1), benchmarks: z.array(z.string()),
  effort: z.object({ estimate: z.string(), uncertainty: z.enum(['low', 'medium', 'high']) }),
  dependencies: z.array(z.string()), related: z.array(z.string()), phase: z.number().int().min(1).max(6),
  completionCriteria: z.array(z.string()).min(1), references: z.array(z.string()),
  origin: z.enum(['deterministic', 'model']),
});
export type Finding = z.infer<typeof FindingSchema>;

export const ConfigSchema = z.object({
  schemaVersion: z.literal(1).default(1), target: z.string().default('.'),
  output: z.string().default('docs/codebase-intelligence'),
  include: z.array(z.string()).default(['**/*']), exclude: z.array(z.string()).default([]),
  depth: z.enum(['inventory', 'standard', 'deep']).default('standard'),
  specialists: z.array(z.enum(categories)).default([...categories]),
  concurrency: z.number().int().min(1).max(16).default(4),
  budgets: z.object({ maxFiles: z.number().int().positive().default(30000), maxFileBytes: z.number().int().positive().default(1048576),
    maxTotalBytes: z.number().int().positive().default(150000000), maxRunSeconds: z.number().positive().default(600),
    contextTokens: z.number().int().min(512).default(12000), maxModelCalls: z.number().int().nonnegative().default(8),
    toolTimeoutMs: z.number().int().positive().max(60000).default(15000),
  }).default(() => ({maxFiles:30000,maxFileBytes:1048576,maxTotalBytes:150000000,maxRunSeconds:600,contextTokens:12000,maxModelCalls:8,toolTimeoutMs:15000})),
  tools: z.object({ git: z.boolean().default(true), python: z.boolean().default(true) }).default({git:true,python:true}),
  privacy: z.object({ sendSource: z.boolean().default(false), redact: z.literal(true).default(true) }).default({sendSource:false,redact:true}),
  network: z.object({ enabled: z.boolean().default(false), allowedOrigins: z.array(z.string().url()).default([]) }).default({enabled:false,allowedOrigins:[]}),
  model: z.object({ provider: z.enum(['none','openai-compatible','anthropic','gemini','ollama']).default('none'),
    name: z.string().default(''), baseUrl: z.string().default(''), apiKeyEnv: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).default('MODEL_API_KEY'),
    timeoutMs: z.number().int().positive().max(60000).default(30000), maxRetries: z.number().int().min(0).max(3).default(1),
  }).default({provider:'none',name:'',baseUrl:'',apiKeyEnv:'MODEL_API_KEY',timeoutMs:30000,maxRetries:1}),
  weights: z.object({ severity:z.number().nonnegative().default(5), confidence:z.number().nonnegative().default(2),
    security:z.number().nonnegative().default(2), effort:z.number().nonnegative().default(1), risk:z.number().nonnegative().default(1),
  }).default({severity:5,confidence:2,security:2,effort:1,risk:1}),
  retention: z.number().int().positive().default(20), verbosity: z.enum(['concise','detailed']).default('detailed'),
  resume: z.enum(['reuse-unchanged','restart']).default('reuse-unchanged'),
}).strict().superRefine((config,ctx)=>{
  if(config.model.baseUrl){
    try {const url=new URL(config.model.baseUrl);if(url.username||url.password||url.search||url.hash)ctx.addIssue({code:'custom',path:['model','baseUrl'],message:'Model baseUrl cannot contain credentials, query parameters, or fragments'});}
    catch{ctx.addIssue({code:'custom',path:['model','baseUrl'],message:'Model baseUrl must be a valid URL'});}
  }
  for(const [i,origin] of config.network.allowedOrigins.entries()){
    const url=new URL(origin);if(url.username||url.password||url.search||url.hash||url.pathname!=='/')ctx.addIssue({code:'custom',path:['network','allowedOrigins',i],message:'Allowed origins must be exact origins without credentials or paths'});
  }
});
export type Config = z.infer<typeof ConfigSchema>;
export type SymbolInfo = {name:string; kind:string; lineStart:number; lineEnd:number; exported:boolean};
export type ImportInfo = {specifier:string; line:number; resolved?:string};
export type FileRecord = {
  path:string; hash:string; bytes:number; lines:number; language:string; kind:'source'|'test'|'config'|'documentation'|'other';
  module:string; parser:string; parseErrors:string[]; symbols:SymbolInfo[]; imports:ImportInfo[];
  exports:string[]; references:{name:string; line:number}[]; configFor:string[]; testsFor:string[];
  cacheHit:boolean; findings:Finding[];
};
export type Technology = {name:string; version:string; versionKind:'declared'|'locked'|'detected'; path:string; line:number; adapter:string; references:string[]};
export type ToolResult = {name:string; command:string[]; status:'ok'|'failed'|'unavailable'|'disabled'; exitCode:number|null; durationMs:number; stdout:string; stderr:string};
export type Coverage = {
  included:string[]; excluded:{path:string;reason:string}[]; parsed:string[]; failed:{path:string;reason:string}[];
  analyzedModules:string[]; depth:string; tools:ToolResult[]; untestedPaths:string[]; unsupported:string[];
  unresolvedEvidence:string[]; limitations:string[]; reused:number; changed:string[]; invalidated:string[]; scopedOut:string[];
};
export type Index = {version:string; files:FileRecord[]; technologies:Technology[]; edges:{from:string;to:string;line:number}[];
  modules:{path:string;files:string[];entryPoints:string[]}[]; coverage:Coverage; git:{head?:string;branch?:string;dirty?:string[]}; fingerprint:string};
export type Task = {id:string;phase:number;title:string;findings:string[];dependencies:string[];files:string[];
  steps:string[];tests:string[];benchmarks:string[];rollback:string;done:string[];risk:string;status:'pending'|'approved'|'completed'};
export type Roadmap = {tasks:Task[]; rootCauses:{id:string;cause:string;findings:string[]}[];
  conflicts:{findings:string[];reason:string;resolution:string}[]; scoring:string;parallelGroups:string[][]};
export const stages = ['discovery','specialists','model-review','synthesis','documentation','verification'] as const;
export type Stage = typeof stages[number];
export type Run = {schemaVersion:1;id:string;version:string;engineVersion:string;createdAt:string;updatedAt:string;
  target:string;output:string;config:Config;scope?:string;changedOnly:boolean;previous?:string;status:'running'|'complete'|'partial'|'failed';
  stage:Stage;tasks:Record<Stage,{status:'pending'|'running'|'complete'|'failed';attempts:number;error?:string}>;
  errors:{stage:string;message:string}[];index?:Index;findings:Finding[];roadmap?:Roadmap;documents:string[];
  validation?:{valid:boolean;errors:string[];warnings:string[]};modelCalls:number;modelReviews:{module:string;summary:string}[];
  tools:ToolResult[];configHash:string;};
