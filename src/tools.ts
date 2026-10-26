import { spawn } from 'node:child_process';
import { type Config, type ToolResult } from './schema.js';
import { redact } from './safety.js';
import { PYTHON_AST } from './python.js';

export const toolRegistry = {
  git: {description:'Fixed Git object/index metadata only; status and working-tree diff are excluded because they can invoke configured filters', commands:['version','HEAD','branch','object-format','index-entries']},
  python: {description:'Isolated Python AST parser; source is stdin and is never executed', commands:['ast']},
  typescript: {description:'Bundled TypeScript compiler API; syntax parsing only; no plugins/config execution', commands:['parse']},
};
export async function runTool(name:'git'|'python',args:string[],cwd:string,input:string|undefined,config:Config):Promise<ToolResult> {
  const start=Date.now(); const command=name==='git'?'git':'python3';
  const gitCommands=[['--version'],['-c','core.fsmonitor=false','rev-parse','--verify','HEAD'],
    ['-c','core.fsmonitor=false','rev-parse','--show-object-format'],['-c','core.fsmonitor=false','symbolic-ref','--short','HEAD'],
    ['-c','core.fsmonitor=false','ls-files','--stage','-z']];
  const permitted=name==='git' ? gitCommands.some(command=>JSON.stringify(args)===JSON.stringify(command)) :
    args.length===4&&args[0]==='-I'&&args[1]==='-S'&&args[2]==='-c'&&args[3]===PYTHON_AST;
  if(!permitted) throw new Error('Tool command is not allowlisted');
  if(!config.tools[name]) return {name,command:[command,...(name==='python'?['<isolated-ast-parser>']:args)],status:'disabled',exitCode:null,durationMs:0,stdout:'',stderr:''};
  return await new Promise(resolve=>{
    let stdout='',stderr='',finished=false,overflow=false;
    const child=spawn(command,args,{cwd,shell:false,env:{PATH:process.env.PATH,LANG:'C.UTF-8',
      GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0',
      PYTHONIOENCODING:'utf-8'},stdio:['pipe','pipe','pipe']});
    const end=(status:ToolResult['status'],code:number|null)=>{if(finished)return;finished=true;clearTimeout(timer);
      resolve({name,command:[command,...(name==='python'?['<isolated-ast-parser>']:args)],status,exitCode:code,
        durationMs:Date.now()-start,stdout:redact(stdout),stderr:redact(stderr)});};
    const timer=setTimeout(()=>{stderr+=' Tool timeout';child.kill('SIGKILL');},config.budgets.toolTimeoutMs);
    child.stdout.on('data',d=>{if(stdout.length+d.length>4000000){overflow=true;child.kill('SIGKILL');}else stdout+=d;});
    child.stderr.on('data',d=>{if(stderr.length<16000)stderr+=d.toString().slice(0,16000-stderr.length);});
    child.on('error',e=>{stderr+=e.message;end('unavailable',null);});
    child.on('close',code=>end(code===0&&!overflow?'ok':'failed',code));
    child.stdin.on('error',()=>{}); child.stdin.end(input);
  });
}
