import ts from 'typescript';
import path from 'node:path';
import { type Config, type FileRecord, type Finding, type ToolResult } from './schema.js';
import { makeFinding, type Candidate } from './findings.js';
import { PYTHON_AST } from './python.js';
import { runTool } from './tools.js';
import { errorText } from './safety.js';

export interface ParseContext {file:FileRecord; source:string;config:Config;tools:ToolResult[]}
export interface ExpertAdapter {
  id:string;languages:string[];supportedVersions:string; recommendedAnalyzers:string[];
  pitfalls:string[];conventions:string[];performanceStrategies:string[];securityChecks:string[];
  testingStrategies:string[];antiPatterns:string[];officialReferences:string[];
  compatible(language:string):boolean;
  parse(context:ParseContext):Promise<void>;
}
const rules:Record<string,Omit<Candidate,'rule'|'lineStart'>> = {
  'constant-condition':{title:'Literal condition fixes a control-flow branch',category:'correctness',severity:'low',confidence:0.98,
    description:'The condition is a literal true, false or null value. One branch is statically unreachable; intentional feature stubs are possible.',
    recommendation:'Check intended behavior and replace the literal with the required predicate, or document intentional disabled code.',tests:['Exercise both intended control-flow branches and the disabled-feature case.']},
  'array-off-by-one':{title:'Inclusive upper bound can access one past an array',category:'correctness',severity:'high',confidence:0.93,
    description:'A loop condition uses <= array.length and the loop body indexes the same array with that loop variable. The inclusive bound permits an undefined element.',
    recommendation:'Use a strict upper bound or iterate the values directly after checking loop-variable updates and intentional sentinel handling.',tests:['Test an empty array, a single element and the last valid index.']},
  'nan-equality':{title:'Equality with NaN does not detect NaN',category:'correctness',severity:'high',confidence:0.95,
    description:'The equality or inequality operand is the identifier NaN. Built-in NaN is unequal to every value including itself; local shadowing requires caller review.',
    recommendation:'After checking shadowed bindings and coercion requirements, use Number.isNaN for numeric NaN checks.',tests:['Test NaN, a finite number, undefined and a numeric string.']},
  'dynamic-eval':{title:'Dynamic code evaluation requires a trust-boundary review',category:'security',severity:'high',confidence:0.8,status:'HYPOTHESIS',
    description:'A dynamic value reaches eval, exec or a Function constructor. Static inspection does not establish whether the value is attacker controlled.',
    recommendation:'Trace input provenance; replace dynamic evaluation with a constrained parser or fixed dispatch if untrusted input can reach it.',tests:['Pass adversarial input through each reachable entry point and verify it cannot execute code.']},
  'dynamic-html':{title:'Dynamic HTML assignment needs contextual sanitization',category:'security',severity:'high',confidence:0.75,status:'HYPOTHESIS',
    description:'A non-literal value is assigned to innerHTML or outerHTML. Input trust and existing sanitization have not been established.',
    recommendation:'Trace the value and use textContent for plain text or a maintained sanitizer appropriate to the rendering context.',tests:['Test HTML and script payloads through the actual input boundary.']},
  'loop-membership':{title:'Repeated membership lookup inside a loop may scale poorly',category:'performance',confidence:0.75,status:'HYPOTHESIS',
    description:'A membership search occurs in a loop. For linear containers this may repeat a linear scan; actual types and input sizes must be measured.',
    recommendation:'Measure representative inputs; if membership scans dominate, construct and reuse a Set while preserving equality and ordering semantics.',
    tests:['Compare results for duplicates, empty collections and boundary values.'],benchmarks:['Measure time and memory over representative collection sizes before and after changing the lookup.']},
  'empty-catch':{title:'Empty catch discards failure information',category:'correctness',severity:'medium',confidence:0.9,
    description:'A catch block contains no statements. Exceptions leave no explicit recovery or diagnostic action in this handler.',
    recommendation:'Confirm whether failures may safely be ignored; otherwise preserve context and implement a defined recovery or propagation path.',tests:['Inject a failure and verify the documented recovery, propagation and diagnostic behavior.']},
  'python-bare-except':{title:'Bare except catches process-control exceptions',category:'correctness',severity:'medium',confidence:0.95,
    description:'A bare except handler also catches BaseException subclasses such as KeyboardInterrupt and SystemExit.',
    recommendation:'Catch the expected Exception subclasses and let process-control exceptions propagate unless suppression is explicitly required.',tests:['Test a normal failure and verify KeyboardInterrupt and SystemExit propagation.']},
  'python-pickle':{title:'Pickle deserialization requires trusted input',category:'security',severity:'high',confidence:0.8,status:'HYPOTHESIS',
    description:'A call to pickle.loads is present. Deserializing attacker-controlled pickle data permits code execution; the input trust boundary is not known.',
    recommendation:'Trace input provenance and use a non-executable data format for untrusted payloads.',tests:['Verify untrusted payloads are rejected before deserialization.']},
};
function add(ctx:ParseContext,rule:string,lineStart:number,lineEnd:number,symbol:string):void {
  const spec=rules[rule]; if(spec)ctx.file.findings.push(makeFinding(ctx.file,ctx.source,{...spec,rule,lineStart,lineEnd,symbol}));
}
function tsParse(ctx:ParseContext):void {
  const {file,source}=ctx;
  const scriptKind=file.path.endsWith('.tsx')?ts.ScriptKind.TSX:file.path.endsWith('.jsx')?ts.ScriptKind.JSX:
    file.language==='TypeScript'?ts.ScriptKind.TS:ts.ScriptKind.JS;
  const ast=ts.createSourceFile(file.path,source,ts.ScriptTarget.Latest,true,scriptKind);
  const diagnostics=(ast as unknown as {parseDiagnostics:ts.Diagnostic[]}).parseDiagnostics;
  file.parseErrors=diagnostics.map(d=>`Syntax error ${d.code} at line ${ast.getLineAndCharacterOfPosition(d.start??0).line+1}`);
  const line=(node:ts.Node):number=>ast.getLineAndCharacterOfPosition(node.getStart(ast)).line+1;
  const end=(node:ts.Node):number=>ast.getLineAndCharacterOfPosition(node.end).line+1;
  const nodeText=(node:ts.Node):string=>node.getText(ast);
  const isFunction=(n:ts.Node):boolean=>ts.isFunctionDeclaration(n)||ts.isMethodDeclaration(n)||ts.isArrowFunction(n)||ts.isFunctionExpression(n)||ts.isConstructorDeclaration(n);
  const nameOf=(node:ts.Node):string=> {
    const named=node as ts.NamedDeclaration;
    if(named.name)return named.name.getText(ast);
    if(ts.isVariableDeclaration(node.parent))return node.parent.name.getText(ast);
    return `<anonymous@${line(node)}>`;
  };
  const visit=(node:ts.Node,ancestors:string[],loops:ts.Node[]):void=>{
    let names=ancestors;
    if(isFunction(node)||ts.isClassDeclaration(node)||ts.isInterfaceDeclaration(node)||ts.isTypeAliasDeclaration(node)||ts.isEnumDeclaration(node)) {
      names=[...ancestors,nameOf(node)]; const exported=!!(ts.getCombinedModifierFlags(node as ts.Declaration)&ts.ModifierFlags.Export);
      file.symbols.push({name:names.join('.'),kind:ts.SyntaxKind[node.kind]??'symbol',lineStart:line(node),lineEnd:end(node),exported});
      if(exported)file.exports.push(names.join('.'));
    }
    if(ts.isImportDeclaration(node)&&ts.isStringLiteral(node.moduleSpecifier))file.imports.push({specifier:node.moduleSpecifier.text,line:line(node)});
    if(ts.isExportDeclaration(node)&&node.moduleSpecifier&&ts.isStringLiteral(node.moduleSpecifier))file.imports.push({specifier:node.moduleSpecifier.text,line:line(node)});
    if(ts.isCallExpression(node)&&node.arguments[0]&&ts.isStringLiteral(node.arguments[0])&&
      (node.expression.kind===ts.SyntaxKind.ImportKeyword||(ts.isIdentifier(node.expression)&&node.expression.text==='require')))
      file.imports.push({specifier:node.arguments[0].text,line:line(node)});
    if(ts.isIdentifier(node)&&file.references.length<2000)file.references.push({name:node.text,line:line(node)});
    const symbol=names.join('.')||'<module>';
    const emit=(rule:string,n:ts.Node)=>add(ctx,rule,line(n),end(n),symbol);
    if(ts.isIfStatement(node)&&[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(node.expression.kind))emit('constant-condition',node.expression);
    if(ts.isCatchClause(node)&&node.block.statements.length===0)emit('empty-catch',node);
    if(ts.isBinaryExpression(node)) {
      const op=node.operatorToken.kind;
      if([ts.SyntaxKind.EqualsEqualsToken,ts.SyntaxKind.EqualsEqualsEqualsToken,ts.SyntaxKind.ExclamationEqualsToken,ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(op)&&
        [node.left,node.right].some(n=>ts.isIdentifier(n)&&n.text==='NaN'))emit('nan-equality',node);
      if(op===ts.SyntaxKind.EqualsToken&&ts.isPropertyAccessExpression(node.left)&&['innerHTML','outerHTML'].includes(node.left.name.text)&&!ts.isStringLiteralLike(node.right))emit('dynamic-html',node);
    }
    if((ts.isCallExpression(node)||ts.isNewExpression(node))&&ts.isIdentifier(node.expression)&&['eval','Function'].includes(node.expression.text)&&
      node.arguments?.some(a=>!ts.isStringLiteralLike(a)))emit('dynamic-eval',node);
    if(ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)&&['includes','indexOf'].includes(node.expression.name.text)&&loops.length)emit('loop-membership',node);
    if(ts.isForStatement(node)&&node.condition&&ts.isBinaryExpression(node.condition)&&
      node.condition.operatorToken.kind===ts.SyntaxKind.LessThanEqualsToken&&ts.isIdentifier(node.condition.left)&&
      ts.isPropertyAccessExpression(node.condition.right)&&node.condition.right.name.text==='length') {
      const variable=node.condition.left.text; const array=nodeText(node.condition.right.expression); let accesses=false;
      const check=(n:ts.Node):void=>{if(ts.isElementAccessExpression(n)&&nodeText(n.expression)===array&&n.argumentExpression&&nodeText(n.argumentExpression)===variable)accesses=true;ts.forEachChild(n,check);};
      check(node.statement); if(accesses)emit('array-off-by-one',node.condition);
    }
    const nextLoops=isFunction(node)?[]:ts.isForStatement(node)||ts.isForOfStatement(node)||ts.isForInStatement(node)||ts.isWhileStatement(node)||ts.isDoStatement(node)?[...loops,node]:loops;
    ts.forEachChild(node,child=>visit(child,names,nextLoops));
  };
  visit(ast,[],[]);
}
const base={supportedVersions:'Syntax support from bundled TypeScript compiler; runtime behavior is not type-checked',recommendedAnalyzers:['TypeScript compiler API'],
  pitfalls:['Syntax alone does not prove runtime types or reachability'],conventions:['Resolve local imports using indexed paths'],
  performanceStrategies:['Identify repeated membership scans; require measurements'],securityChecks:['Dynamic evaluation and dynamic HTML sinks'],
  testingStrategies:['Boundary tests and failing regressions before changes'],antiPatterns:['Inclusive array bounds and swallowed failures'],
  officialReferences:['https://www.typescriptlang.org/docs/','https://nodejs.org/api/']};
export const javascriptAdapter:ExpertAdapter={...base,id:'javascript-typescript',languages:['JavaScript','TypeScript'],
  compatible:l=>['JavaScript','TypeScript'].includes(l),async parse(ctx){ctx.file.parser=`typescript-${ts.version}`;tsParse(ctx);}};
export const pythonAdapter:ExpertAdapter={...base,id:'python',languages:['Python'],supportedVersions:'AST syntax supported by the locally discovered Python 3 interpreter',
  recommendedAnalyzers:['Python ast (isolated interpreter)'],officialReferences:['https://docs.python.org/3/library/ast.html'],
  securityChecks:['Dynamic eval/exec, pickle.loads'],antiPatterns:['Bare except and constant conditions'],compatible:l=>l==='Python',
  async parse(ctx){
    const result=await runTool('python',['-I','-S','-c',PYTHON_AST],ctx.config.target,ctx.source,ctx.config);
    // AST output contains identifiers but no source; do not retain thousands of parser JSON lines in logs.
    ctx.tools.push({...result,stdout:result.status==='ok'?'Python AST result captured in index.':result.stdout});
    if(result.status!=='ok'){ctx.file.parser='unavailable';ctx.file.parseErrors.push(`Python parser ${result.status}`);return;}
    const parsed=JSON.parse(result.stdout);ctx.file.parser='python-ast';
    ctx.file.symbols=parsed.symbols;ctx.file.imports=parsed.imports;ctx.file.exports=parsed.exports;
    ctx.file.references=parsed.references;ctx.file.parseErrors=parsed.errors;
    for(const issue of parsed.issues)add(ctx,issue.rule,issue.line,issue.end,issue.symbol);
  }};
export const genericAdapter:ExpertAdapter={...base,id:'generic',languages:['*'],supportedVersions:'Inventory only; no semantic version support',
  recommendedAnalyzers:[],securityChecks:[],performanceStrategies:[],antiPatterns:[],officialReferences:[],compatible:()=>true,
  async parse(ctx){ctx.file.parser='inventory-only';}};

export class AdapterRegistry {
  private adapters:ExpertAdapter[]=[];
  register(adapter:ExpertAdapter):this {if(this.adapters.some(a=>a.id===adapter.id))throw new Error(`Duplicate adapter: ${adapter.id}`);this.adapters.push(adapter);return this;}
  forLanguage(language:string):ExpertAdapter {return this.adapters.find(a=>a.id!=='generic'&&a.compatible(language))??genericAdapter;}
  list():ExpertAdapter[]{return [...this.adapters,genericAdapter];}
}
export const defaultRegistry=():AdapterRegistry=>new AdapterRegistry().register(javascriptAdapter).register(pythonAdapter);
export async function parseFile(ctx:ParseContext,registry:AdapterRegistry):Promise<void> {
  if(ctx.config.depth==='inventory'){ctx.file.parser='inventory-only';return;}
  try {await registry.forLanguage(ctx.file.language).parse(ctx);}
  catch(e){ctx.file.parser='failed';ctx.file.parseErrors.push(errorText(e));}
  ctx.file.findings=ctx.file.findings.filter(f=>ctx.config.specialists.includes(f.category));
}
export function languageOf(p:string):string {
  const ext=path.extname(p).toLowerCase();
  return ({'.ts':'TypeScript','.tsx':'TypeScript','.mts':'TypeScript','.cts':'TypeScript','.js':'JavaScript','.jsx':'JavaScript','.mjs':'JavaScript','.cjs':'JavaScript',
    '.py':'Python','.java':'Java','.go':'Go','.rs':'Rust','.cs':'C#','.php':'PHP','.c':'C','.h':'C/C++','.cpp':'C++','.cc':'C++',
    '.rb':'Ruby','.swift':'Swift','.kt':'Kotlin','.scala':'Scala','.dart':'Dart','.vue':'Vue','.svelte':'Svelte','.html':'HTML','.css':'CSS','.scss':'SCSS',
    '.sql':'SQL','.sh':'Shell','.json':'JSON','.yaml':'YAML','.yml':'YAML','.toml':'TOML','.md':'Markdown','.xml':'XML','.tf':'Terraform',
  } as Record<string,string>)[ext]??'Unknown';
}
