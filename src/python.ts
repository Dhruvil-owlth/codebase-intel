// The interpreter parses untrusted source as data. No imports from the target and no execution.
export const PYTHON_AST = String.raw`
import ast, json, sys
text = sys.stdin.read()
out = {'symbols': [], 'imports': [], 'exports': [], 'references': [], 'issues': [], 'errors': []}
try:
    tree = ast.parse(text)
    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.names=[]
            self.loops=0
        def issue(self, rule, node):
            out['issues'].append({'rule':rule,'line':node.lineno,'end':getattr(node,'end_lineno',node.lineno),'symbol':'.'.join(self.names) or '<module>'})
        def definition(self,node,kind):
            name='.'.join(self.names+[node.name])
            out['symbols'].append({'name':name,'kind':kind,'lineStart':node.lineno,'lineEnd':node.end_lineno,'exported':not node.name.startswith('_')})
            self.names.append(node.name)
            self.generic_visit(node)
            self.names.pop()
        def visit_FunctionDef(self,n): self.definition(n,'function')
        def visit_AsyncFunctionDef(self,n): self.definition(n,'async-function')
        def visit_ClassDef(self,n): self.definition(n,'class')
        def visit_Import(self,n):
            for a in n.names: out['imports'].append({'specifier':a.name,'line':n.lineno})
        def visit_ImportFrom(self,n):
            out['imports'].append({'specifier':'.'*n.level+(n.module or ''),'line':n.lineno})
        def visit_Name(self,n):
            if isinstance(n.ctx,ast.Load) and len(out['references'])<2000: out['references'].append({'name':n.id,'line':n.lineno})
        def visit_If(self,n):
            if isinstance(n.test,ast.Constant) and isinstance(n.test.value,(bool,type(None))): self.issue('constant-condition',n.test)
            self.generic_visit(n)
        def visit_ExceptHandler(self,n):
            if n.type is None: self.issue('python-bare-except',n)
            self.generic_visit(n)
        def visit_Call(self,n):
            if isinstance(n.func,ast.Name) and n.func.id in ('eval','exec') and n.args and not isinstance(n.args[0],ast.Constant): self.issue('dynamic-eval',n)
            if isinstance(n.func,ast.Attribute) and n.func.attr=='loads' and isinstance(n.func.value,ast.Name) and n.func.value.id=='pickle': self.issue('python-pickle',n)
            self.generic_visit(n)
        def visit_Compare(self,n):
            if self.loops and any(isinstance(x,(ast.In,ast.NotIn)) for x in n.ops): self.issue('loop-membership',n)
            self.generic_visit(n)
        def loop(self,n):
            self.loops+=1
            self.generic_visit(n)
            self.loops-=1
        def visit_For(self,n): self.loop(n)
        def visit_AsyncFor(self,n): self.loop(n)
        def visit_While(self,n): self.loop(n)
    Visitor().visit(tree)
except (SyntaxError,ValueError,RecursionError) as e:
    out['errors'].append('Python AST parse failed at line '+str(getattr(e,'lineno',0))+': '+type(e).__name__)
print(json.dumps(out))
`;
