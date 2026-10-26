import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export const hash = (s:string|Buffer):string => createHash('sha256').update(s).digest('hex');
export const posix = (p:string):string => p.split(path.sep).join('/');
export function redact(s:string):string {
  return s.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, '[REDACTED PRIVATE KEY]')
    .replace(/\b(?:sk-[a-zA-Z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{15,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{20,})\b/g,'[REDACTED TOKEN]')
    .replace(/((?:password|passwd|secret|api[_-]?key|access[_-]?token|authorization|private[_-]?key)\s*["']?\s*[:=]\s*)(["'`])[^\n]*?\2/gi,'$1"[REDACTED]"')
    .replace(/((?:password|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;}]+/gi,'$1[REDACTED]')
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/g,'$1[REDACTED]@')
    .replace(/([?&](?:token|key|secret|password|auth)=)[^\s&#"']+/gi,'$1[REDACTED]');
}
export const errorText = (e:unknown):string => redact(e instanceof Error ? e.message : String(e));
export function inside(root:string,candidate:string):boolean {
  const rel = path.relative(root,candidate);
  return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel));
}
export function relativePath(root:string,relative:string):string {
  if (relative.includes('\0') || path.isAbsolute(relative) || relative.includes('\\')) throw new Error('Unsafe relative path');
  const result=path.resolve(root,relative);
  if (!inside(root,result)) throw new Error('Path escapes allowed root');
  return result;
}
export async function noSymlinkAncestors(candidate:string):Promise<void> {
  let current=path.resolve(candidate);
  while (true) {
    try { if ((await fs.lstat(current)).isSymbolicLink()) throw new Error(`Symlink path refused: ${current}`); }
    catch(e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
    const parent=path.dirname(current); if(parent===current) break; current=parent;
  }
}
export async function safeRead(root:string,relative:string,maxBytes=1048576):Promise<string> {
  const absolute=relativePath(root,relative); await noSymlinkAncestors(absolute);
  const handle=await fs.open(absolute,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try { const stat=await handle.stat(); if(!stat.isFile() || stat.size>maxBytes) throw new Error('File exceeds read budget or is not regular');
    const data=await handle.readFile(); if(data.length>maxBytes) throw new Error('File grew beyond read budget'); return data.toString('utf8');
  } finally { await handle.close(); }
}
export async function atomicWrite(root:string,relative:string,content:string):Promise<void> {
  const destination=relativePath(root,relative); await noSymlinkAncestors(destination);
  await fs.mkdir(path.dirname(destination),{recursive:true});
  const temporary=path.join(path.dirname(destination),`.intel-${randomUUID()}.tmp`);
  try { await fs.writeFile(temporary,content,{flag:'wx',mode:0o600}); await fs.rename(temporary,destination); }
  finally { await fs.rm(temporary,{force:true}).catch(()=>{}); }
}
export async function writeJson(root:string,relative:string,value:unknown):Promise<void> {
  await atomicWrite(root,relative,JSON.stringify(value,null,2)+'\n');
}
export const md = (s:string):string => redact(s).replace(/[\r\n]+/g,' ').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/([\\`*_[\]{}()|#!])/g,'\\$1');
export const linkPath=(p:string):string => p.split('/').map(part=>part==='..'?'..':encodeURIComponent(part).replace(/[!'()*]/g,c=>`%${c.charCodeAt(0).toString(16).toUpperCase()}`)).join('/');
