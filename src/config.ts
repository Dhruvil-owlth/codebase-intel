import fs from 'node:fs/promises';
import path from 'node:path';
import { ConfigSchema, type Config } from './schema.js';
import { atomicWrite, noSymlinkAncestors, inside } from './safety.js';

export const defaultConfig=():Config=>ConfigSchema.parse({});
export async function loadConfig(file?:string,overrides:Record<string,unknown>={}):Promise<Config> {
  let input:Record<string,unknown>={};
  if(file) input=JSON.parse(await fs.readFile(file,'utf8'));
  else { try {input=JSON.parse(await fs.readFile(path.resolve('codebase-intel.json'),'utf8'));} catch(e) {if((e as NodeJS.ErrnoException).code!=='ENOENT') throw e;} }
  const c=ConfigSchema.parse({...input,...Object.fromEntries(Object.entries(overrides).filter(([,v])=>v!==undefined))});
  c.target=await fs.realpath(path.resolve(c.target));
  if(!(await fs.stat(c.target)).isDirectory()) throw new Error('Target must be a directory');
  c.output=path.resolve(c.output); await noSymlinkAncestors(c.output);
  if(c.output===c.target || inside(c.output,c.target)) throw new Error('Output must not equal or contain the target repository');
  // A dedicated report root may live in the target, but must never be a source directory.
  try {
    const entries=await fs.readdir(c.output);
    if(entries.length && !entries.includes('.codebase-intel-output')) throw new Error('Output directory is not an owned Codebase Intel output root; choose a new directory');
  } catch(e) {if((e as NodeJS.ErrnoException).code!=='ENOENT') throw e;}
  return c;
}
export async function initConfig(directory:string):Promise<string> {
  await noSymlinkAncestors(directory); const file=path.join(directory,'codebase-intel.json');
  try {await fs.access(file); throw new Error('Configuration already exists; refusing to overwrite');}
  catch(e) {if((e as NodeJS.ErrnoException).code!=='ENOENT') throw e;}
  await atomicWrite(directory,'codebase-intel.json',JSON.stringify(defaultConfig(),null,2)+'\n'); return file;
}
