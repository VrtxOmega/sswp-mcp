import {createHash} from 'node:crypto';
import {readdirSync,lstatSync,readFileSync,copyFileSync,mkdirSync} from 'node:fs';
import {join,relative,dirname} from 'node:path';
export const excluded=new Set(['.git','node_modules','.venv','data','__pycache__','.sswp.json']);
export function sourceFiles(root:string):string[] {
  const result:string[]=[];
  const walk=(folder:string)=>{for(const name of readdirSync(folder)){if(excluded.has(name))continue;const p=join(folder,name),s=lstatSync(p);if(s.isSymbolicLink())throw Error('Source symlinks require an explicit packaged source snapshot');if(s.isDirectory())walk(p);else if(s.isFile())result.push(relative(root,p).replaceAll('\\','/'));}};
  walk(root);return result.sort();
}
export function sourceIdentity(root:string) {
  const hash=createHash('sha256');for(const f of sourceFiles(root))hash.update(f+'\0'+createHash('sha256').update(readFileSync(join(root,f))).digest('hex')+'\n');return hash.digest('hex');
}
export function copySources(root:string,dest:string) {for(const f of sourceFiles(root)){const target=join(dest,f);mkdirSync(dirname(target),{recursive:true});copyFileSync(join(root,f),target);}}
