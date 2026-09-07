import {createHash} from 'node:crypto';
import {readdirSync,lstatSync,readFileSync,copyFileSync,mkdirSync,realpathSync} from 'node:fs';
import {join,relative,dirname,isAbsolute} from 'node:path';
import {spawnSync} from 'node:child_process';

// These exclusions apply only to untracked/fallback files. Tracked inputs win.
export const excluded=new Set(['.git','node_modules','.venv','__pycache__','.sswp.json']);

function gitFiles(root:string,mode:'--cached'|'--others'):string[]|null {
  const args=['-C',root,'ls-files',mode,'-z'];
  if(mode==='--others')args.push('--exclude-standard');
  args.push('--');
  const result=spawnSync('git',args,{env:{...process.env,LC_ALL:'C'},timeout:10000,maxBuffer:16*1024*1024,windowsHide:true});
  if(result.error){
    if((result.error as NodeJS.ErrnoException).code==='ENOENT')return null;
    throw Error('Cannot enumerate source inputs: '+result.error.message);
  }
  if(result.status!==0){
    const error=result.stderr?.toString('utf8')||'Git source enumeration failed';
    if(error.toLowerCase().includes('not a git repository'))return null;
    throw Error('Cannot enumerate source inputs: '+error);
  }
  return new TextDecoder('utf-8',{fatal:true}).decode(result.stdout).split('\0').filter(Boolean);
}

export function sourceFiles(root:string):string[] {
  root=realpathSync(root);
  const tracked=gitFiles(root,'--cached');
  const candidates=new Set<string>();
  if(tracked!==null){
    const other=gitFiles(root,'--others');
    if(other===null)throw Error('Git source enumeration became unavailable');
    for(const name of tracked)candidates.add(name);
    for(const name of other)if(!name.split('/').some(part=>excluded.has(part)))candidates.add(name);
  }else{
    const walk=(folder:string)=>{
      for(const name of readdirSync(folder)){
        if(excluded.has(name))continue;
        const path=join(folder,name),stat=lstatSync(path);
        if(stat.isSymbolicLink())throw Error('Source symlinks require an explicit packaged source snapshot');
        if(stat.isDirectory())walk(path);
        else if(stat.isFile())candidates.add(relative(root,path).replaceAll('\\','/'));
      }
    };
    walk(root);
  }
  const result:string[]=[];
  // UTF-8 byte ordering agrees with Python's Unicode code-point ordering.
  for(const name of [...candidates].sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b)))){
    const parts=name.split('/');
    if(isAbsolute(name)||parts.includes('..'))throw Error('Source path escapes the approved root');
    let path=root,missing=false;
    for(const part of parts){
      path=join(path,part);
      try{
        if(lstatSync(path).isSymbolicLink())throw Error('Source symlinks require an explicit packaged source snapshot');
      }catch(error){
        if(['ENOENT','ENOTDIR'].includes((error as NodeJS.ErrnoException).code||'')){missing=true;break;}
        throw error;
      }
    }
    if(missing)continue; // A deleted tracked input changes the resulting digest.
    const stat=lstatSync(path);
    if(stat.isFile())result.push(name);
    else if(stat.isDirectory())throw Error('Tracked directories/submodules require an explicit packaged source snapshot');
    else throw Error('Unsupported source file type');
  }
  return result;
}

export function sourceIdentity(root:string):string {
  const hash=createHash('sha256');
  for(const name of sourceFiles(root))hash.update(name+'\0'+createHash('sha256').update(readFileSync(join(root,name))).digest('hex')+'\n');
  return hash.digest('hex');
}

export function copySources(root:string,dest:string):void {
  for(const name of sourceFiles(root)){
    const target=join(dest,name);
    mkdirSync(dirname(target),{recursive:true});
    copyFileSync(join(root,name),target);
  }
}
