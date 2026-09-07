import {spawn} from 'node:child_process';
import {existsSync,realpathSync,mkdtempSync,rmSync,mkdirSync,lstatSync,readdirSync,readFileSync} from 'node:fs';
import {join,resolve,isAbsolute,relative,sep} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {copySources,sourceIdentity} from './source-state.js';
import type {GateResult,BuildEnvironment} from './types.js';
export async function runCommand(command:string,args:string[],cwd:string,timeout=60000,env:Record<string,string>={}):Promise<{status:number|null,stdout:string,stderr:string,error?:string}> {
  return new Promise(resolve=>{
    const child=spawn(command,args,{cwd,shell:false,windowsHide:true,detached:process.platform!=='win32',env:{...process.env,...env}});
    let stdout='',stderr='',settled=false,timedOut=false;
    const finish=(value:any)=>{if(!settled){settled=true;clearTimeout(timer);resolve(value);}};
    const timer=setTimeout(()=>{
      timedOut=true;
      if(process.platform==='win32'&&child.pid){const killer=spawn('taskkill',['/PID',String(child.pid),'/T','/F'],{windowsHide:true});killer.on('error',()=>child.kill());}
      else if(child.pid){try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}}
    },Math.max(50,Math.min(timeout,300000)));
    child.stdout?.on('data',d=>{stdout=(stdout+d).slice(-65536);});child.stderr?.on('data',d=>{stderr=(stderr+d).slice(-65536);});
    child.on('error',e=>finish({status:null,stdout,stderr,error:e.message}));child.on('close',status=>finish({status,stdout,stderr,...(timedOut?{error:'TIMEOUT'}:{})}));
  });
}
const result=(gate:string,status:GateResult['status'],evidence:string,durationMs=0):GateResult=>({gate,status,evidence,durationMs});
export async function gitIntegrityGate(root:string):Promise<GateResult> {
  const start=Date.now();const r=await runCommand('git',['status','--porcelain=v1','--untracked-files=all'],root,10000);
  if(r.error||r.status!==0)return result('GIT_INTEGRITY','ERROR',r.error||r.stderr||`git exit ${r.status}`,Date.now()-start);
  return result('GIT_INTEGRITY',r.stdout.trim()?'FAIL':'PASS',r.stdout.trim()?'Working tree has changes':'Git command succeeded; working tree clean',Date.now()-start);
}
export function lockfileGate(root:string):GateResult {
  if(!existsSync(join(root,'package.json'))){
    const locks=['uv.lock','poetry.lock','Pipfile.lock','Cargo.lock','go.sum'].filter(f=>existsSync(join(root,f)));
    return result('LOCKFILE_PRESENT',locks.length?'PASS':'NOT_APPLICABLE',locks.length?`${locks.join(', ')} present; content consistency not established`:'No supported lockfile ecosystem detected');
  }
  const locks=['package-lock.json','pnpm-lock.yaml','yarn.lock'].filter(f=>existsSync(join(root,f)));
  return result('LOCKFILE_PRESENT',locks.length===1?'PASS':locks.length?'INCONCLUSIVE':'FAIL',locks.length===1?`${locks[0]} present; consistency not established`:locks.length?'Multiple lockfiles; package manager selection required':'No lockfile');
}
export async function runGates(root:string,_env:BuildEnvironment,policy:any={}):Promise<GateResult[]> {
  const output=[await gitIntegrityGate(root),lockfileGate(root)];
  const profile=policy.projects?.[realpathSync(root).replaceAll('\\','/')]||{};
  for(const [gate,key] of [['BUILD_SUCCESS','build'],['TEST_PASS','test'],['LINT','lint']]){
    const command=profile[key];
    if(!command){output.push(result(gate,'INCONCLUSIVE','No explicit operator command configured'));continue;}
    if(!Array.isArray(command.argv)||!command.argv.length||command.argv.some((a:any)=>typeof a!=='string')){output.push(result(gate,'ERROR','Invalid operator command'));continue;}
    const start=Date.now();const r=await runCommand(command.argv[0],command.argv.slice(1),root,command.timeoutMs||60000);
    output.push(result(gate,r.error?'ERROR':r.status===0?'PASS':'FAIL',r.error||`exit=${r.status}; ${(r.stdout+'\n'+r.stderr).slice(-8000)}`,Date.now()-start));
  }
  output.push(await reproducibleBuildGate(root,profile.reproducible));
  return output;
}

function outputManifest(root:string,outputs:string[]) {
  const manifest:Record<string,string>={};
  const walk=(p:string)=>{const stat=lstatSync(p);if(stat.isSymbolicLink())throw Error('Output symlinks are not supported');if(stat.isDirectory()){for(const name of readdirSync(p).sort())walk(join(p,name));}else if(stat.isFile())manifest[relative(root,p).replaceAll('\\','/')]=createHash('sha256').update(readFileSync(p)).digest('hex');};
  for(const output of outputs){const target=resolve(root,output);if(isAbsolute(output)||!target.startsWith(resolve(root)+sep))throw Error('Output must be inside build directory');walk(target);}
  return Object.fromEntries(Object.entries(manifest).sort(([a],[b])=>a.localeCompare(b)));
}
export async function reproducibleBuildGate(root:string,profile:any):Promise<GateResult> {
  if(!profile)return result('REPRODUCIBLE_BUILD','INCONCLUSIVE','No independent-build profile configured');
  if(!Array.isArray(profile.outputs)||!profile.outputs.length||!Array.isArray(profile.argv)||!profile.argv.length)return result('REPRODUCIBLE_BUILD','ERROR','Explicit argv and output paths are required');
  const start=Date.now(),base=mkdtempSync(join(tmpdir(),'sswp-repeat-')),manifests=[];
  try {
    const source=sourceIdentity(root);
    for(let i=0;i<2;i++){
      const dest=join(base,String(i));mkdirSync(dest);copySources(root,dest);
      // Remove declared build outputs from the copied input so a no-op command
      // cannot pass by comparing two copies of pre-existing artifacts.
      for(const out of profile.outputs){const target=resolve(dest,out);if(typeof out!=='string'||isAbsolute(out)||!target.startsWith(resolve(dest)+sep))throw Error('Output escapes isolated build');if(existsSync(target))rmSync(target,{recursive:true,force:true});}
      const commands=[...(profile.setup||[]),{argv:profile.argv,timeoutMs:profile.timeoutMs}];
      for(const command of commands){if(!Array.isArray(command.argv)||!command.argv.length||command.argv.some((x:any)=>typeof x!=='string'))throw Error('Invalid independent-build command');const run=await runCommand(command.argv[0],command.argv.slice(1),dest,command.timeoutMs||60000,{TZ:'UTC',SOURCE_DATE_EPOCH:'0',...(profile.env||{})});if(run.error||run.status!==0)return result('REPRODUCIBLE_BUILD',run.error?'ERROR':'FAIL',`Independent build ${i+1}: ${run.error||run.stderr||run.stdout||run.status}`,Date.now()-start);}
      const manifest=outputManifest(dest,profile.outputs);if(!Object.keys(manifest).length)throw Error('No output files produced');manifests.push(manifest);
    }
    if(sourceIdentity(root)!==source)return result('REPRODUCIBLE_BUILD','ERROR','Source changed while independent builds ran',Date.now()-start);
    const match=JSON.stringify(manifests[0])===JSON.stringify(manifests[1]);
    return result('REPRODUCIBLE_BUILD',match?'PASS':'FAIL',JSON.stringify({source_sha256:source,matching:match,manifests,scope:'Two separate source copies on this host with explicit commands; not a hermetic environment or cross-host proof'}),Date.now()-start);
  }catch(e){return result('REPRODUCIBLE_BUILD','ERROR',String(e),Date.now()-start);}
  finally{const safe=realpathSync(base);if(safe.startsWith(realpathSync(tmpdir())+sep)&&safe.includes('sswp-repeat-'))rmSync(safe,{recursive:true,force:true});}
}
