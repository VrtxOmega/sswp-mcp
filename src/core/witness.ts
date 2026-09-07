import {existsSync,readFileSync,realpathSync} from 'node:fs';
import {join,basename} from 'node:path';
import {randomUUID} from 'node:crypto';
import {canonical,sha} from './integrity.js';
import {runGates,runCommand} from './gate-runner.js';
import {sourceIdentity} from './source-state.js';
import {parse as parseYaml} from 'yaml';
import type {SswpAttestation,DependencyEntry,BuildEnvironment} from './types.js';

export function dependencyInventory(root:string):{entries:DependencyEntry[],scope:string} {
  const lock=join(root,'package-lock.json');
  if(!existsSync(lock)){
    const pnpm=join(root,'pnpm-lock.yaml');
    if(existsSync(pnpm)){
      const data=parseYaml(readFileSync(pnpm,'utf8')),entries:DependencyEntry[]=[];
      for(const [key,value] of Object.entries(data.packages||{})){const p=value as any,at=key.lastIndexOf('@');entries.push({name:at>0?key.slice(0,at):key,version:at>0?key.slice(at+1):'unknown',resolved:p.resolution?.tarball||key,integrity:p.resolution?.integrity||null,suspicious:!p.resolution?.integrity,riskScore:0});}
      return {entries,scope:'pnpm lock package entries including transitive packages; declared integrity, not independently verified installed bytes'};
    }
    return {entries:[],scope:'No supported npm/pnpm lockfile; dependency coverage unverified'};
  }
  const data=JSON.parse(readFileSync(lock,'utf8'));const entries:DependencyEntry[]=[];
  for(const [location,value] of Object.entries(data.packages||{})){
    if(!location)continue;const p=value as any;
    entries.push({name:p.name||location.split('node_modules/').pop()||location,version:p.version||'unknown',resolved:p.resolved||location,integrity:p.integrity||null,suspicious:!p.integrity&&!p.link,riskScore:0});
  }
  return {entries,scope:'npm lockfile package entries; integrity fields are declared metadata, not independently verified installed bytes'};
}
export async function witness(root:string,policy:any={},taskId='unscoped'):Promise<SswpAttestation> {
  root=realpathSync(root);const inventory=dependencyInventory(root);
  const sourceBefore=sourceIdentity(root);
  const env:BuildEnvironment={cwd:root,nodeVersion:process.version,os:process.platform,arch:process.arch,ci:!!process.env.CI,buildCommand:'operator-profile',buildOutput:''};
  const before=await runCommand('git',['rev-parse','HEAD'],root,10000);
  const gates=await runGates(root,env,policy);
  const after=await runCommand('git',['rev-parse','HEAD'],root,10000);
  const sourceAfter=sourceIdentity(root);
  if(sourceBefore!==sourceAfter)gates.push({gate:'SOURCE_BYTES',status:'FAIL',evidence:'Source bytes changed while checks ran',durationMs:0});
  if(before.status!==0||after.status!==0||before.stdout!==after.stdout)gates.push({gate:'SOURCE_REVISION','status':'ERROR',evidence:'Cannot establish one stable Git revision across the checks',durationMs:0});
  const att:any={id:randomUUID(),version:'2.1.0',signatureAlgorithm:'sha256-canonical-json-v2',timestamp:new Date().toISOString(),taskId,target:{name:basename(root),repo:root,commitHash:before.status===0?before.stdout.trim():'unknown',branch:'recorded-by-commit'},environment:{nodeVersion:env.nodeVersion,os:env.os,arch:env.arch,ci:env.ci},dependencies:inventory.entries,dependencyCoverage:inventory.scope,gates,adversarial:{totalPackages:inventory.entries.length,suspiciousPackages:inventory.entries.filter(d=>d.suspicious).length,probes:[],overallRisk:0,assessment:'NOT_PERFORMED; zero is not a safety probability'},seal:{chainHash:'assigned-by-persistent-registry',sequence:0}};
  att.source={before:sourceBefore,after:sourceAfter,scope:'Source tree; installed dependencies and runtime are host-trusted'};
  att.adversarial.probes=inventory.entries.map(d=>({package:d.name,probe:'LOCK_METADATA',result:!d.integrity?'INCONCLUSIVE':'PASS',detail:!d.integrity?'No integrity declaration':'Integrity declaration present; installed bytes and vulnerabilities not checked'}));
  att.adversarial.assessment='Local metadata probes only; no adversarial execution or vulnerability feed consulted';
  att.signature=sha(canonical(att));return att;
}
export function verifyAttestation(filePath:string):boolean {
  const att=JSON.parse(readFileSync(filePath,'utf8'));
  if(att.signatureAlgorithm!=='sha256-canonical-json-v2')return false;
  const {signature,...payload}=att;return typeof signature==='string'&&sha(canonical(payload))===signature;
}
export const formatAttestation=(att:SswpAttestation)=>JSON.stringify(att,null,2);
