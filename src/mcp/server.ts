import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {CallToolRequestSchema,ListToolsRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {RegistryManager} from '../registry/manager.js';
import {witness,verifyAttestation} from '../core/witness.js';
import {consumeApproval,canonical,sha} from '../core/integrity.js';
import {gitIntegrityGate,lockfileGate} from '../core/gate-runner.js';
import {readFileSync,writeFileSync,renameSync,realpathSync,existsSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import Ajv from 'ajv';
const REG=new RegistryManager({autoInit:true});
const input=(properties:any,required:string[]=[])=>({type:'object',properties,required,additionalProperties:false});
const str={type:'string',minLength:1},limit={type:'integer',minimum:1,maximum:100,default:20};
const action={repoPath:str,task_id:str,approval:{type:'object'}};
export const definitions=[
 {name:'sswp_witness',description:'Run explicitly configured checks within an operator-approved project. Requires a task-bound, one-use receipt from omega_authorize_action. Missing evidence is INCONCLUSIVE; a successful build does not prove reproducibility.',inputSchema:input(action,['repoPath','task_id','approval'])},
 {name:'sswp_bulk_witness',description:'Run individually approved witness actions. Each item requires its own one-use approval receipt.',inputSchema:input({items:{type:'array',minItems:1,maxItems:20,items:input(action,['repoPath','task_id','approval'])}},['items'])},
 {name:'sswp_verify',description:'Check all nested fields of a v2 attestation against its content hash. Legacy formats are unverified. A matching hash establishes internal consistency, not authorship or truth.',inputSchema:input({filePath:str},['filePath'])},
 {name:'sswp_check_repo',description:'Read-only Git execution and lockfile-presence checks; no project build scripts run.',inputSchema:input({repoPath:str},['repoPath'])},
 {name:'sswp_registry_health',description:'Latest check per node with historical timestamps, current path availability, capture delivery status and v2 ledger integrity.',inputSchema:input({limit})},
 {name:'sswp_ledger',description:'Versioned local ledger and verification status. Historical records are preserved separately and are not certified by this chain.',inputSchema:input({limit})},
 {name:'sswp_node_search',description:'Find registry nodes by literal name, description or path.',inputSchema:input({query:str,limit},['query'])},
 {name:'sswp_analyze_deps',description:'Local metadata checks. Flags unpinned versions and missing integrity declarations; does not establish maliciousness, CVE coverage or package safety.',inputSchema:input({packages:{type:'array',maxItems:1000,items:{type:'object',properties:{name:str,version:str,integrity:{type:'string'}},required:['name','version'],additionalProperties:false}}},['packages'])},
 {name:'sswp_export_to_omega',description:'Retry durable delivery of committed attestations to Brain. Delivery is idempotent; Brain consumption status is separate.',inputSchema:input({})}
];
const ajv=new Ajv({strict:false});const validators=new Map(definitions.map(t=>[t.name,ajv.compile<any>(t.inputSchema)]));
function materializePending() {
  const rows=REG.db.prepare("SELECT a.*,n.repo_path FROM attestations a JOIN nodes n ON n.node_id=a.node_id WHERE json_extract(a.metadata,'$.materialization')='pending' ORDER BY a.run_at").all() as any[];
  for(const row of rows){
    try {
      const latest=REG.getLatestAttestation(row.node_id);
      if(latest?.attestation_id!==row.attestation_id){REG.db.prepare('UPDATE attestations SET metadata=json_set(metadata,\'$.materialization\',\'superseded\') WHERE attestation_id=?').run(row.attestation_id);continue;}
      if(!existsSync(row.repo_path)||resolve(row.sswp_json_path)!==resolve(row.repo_path,'.sswp.json'))throw Error('Recorded destination unavailable or invalid');
      const temporary=row.sswp_json_path+'.'+randomUUID()+'.tmp';writeFileSync(temporary,row.raw_json);renameSync(temporary,row.sswp_json_path);
      REG.db.prepare("UPDATE attestations SET metadata=json_set(metadata,'$.materialization','complete') WHERE attestation_id=?").run(row.attestation_id);
    }catch(e){console.error('SSWP materialization pending:',String(e));}
  }
}
async function witnessAction(args:any) {
  const target={repoPath:realpathSync(args.repoPath).replaceAll('\\','/')};
  // Compare exactly what the approval covers; changing path representation also
  // requires a new receipt instead of silently rewriting signed arguments.
  if(args.repoPath!==target.repoPath)throw Error('Use the canonical absolute repoPath for approval and execution');
  const policy=consumeApproval('sswp_witness',target,args.approval,args.task_id);
  const att=await witness(target.repoPath,policy,args.task_id);
  const node=REG.upsertNode({name:att.target.name,repo_path:target.repoPath});
  const destination=join(target.repoPath,'.sswp.json'),raw=canonical(att);
  // The database is authoritative. A crash before materialization leaves a
  // recoverable raw_json plus a durable export job.
  REG.saveAttestation(node.node_id,att,destination,raw);
  materializePending();
  try{REG.flushEvents();}catch(e){return {attestation:att,delivery:'pending',delivery_error:String(e)};}
  return {attestation:att,delivery:'queued_for_brain',materialization:REG.db.prepare('SELECT metadata FROM attestations WHERE attestation_id=?').get(att.id!)};
}
export async function dispatch(name:string,args:any) {
  const validate=validators.get(name);if(!validate)throw Error('Unknown tool');if(!validate(args))throw Error(ajv.errorsText(validate.errors));
  if(name==='sswp_witness')return witnessAction(args);
  if(name==='sswp_bulk_witness'){const result=[];for(const item of args.items){try{result.push(await witnessAction(item));}catch(e){result.push({repoPath:item.repoPath,error:String(e)});}}return result;}
  if(name==='sswp_verify') {const att=JSON.parse(readFileSync(args.filePath,'utf8'));return {verified:verifyAttestation(args.filePath),status:att.signatureAlgorithm==='sha256-canonical-json-v2'?(verifyAttestation(args.filePath)?'HASH_VALID':'HASH_MISMATCH'):'LEGACY_UNVERIFIED',meaning:'content consistency only; no assertion of origin or correctness'};}
  if(name==='sswp_check_repo')return {git:await gitIntegrityGate(args.repoPath),lockfile:lockfileGate(args.repoPath)};
  if(name==='sswp_registry_health')return {nodes:REG.getHealthBoard().slice(0,args.limit||20),integrity:REG.verifyLedger(),delivery_pending:REG.db.prepare('SELECT COUNT(*) n FROM event_outbox WHERE delivered=0').get(),materialization_pending:REG.db.prepare("SELECT COUNT(*) n FROM attestations WHERE json_extract(metadata,'$.materialization')='pending'").get()};
  if(name==='sswp_ledger')return {integrity:REG.verifyLedger(),entries:REG.getLedger(args.limit||20)};
  if(name==='sswp_node_search'){const q=args.query.toLowerCase();return REG.listNodes().filter(n=>(n.name+' '+n.repo_path+' '+n.description).toLowerCase().includes(q)).slice(0,args.limit||20);}
  if(name==='sswp_analyze_deps')return {assessment:'metadata signals only; not a security verdict',packages:args.packages.map((p:any)=>({...p,unpinned:/[\^~*<>]|latest/.test(p.version),integrityDeclaration:p.integrity?'PRESENT_UNVERIFIED':'MISSING',vulnerabilityStatus:'NOT_CHECKED'}))};
  if(name==='sswp_export_to_omega'){materializePending();REG.flushEvents();return {queued:true,pending:REG.db.prepare('SELECT COUNT(*) n FROM event_outbox WHERE delivered=0').get()};}
}
export async function start() {
  const server=new Server({name:'sswp-mcp',version:'2.1.0'},{capabilities:{tools:{}}});
  server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:definitions.map(t=>({...t,annotations:{readOnlyHint:!['sswp_witness','sswp_bulk_witness','sswp_export_to_omega'].includes(t.name),idempotentHint:!['sswp_witness','sswp_bulk_witness'].includes(t.name),openWorldHint:false}}))}));
  server.setRequestHandler(CallToolRequestSchema,async r=>{try{return {content:[{type:'text',text:JSON.stringify(await dispatch(r.params.name,r.params.arguments||{}))}]};}catch(e){return {isError:true,content:[{type:'text',text:String(e)}]};}});
  await server.connect(new StdioServerTransport());
  const timer=setInterval(()=>{try{materializePending();REG.flushEvents();}catch(e){console.error('SSWP delivery pending:',String(e));}},5000);timer.unref();
}
if(require.main===module)start().catch(e=>{console.error(e);process.exitCode=1;});
