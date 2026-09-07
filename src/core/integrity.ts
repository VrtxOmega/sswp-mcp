import {createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {readFileSync,realpathSync,mkdirSync} from 'node:fs';
import {resolve,join} from 'node:path';
import Database from 'better-sqlite3';
import {homedir} from 'node:os';
import {sourceIdentity} from './source-state.js';
export function canonical(v:any):string {
  if(v===null || typeof v!=='object') {const s=JSON.stringify(v);if(s===undefined || (typeof v==='number'&&!Number.isFinite(v)))throw Error('Non-JSON value');return s;}
  if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
  return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
}
export const sha=(s:string)=>createHash('sha256').update(s).digest('hex');
export function initLedger(db:Database.Database) {db.exec('CREATE TABLE IF NOT EXISTS ledger_v2(id INTEGER PRIMARY KEY,prev_hash TEXT NOT NULL,event_json TEXT NOT NULL,hash TEXT NOT NULL UNIQUE)');}
function row(db:Database.Database,type:string,payload:any,taskId:string) {
  const last=db.prepare('SELECT id,hash FROM ledger_v2 ORDER BY id DESC LIMIT 1').get() as any;
  const sequence=last?last.id+1:1,prev=last?.hash??'GENESIS_V2';
  const event=canonical({version:2,sequence,task_id:taskId,event_type:type,payload,timestamp:new Date().toISOString()});
  const hash=sha(prev+'\n'+event);db.prepare('INSERT INTO ledger_v2 VALUES(?,?,?,?)').run(sequence,prev,event,hash);return hash;
}
export function appendLedger(db:Database.Database,type:string,payload:any,taskId='system') {
  initLedger(db);return db.transaction(()=>{
    if(verifyLedger(db).invalid_rows.length)throw Error('Existing v2 ledger is invalid; append refused');
    if(!db.prepare('SELECT 1 FROM ledger_v2 LIMIT 1').get()) {
      const digest=createHash('sha256');let count=0;
      if(db.prepare("SELECT 1 FROM sqlite_master WHERE name='ledger'").get())for(const r of db.prepare('SELECT * FROM ledger ORDER BY id').iterate()){digest.update(canonical(r)+'\n');count++;}
      row(db,'LEGACY_BOUNDARY',{legacy_rows:count,legacy_logical_sha256:digest.digest('hex'),legacy_status:'preserved_unverified',format:'v2'},'system');
    }
    return row(db,type,payload,taskId);
  }).immediate();
}
export function verifyLedger(db:Database.Database) {
  initLedger(db);let prev='GENESIS_V2',count=0;const invalid:number[]=[];
  for(const r of db.prepare('SELECT * FROM ledger_v2 ORDER BY id').iterate() as any){count++;let structural=false;try{const e=JSON.parse(r.event_json);structural=e.version===2&&e.sequence===r.id&&canonical(e)===r.event_json;}catch{}if(!structural||r.id!==count||r.prev_hash!==prev||sha(r.prev_hash+'\n'+r.event_json)!==r.hash)invalid.push(r.id);prev=r.hash;}
  return {format:2,rows:count,valid:count>0&&invalid.length===0,invalid_rows:invalid,head:prev,legacy_status:'preserved_unverified',guarantee:'local tamper-evident chain; no independent external anchor'};
}
export const sharedPath=()=>process.env.VERITAS_SHARED_DIR||join(homedir(),'.veritas-shared');
export function consumeApproval(tool:string,args:any,receipt:any,taskId:string) {
  if(!taskId||!receipt?.payload||!receipt.mac)throw Error('A task-bound operator-policy approval receipt is required');
  const shared=sharedPath(),policyBytes=readFileSync(join(shared,'operator-policy.json')),policy=JSON.parse(policyBytes.toString());
  const real=realpathSync(args.repoPath).replaceAll('\\','/');
  const pathkey=(p:string)=>process.platform==='win32'?p.toLowerCase():p;
  const allowed=(policy.witness_roots||[]).map((p:string)=>pathkey(realpathSync(p).replaceAll('\\','/')));
  if(!allowed.includes(pathkey(real)))throw Error('Project is not registered in operator policy');
  const key=readFileSync(join(shared,'approval.key')),expected=createHmac('sha256',key).update(canonical(receipt.payload)).digest();
  const actual=Buffer.from(receipt.mac,'hex');if(actual.length!==expected.length||!timingSafeEqual(actual,expected))throw Error('Invalid approval MAC');
  const p=receipt.payload;
  if(p.version!==1||p.tool!==tool||p.task_id!==taskId||p.args_sha256!==sha(canonical(args))||p.policy_sha256!==sha(policyBytes.toString())||p.expires<Math.floor(Date.now()/1000)||p.expires>Math.floor(Date.now()/1000)+180)throw Error('Approval is stale or bound to different arguments/task/policy');
  if(p.source_sha256!==sourceIdentity(real))throw Error('Source changed since approval; request a fresh receipt');
  const db=new Database(join(shared,'coordination.sqlite'));db.pragma('busy_timeout=30000');
  try{db.exec('CREATE TABLE IF NOT EXISTS used_approvals(nonce TEXT PRIMARY KEY,used_at TEXT NOT NULL)');db.prepare('INSERT INTO used_approvals VALUES(?,?)').run(p.nonce,new Date().toISOString());}finally{db.close();}
  return policy;
}
export function deliverOutbox(db:Database.Database) {
  const shared=sharedPath();mkdirSync(shared,{recursive:true});const bus=new Database(join(shared,'coordination.sqlite'));bus.pragma('busy_timeout=30000');
  try {bus.exec('CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,event_type TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL)');
    // Replay also covers a bus DB restored from an older independent snapshot.
    const present=new Set((bus.prepare('SELECT id FROM events').all() as any[]).map(e=>e.id));
    for(const e of db.prepare('SELECT * FROM event_outbox ORDER BY created_at').all() as any[]){if(e.delivered&&present.has(e.id))continue;bus.prepare('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)').run(e.id,e.task_id,e.event_type,e.payload,e.created_at);db.prepare('UPDATE event_outbox SET delivered=1 WHERE id=?').run(e.id);}
  } finally{bus.close();}
}
