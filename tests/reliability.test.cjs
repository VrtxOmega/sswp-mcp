const {test,after}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),cp=require('node:child_process');
const base=fs.mkdtempSync(path.join(os.tmpdir(),'omega-regression-'));process.env.VERITAS_SHARED_DIR=path.join(base,'shared');fs.mkdirSync(process.env.VERITAS_SHARED_DIR);process.env.SSWP_DB=path.join(base,'registry.sqlite');
const {runCommand,gitIntegrityGate,reproducibleBuildGate,runGates}=require('../dist/gates-test.cjs');
const {canonical,sha,appendLedger,verifyLedger,consumeApproval}=require('../dist/integrity-test.cjs');
const {sourceIdentity}=require('../dist/source-test.cjs');
const {witness,verifyAttestation,dependencyInventory}=require('../dist/witness-test.cjs');
const {RegistryManager}=require('../dist/registry-test.cjs'),Database=require('better-sqlite3');
const fixture=name=>{const p=path.join(base,name);fs.mkdirSync(p);return p;};
const repo=fixture('source');fs.writeFileSync(path.join(repo,'source.txt'),'retained source');
const canonicalRepo=fs.realpathSync(repo).replaceAll('\\','/');
const policy={witness_roots:[canonicalRepo],projects:{}};fs.writeFileSync(path.join(process.env.VERITAS_SHARED_DIR,'operator-policy.json'),JSON.stringify(policy));
const key=crypto.randomBytes(32);fs.writeFileSync(path.join(process.env.VERITAS_SHARED_DIR,'approval.key'),key);
function receipt(task='task-a'){
 const payload={version:1,tool:'sswp_witness',args_sha256:sha(canonical({repoPath:canonicalRepo})),source_sha256:sourceIdentity(repo),task_id:task,policy_sha256:sha(JSON.stringify(policy)),expires:Math.floor(Date.now()/1000)+120,nonce:crypto.randomBytes(16).toString('hex')};
 return {payload,mac:crypto.createHmac('sha256',key).update(canonical(payload)).digest('hex')};
}
test('Git failure is ERROR; absent commands never become PASS',async()=>{
 assert.equal((await gitIntegrityGate(repo)).status,'ERROR');
 const gates=await runGates(repo,{},{});assert.equal(gates.find(g=>g.gate==='TEST_PASS').status,'INCONCLUSIVE');
});
test('Timeout terminates the subprocess tree',async()=>{
 const pid=path.join(base,'child.pid');
 const code="const cp=require('child_process'),fs=require('fs');const p=cp.spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});fs.writeFileSync(process.argv[1],String(p.pid));setInterval(()=>{},1000)";
 const r=await runCommand(process.execPath,['-e',code,pid],repo,1000);assert.equal(r.error,'TIMEOUT');
 const child=Number(fs.readFileSync(pid,'utf8'));assert.throws(()=>process.kill(child,0));
});
test('Independent builds match deterministic output and reject varying or absent output',async()=>{
 const profile={argv:[process.execPath,'-e',"require('fs').writeFileSync('artifact.txt','stable')"],outputs:['artifact.txt']};
 assert.equal((await reproducibleBuildGate(repo,profile)).status,'PASS');
 assert.equal((await reproducibleBuildGate(repo,{...profile,argv:[process.execPath,'-e',"require('fs').writeFileSync('artifact.txt',process.cwd())"]})).status,'FAIL');
 fs.writeFileSync(path.join(repo,'artifact.txt'),'stale');
 assert.equal((await reproducibleBuildGate(repo,{...profile,argv:[process.execPath,'-e','0']})).status,'ERROR');
 fs.unlinkSync(path.join(repo,'artifact.txt'));
});
test('Approval binds policy, task, source and exact arguments, and rejects replay',()=>{
 let a=receipt();assert.throws(()=>consumeApproval('sswp_witness',{repoPath:canonicalRepo},a,'wrong-task'));
 consumeApproval('sswp_witness',{repoPath:canonicalRepo},a,'task-a');assert.throws(()=>consumeApproval('sswp_witness',{repoPath:canonicalRepo},a,'task-a'));
 a=receipt();fs.writeFileSync(path.join(repo,'source.txt'),'changed');assert.throws(()=>consumeApproval('sswp_witness',{repoPath:canonicalRepo},a,'task-a'),/Source changed/);
 a=receipt();a.mac='00'.repeat(32);assert.throws(()=>consumeApproval('sswp_witness',{repoPath:canonicalRepo},a,'task-a'),/MAC/);
 a=receipt();fs.writeFileSync(path.join(process.env.VERITAS_SHARED_DIR,'operator-policy.json'),JSON.stringify({...policy,revision:2}));assert.throws(()=>consumeApproval('sswp_witness',{repoPath:canonicalRepo},a,'task-a'),/policy/);fs.writeFileSync(path.join(process.env.VERITAS_SHARED_DIR,'operator-policy.json'),JSON.stringify(policy));
});
test('Python receipts and source digests verify in Node',()=>{
 const root=path.resolve(__dirname,'../..'),python=path.join(root,'.venv/Scripts/python.exe');
 const code="import sys,json;sys.path.insert(0,sys.argv[1]);import omega_runtime as r;print(json.dumps(r.approval('sswp_witness',{'repoPath':sys.argv[2]},'cross-language')))";
 const r=cp.spawnSync(python,['-X','utf8','-c',code,path.join(root,'omega-brain'),canonicalRepo],{env:process.env,encoding:'utf8',windowsHide:true});assert.equal(r.status,0,r.stderr);
 consumeApproval('sswp_witness',{repoPath:canonicalRepo},JSON.parse(r.stdout),'cross-language');
});
test('Nested attestation changes invalidate the hash; legacy is unverified',async()=>{
 const att=await witness(repo,{},'hash-test'),p=path.join(base,'att.json');fs.writeFileSync(p,canonical(att));assert.equal(verifyAttestation(p),true);
 att.target.name='tampered nested value';fs.writeFileSync(p,canonical(att));assert.equal(verifyAttestation(p),false);
 fs.writeFileSync(p,JSON.stringify({signature:'old'}));assert.equal(verifyAttestation(p),false);
});
test('Ledger covers event type, nested payload, timestamp; detects corruption',()=>{
 const db=new Database(path.join(base,'ledger.sqlite'));appendLedger(db,'TEST',{nested:{value:1}},'a');assert.equal(verifyLedger(db).valid,true);
 db.prepare("UPDATE ledger_v2 SET event_json=replace(event_json,'TEST','OTHER') WHERE id=2").run();assert.equal(verifyLedger(db).valid,false);db.close();
});
test('Attestation, gates, ledger and delivery job commit together; latest per node',async()=>{
 const reg=new RegistryManager({dbPath:path.join(base,'atomic.sqlite')}),n=reg.upsertNode({name:'fixture',repo_path:canonicalRepo});
 const att=await witness(repo,{},'atomic-task');reg.saveAttestation(n.node_id,att,path.join(repo,'.sswp.json'),canonical(att));
 assert.equal(reg.getHealthBoard().length,1);assert.equal(reg.getHealthBoard()[0].overall_status,'ERROR');
 assert.equal(reg.db.prepare('SELECT COUNT(*) n FROM event_outbox').get().n,1);reg.flushEvents();reg.flushEvents();
 const bus=new Database(path.join(process.env.VERITAS_SHARED_DIR,'coordination.sqlite'));assert.equal(bus.prepare("SELECT COUNT(*) n FROM events WHERE event_type='SSWP_ATTESTATION'").get().n,1);bus.close();
 const before=reg.verifyLedger().rows;reg.db.exec("CREATE TRIGGER fail_gate BEFORE INSERT ON gates_history BEGIN SELECT RAISE(ABORT,'injected failure'); END");
 const second=await witness(repo,{},'atomic-task');assert.throws(()=>reg.saveAttestation(n.node_id,second,path.join(repo,'.sswp.json'),canonical(second)),/injected/);
 assert.equal(reg.verifyLedger().rows,before);assert.equal(reg.db.prepare('SELECT COUNT(*) n FROM attestations').get().n,1);reg.close();
});
test('pnpm inventory reports transitive packages without claiming installed verification',()=>{
 const packages=dependencyInventory(path.resolve(__dirname,'..'));assert(packages.entries.length>50);assert.match(packages.scope,/not independently verified/);
});
after(()=>{const safe=fs.realpathSync(base);assert(safe.startsWith(fs.realpathSync(os.tmpdir())+path.sep));fs.rmSync(safe,{recursive:true,force:true});});
