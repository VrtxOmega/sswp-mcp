'use strict';
const {test,after}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),cp=require('node:child_process'),crypto=require('node:crypto');
const base=fs.mkdtempSync(path.join(os.tmpdir(),'sswp-source-contract-'));
process.env.VERITAS_SHARED_DIR=path.join(base,'shared');fs.mkdirSync(process.env.VERITAS_SHARED_DIR);
const {sourceFiles,sourceIdentity,copySources}=require('../dist/source-test.cjs');
const {consumeApproval,sha,canonical}=require('../dist/integrity-test.cjs');
const {witness}=require('../dist/witness-test.cjs');
const {verifyBuildReceipt}=require('../scripts/verify-build-receipt.cjs');
const root=path.join(base,'project');fs.mkdirSync(root);
function git(args){const r=cp.spawnSync('git',['-C',root,...args],{encoding:'utf8',windowsHide:true});assert.equal(r.status,0,r.stderr);}
git(['init']);git(['config','user.name','Regression fixture']);git(['config','user.email','fixture@example.invalid']);
fs.mkdirSync(path.join(root,'data'));fs.writeFileSync(path.join(root,'data','input.txt'),'original');
fs.writeFileSync(path.join(root,'.gitignore'),'dist/\nbuild/\n');git(['add','.']);git(['commit','-m','fixture']);
const canonicalRoot=fs.realpathSync(root).replaceAll('\\','/');

test('Tracked data, nonignored new inputs and tracked ignored files are covered',()=>{
  const before=sourceIdentity(root);
  fs.mkdirSync(path.join(root,'dist'));fs.writeFileSync(path.join(root,'dist','artifact'),'generated');
  assert.equal(sourceIdentity(root),before);
  fs.writeFileSync(path.join(root,'data','input.txt'),'changed');assert.notEqual(sourceIdentity(root),before);
  const second=sourceIdentity(root);fs.writeFileSync(path.join(root,'new-input.txt'),'new');assert.notEqual(sourceIdentity(root),second);
  git(['add','-f','dist/artifact']);assert(sourceFiles(root).includes('dist/artifact'));
  git(['rm','--cached','dist/artifact']);
  const destination=path.join(base,'copy');fs.mkdirSync(destination);copySources(root,destination);
  assert.equal(fs.readFileSync(path.join(destination,'data/input.txt'),'utf8'),'changed');
  assert(!fs.existsSync(path.join(destination,'dist/artifact')));
});

test('Python and Node hash the same tracked and nonignored source inputs',()=>{
  const suite=path.resolve(__dirname,'../..');
  const python=process.env.OMEGA_PYTHON||path.join(suite,process.platform==='win32'?'.venv/Scripts/python.exe':'.venv/bin/python');
  const code="import sys;sys.path.insert(0,sys.argv[1]);import omega_runtime as r;print(r.source_identity(sys.argv[2]))";
  const r=cp.spawnSync(python,['-X','utf8','-c',code,path.join(suite,'omega-brain'),canonicalRoot],{encoding:'utf8',env:process.env,windowsHide:true});
  assert.equal(r.status,0,r.stderr);assert.equal(r.stdout.trim(),sourceIdentity(root));
});

test('A normal build writing ignored outputs does not fail SOURCE_BYTES',async()=>{
  const policy={projects:{[canonicalRoot]:{build:{argv:[process.execPath,'-e',"require('fs').mkdirSync('build',{recursive:true});require('fs').writeFileSync('build/output','ok')"],timeoutMs:10000}}}};
  const att=await witness(root,policy,'source-contract');
  assert(!att.gates.some(g=>g.gate==='SOURCE_BYTES'&&g.status==='FAIL'));
  assert(att.gates.some(g=>g.gate==='BUILD_SUCCESS'&&g.status==='PASS'));
});

test('An unavailable unrelated root cannot block an approved existing project',()=>{
  const policy={witness_roots:[path.join(base,'missing'),canonicalRoot],projects:{}};
  const raw=JSON.stringify(policy),key=crypto.randomBytes(32);
  fs.writeFileSync(path.join(process.env.VERITAS_SHARED_DIR,'operator-policy.json'),raw);
  fs.writeFileSync(path.join(process.env.VERITAS_SHARED_DIR,'approval.key'),key);
  const args={repoPath:canonicalRoot};
  const payload={version:1,tool:'sswp_witness',args_sha256:sha(canonical(args)),source_sha256:sourceIdentity(root),task_id:'approved',policy_sha256:sha(raw),expires:Math.floor(Date.now()/1000)+120,nonce:crypto.randomBytes(16).toString('hex')};
  const receipt={payload,mac:crypto.createHmac('sha256',key).update(canonical(payload)).digest('hex')};
  assert.deepEqual(consumeApproval('sswp_witness',args,receipt,'approved'),policy);
});

test('The complete build receipt verifies and rejects source or artifact hash changes',()=>{
  const project=path.resolve(__dirname,'..');
  assert.equal(verifyBuildReceipt(project).verified,true);
  const original=JSON.parse(fs.readFileSync(path.join(project,'dist/build-receipt.json'),'utf8'));
  const source=structuredClone(original);source.sourceHashes['src/core/witness.ts']='0'.repeat(64);
  assert.throws(()=>verifyBuildReceipt(project,source),/mismatch/);
  const artifact=structuredClone(original);artifact.artifacts['sswp-cli.cjs']='0'.repeat(64);
  assert.throws(()=>verifyBuildReceipt(project,artifact),/mismatch/);
  const incomplete=structuredClone(original);delete incomplete.sourceHashes['build.mjs'];
  assert.throws(()=>verifyBuildReceipt(project,incomplete),/Missing source/);
});
after(()=>fs.rmSync(base,{recursive:true,force:true}));
