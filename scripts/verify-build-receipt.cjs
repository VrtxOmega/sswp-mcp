'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const artifacts=['sswp.cjs','sswp-cli.cjs','witness-test.cjs','gates-test.cjs','integrity-test.cjs','registry-test.cjs','source-test.cjs'];
const requiredSources=['build.mjs','package.json','tsconfig.json','src/mcp/server.ts','src/cli.ts','src/core/witness.ts','src/core/gate-runner.ts','src/core/integrity.ts','src/registry/manager.ts','src/core/source-state.ts'];
function verifyBuildReceipt(root,receipt){
  root=fs.realpathSync(root);
  if(!receipt)receipt=JSON.parse(fs.readFileSync(path.join(root,'dist/build-receipt.json'),'utf8'));
  if(receipt.version!==2||receipt.identicalBuilds!==true)throw Error('Unsupported or incomplete build receipt');
  const hash=(name)=>{
    if(typeof name!=='string'||path.isAbsolute(name)||name.split(/[\\/]/).includes('..'))throw Error('Invalid receipt path');
    const file=fs.realpathSync(path.join(root,name));
    const relative=path.relative(root,file);
    if(relative.startsWith('..'+path.sep)||path.isAbsolute(relative))throw Error('Receipt path escapes the source tree');
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  };
  const compare=(name,expected)=>{
    if(typeof expected!=='string'||!/^[0-9a-f]{64}$/.test(expected)||hash(name)!==expected)throw Error('Build receipt mismatch: '+name);
  };
  for(const name of requiredSources)if(!Object.hasOwn(receipt.sourceHashes||{},name))throw Error('Missing source receipt: '+name);
  for(const [name,digest]of Object.entries(receipt.sourceHashes))compare(name,digest);
  for(const name of artifacts)if(!Object.hasOwn(receipt.artifacts||{},name))throw Error('Missing artifact receipt: '+name);
  for(const [name,digest]of Object.entries(receipt.artifacts))compare('dist/'+name,digest);
  compare('pnpm-lock.yaml',receipt.lockSha256);
  compare('dist/sswp.cjs',receipt.bundleSha256);
  return {verified:true,sourceFiles:Object.keys(receipt.sourceHashes).length,artifacts:Object.keys(receipt.artifacts).length,meaning:'Content consistency of recorded source and bundles; not an independent signature or security certification'};
}
module.exports={verifyBuildReceipt};
if(require.main===module){
  try{console.log(JSON.stringify(verifyBuildReceipt(path.resolve(__dirname,'..'))));}
  catch(error){console.error(error.message);process.exitCode=1;}
}
