import {build,version} from 'esbuild';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
const settings={bundle:true,platform:'node',format:'cjs',target:'node22',packages:'external',loader:{'.sql':'text'},logLevel:'warning',metafile:true};
const sourceHashes={},artifacts={};
const hash=p=>createHash('sha256').update(readFileSync(p)).digest('hex');
for(const file of ['build.mjs','package.json','tsconfig.json'])sourceHashes[file]=hash(file);
mkdirSync('dist',{recursive:true});
for(const [source,file] of [['src/mcp/server.ts','sswp.cjs'],['src/cli.ts','sswp-cli.cjs'],['src/core/witness.ts','witness-test.cjs'],['src/core/gate-runner.ts','gates-test.cjs'],['src/core/integrity.ts','integrity-test.cjs'],['src/registry/manager.ts','registry-test.cjs'],['src/core/source-state.ts','source-test.cjs']]) {
 const first=await build({...settings,entryPoints:[source],write:false});
 const second=await build({...settings,entryPoints:[source],write:false});
 if(!Buffer.from(first.outputFiles[0].contents).equals(Buffer.from(second.outputFiles[0].contents)))throw Error('Bundle differs across identical builds');
 writeFileSync('dist/'+file,first.outputFiles[0].contents);
 artifacts[file]=hash('dist/'+file);
 for(const file of Object.keys(first.metafile.inputs))sourceHashes[file]=hash(file);
}
writeFileSync('dist/build-receipt.json',JSON.stringify({version:2,builder:{esbuild:version,node:process.version},bundleSha256:hash('dist/sswp.cjs'),lockSha256:hash('pnpm-lock.yaml'),sourceHashes,artifacts,identicalBuilds:true,scope:'Each bundle built twice from identical inputs; independent-directory reproducibility is a separate gate'},null,2)+'\n');
