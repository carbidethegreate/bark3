import * as fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';

const root=fileURLToPath(new URL('../',import.meta.url));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=code=>{const error=new Error('Public CI input rejected ['+code+']');error.code=code;throw error;};
// Exact Source FROZEN-PUBLIC-INPUTS.json receipt, 9f5f026d...; no discovered paths.
const pins={
 "public/INTERFACE.json": {
  "bytes": 1937,
  "sha256": "647e86c6050c999475be9d5952030f069abfe1c6c16b9150cbe6b4fd6b7f38f0"
 },
 "public/fixtures/clean/assets/index.html": {
  "bytes": 94,
  "sha256": "7c72c38b3b2ea984a50c3ca0b5f907cb8191f1ee799589ade9af5605bbccdcc2"
 },
 "public/fixtures/clean/assets/styles.css": {
  "bytes": 61,
  "sha256": "4e8254d7de3294339fc36d5685366aa3c3a1b7262504c6c4ad9bf4e327ac8633"
 },
 "public/fixtures/clean/clean-receipt.json": {
  "bytes": 1469,
  "sha256": "f5854f0bdb6ac4c7c26f0228713be1978b35854b669b9462486d76f80461e830"
 },
 "public/fixtures/clean/descriptor.json": {
  "bytes": 1324,
  "sha256": "112a2bdf4efcaacff6079c8d887688252596d50e6e148b85eb7186df4a68d911"
 },
 "public/fixtures/clean/manifest.json": {
  "bytes": 306,
  "sha256": "912d7d0238799bdfd56d48817a3dc03060abec5e34786339316997ee26f5b8e0"
 },
 "public/fixtures/clean/unsafe-receipt.json": {
  "bytes": 767,
  "sha256": "ee7700542c51e0920167c097cdc99fce3c80e5b1ee29ce2de97091e951a7dc85"
 },
 "public/fixtures/trust.json": {
  "bytes": 1186,
  "sha256": "3a91091b5dd4ff001d07073e38949fda783d793c8a5a0071b6450b0a90b38a98"
 },
 "public/fixtures/unsafe/assets/index.html": {
  "bytes": 138,
  "sha256": "afdcef24265e2d6e9326543d6cf3aad54ae12c9ab9b0a8bad6c74aec31d8fe08"
 },
 "public/fixtures/unsafe/assets/styles.css": {
  "bytes": 61,
  "sha256": "4e8254d7de3294339fc36d5685366aa3c3a1b7262504c6c4ad9bf4e327ac8633"
 },
 "public/fixtures/unsafe/clean-receipt.json": {
  "bytes": 1469,
  "sha256": "f5854f0bdb6ac4c7c26f0228713be1978b35854b669b9462486d76f80461e830"
 },
 "public/fixtures/unsafe/descriptor.json": {
  "bytes": 1327,
  "sha256": "2380a84111b568aa9fc83d5866f926f13bb497163001d883cdf5916cec467fb0"
 },
 "public/fixtures/unsafe/manifest.json": {
  "bytes": 307,
  "sha256": "7c6f3f095a952abc263cfc383f5261a0249dfe7fc907f3c388ad8a6c1b6aff1d"
 },
 "public/fixtures/unsafe/unsafe-receipt.json": {
  "bytes": 767,
  "sha256": "ee7700542c51e0920167c097cdc99fce3c80e5b1ee29ce2de97091e951a7dc85"
 },
 "public/lib/release-manifest-contract.mjs": {
  "bytes": 10503,
  "sha256": "770e4379d241a0c3752a514ae1c5cefd4cca660065a288fd61d0ed9309b5777d"
 },
 "public/lib/reviewed-asset-gate.mjs": {
  "bytes": 16893,
  "sha256": "fd3f7fb3049d9d85449abda97feba30cac10aafe87dab39fb976541210ba4c56"
 },
 "public/lib/safety.mjs": {
  "bytes": 5458,
  "sha256": "96664d2912d412c200209165d2752f34d4a125fd64d55dd709b9b8e02913c983"
 }
};
function record(value,names){
 if(!value||typeof value!=='object'||Object.getPrototypeOf(value)!==Object.prototype)fail('INVALID_TRUST');
 const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
 if(keys.length!==names.length||keys.some(k=>typeof k!=='string'||!names.includes(k)||!descriptors[k].enumerable||!Object.hasOwn(descriptors[k],'value')))fail('INVALID_TRUST');
 return value;
}
const sameNode=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode;
const sameFile=(a,b)=>sameNode(a,b)&&a.size===b.size&&a.nlink===b.nlink&&a.mtimeNs===b.mtimeNs&&a.ctimeNs===b.ctimeNs;
const stat=file=>fs.lstatSync(file,{bigint:true});
function readRegular(file){
 const before=stat(file);if(before.isSymbolicLink()||!before.isFile())fail('NON_REGULAR_INPUT');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{if(!sameFile(fs.fstatSync(fd,{bigint:true}),before))fail('INPUT_CHANGED');const bytes=fs.readFileSync(fd);if(!sameFile(stat(file),before)||!sameFile(fs.fstatSync(fd,{bigint:true}),before))fail('INPUT_CHANGED');return {bytes,stat:before};}finally{fs.closeSync(fd);}
}
function readFixed(relative){
 if(relative!=='candidate.json'&&!Object.hasOwn(pins,relative))fail('NON_ALLOWLISTED_INPUT');
 const parts=relative.split('/');let parent=root;
 for(const part of parts.slice(0,-1)){parent=path.join(parent,part);const value=stat(parent);if(value.isSymbolicLink()||!value.isDirectory())fail('NON_REGULAR_INPUT');}
 const {bytes}=readRegular(path.join(root,relative)),pin=pins[relative];
 if(pin&&(bytes.length!==pin.bytes||hash(bytes)!==pin.sha256))fail('FROZEN_PUBLIC_PIN');return bytes;
}
function json(bytes,code='INVALID_TRUST'){
 const text=bytes.toString('utf8');if(!Buffer.from(text).equals(bytes))fail(code);
 try{return JSON.parse(text);}catch{fail(code);}
}
function select(){
 if(process.argv.length!==2)fail('INVALID_SELECTOR');
 const bytes=readFixed('candidate.json'),value=json(bytes,'INVALID_SELECTOR'),text=bytes.toString('utf8');
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!=='candidate,version'||value.version!==1||!['clean','unsafe'].includes(value.candidate)||(text.match(/"(?:\\[\s\S]|[^"\\])*"\s*:/g)??[]).length!==2)fail('INVALID_SELECTOR');
 return value.candidate;
}
function fixture(candidate){
 const prefix='public/fixtures/'+candidate+'/',descriptor=readFixed(prefix+'descriptor.json'),manifest=readFixed(prefix+'manifest.json'),cleanReceipt=readFixed(prefix+'clean-receipt.json'),unsafeReceipt=readFixed(prefix+'unsafe-receipt.json');
 const trust=record(json(readFixed('public/fixtures/trust.json')),['version','descriptorPins','expectedDeploymentScopeSHA256','expectedModules','expectedAdapterPin','expectedGatePin']);
 if(trust.version!==1)fail('INVALID_TRUST');record(trust.descriptorPins,['clean','unsafe']);
 for(const choice of ['clean','unsafe']){
  const pin=record(trust.descriptorPins[choice],['path','bytes','sha256']),fixed=pins['public/fixtures/'+choice+'/descriptor.json'];
  if(pin.path!=='fixtures/'+choice+'/descriptor.json'||pin.bytes!==fixed.bytes||pin.sha256!==fixed.sha256)fail('INVALID_TRUST');
 }
 record(trust.expectedAdapterPin,['path','bytes','sha256']);record(trust.expectedGatePin,['path','bytes','sha256']);
 if(!Array.isArray(trust.expectedModules)||trust.expectedModules.length!==2)fail('INVALID_TRUST');
 for(const row of trust.expectedModules)record(row,['name','bytes','sha256']);
 const contractOptions={descriptor:json(descriptor),descriptorPin:trust.descriptorPins[candidate],publicBytes:{descriptor,manifest,cleanReceipt,unsafeReceipt,gateSource:readFixed('public/lib/reviewed-asset-gate.mjs')},expectedDeploymentScopeSHA256:trust.expectedDeploymentScopeSHA256,expectedModules:trust.expectedModules,expectedAdapterPin:trust.expectedAdapterPin,expectedGatePin:trust.expectedGatePin};
 return {sourceDirectory:path.join(root,prefix,'assets'),manifestPath:path.join(root,prefix,'manifest.json'),expectedManifestSHA256:pins[prefix+'manifest.json'].sha256,contractOptions,manifest:json(manifest)};
}
function cleanup(owned,manifest){
 if(!owned)return 'not_created';
 try{
  const parent=stat(owned.root);if(parent.isSymbolicLink()||!parent.isDirectory()||!sameNode(parent,owned.stat))return 'preserved_unverified_tree';
  const names=fs.readdirSync(owned.root).sort();
  if(names.length){
   if(names.join(',')!=='qualified')return 'preserved_unverified_tree';
   const stage=path.join(owned.root,'qualified'),stageStat=stat(stage);
   if(stageStat.isSymbolicLink()||!stageStat.isDirectory()||fs.readdirSync(stage).sort().join(',')!=='index.html,styles.css')return 'preserved_unverified_tree';
   const plan=[];
   for(const name of ['index.html','styles.css']){
    const row=manifest.files.find(row=>row.path===name);if(!row)return 'preserved_unverified_tree';
    const file=path.join(stage,name),read=readRegular(file);if(read.bytes.length!==row.bytes||hash(read.bytes)!==row.sha256)return 'preserved_unverified_tree';plan.push({file,stat:read.stat});
   }
   if(!sameNode(stat(owned.root),owned.stat)||!sameNode(stat(stage),stageStat)||fs.readdirSync(owned.root).sort().join(',')!=='qualified'||fs.readdirSync(stage).sort().join(',')!=='index.html,styles.css')return 'preserved_unverified_tree';
   for(const row of plan){if(!sameNode(stat(owned.root),owned.stat)||!sameNode(stat(stage),stageStat)||!sameFile(stat(row.file),row.stat))return 'preserved_unverified_tree';fs.unlinkSync(row.file);}
   if(!sameNode(stat(stage),stageStat))return 'preserved_unverified_tree';fs.rmdirSync(stage);
  }
  if(!sameNode(stat(owned.root),owned.stat))return 'preserved_unverified_tree';fs.rmdirSync(owned.root);return 'removed_owned_tree';
 }catch{return 'preserved_unverified_tree';}
}

let candidate,owned,manifest,receipt,error;
try{
 candidate=select();
 for(const relative of ['public/INTERFACE.json','public/lib/safety.mjs','public/lib/reviewed-asset-gate.mjs','public/lib/release-manifest-contract.mjs'])readFixed(relative);
 const input=fixture(candidate);manifest=input.manifest;
 const {qualifyPublicRelease}=await import('../lib/public-release-entry.mjs');
 const tempRoot=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'barkive-public-release-'));owned={root:tempRoot,stat:stat(tempRoot)};
 const {manifest:unused,...options}=input;
 receipt=await qualifyPublicRelease({...options,destinationDirectory:path.join(tempRoot,'qualified')});
}catch(caught){error=caught;}
const disposition=cleanup(owned,manifest),temporaryRemoved=disposition!=='preserved_unverified_tree';
if(!temporaryRemoved&&!error){error=new Error('Temporary cleanup refused');error.code='TEMPORARY_CLEANUP_REFUSED';}
if(error){
 const code=/^[A-Z0-9_]{1,64}$/.test(error?.code??'')?error.code:'PUBLIC_CI_FAILURE',result={state:'PUBLIC_RELEASE_REFUSED',candidate:candidate??null,code,cleanup:disposition,temporaryRemoved};
 if(/^[a-z_]{1,40}$/.test(error?.rule??''))result.rule=error.rule;
 console.error(JSON.stringify(result));process.exitCode=1;
}else console.log(JSON.stringify({state:'PUBLIC_RELEASE_QUALIFIED',candidate,...receipt,cleanup:disposition,temporaryRemoved}));
