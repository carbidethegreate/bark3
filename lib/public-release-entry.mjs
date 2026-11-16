import * as fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {assertSafeTextAsset} from '../public/lib/safety.mjs';
import {copyQualifiedPublicAssets} from '../public/lib/reviewed-asset-gate.mjs';
import {validateReleaseManifestContract} from '../public/lib/release-manifest-contract.mjs';

function fail(code,rule){
 const error=new Error('Public release entry rejected ['+code+']');
 error.name='PublicReleaseEntryError';
 error.code=code;
 if(rule)error.rule=rule;
 throw error;
}
function record(value,names){
 if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail('INVALID_ARGUMENT');
 const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
 if(keys.some(k=>typeof k!=='string')||keys.length!==names.length||names.some(k=>!Object.hasOwn(descriptors,k))||keys.some(k=>!descriptors[k].enumerable||!Object.hasOwn(descriptors[k],'value')))fail('INVALID_ARGUMENT');
 return Object.fromEntries(keys.map(k=>[k,descriptors[k].value]));
}
// This checks/copies data shape only; the frozen validator owns canonicalization.
function data(value,ancestors=new Set()){
 if(value===null||typeof value==='string'||typeof value==='boolean')return value;
 if(typeof value==='number'&&Number.isFinite(value)&&!Object.is(value,-0))return value;
 if(!value||typeof value!=='object'||ancestors.has(value))fail('INVALID_ARGUMENT');
 ancestors.add(value);let result;
 if(Array.isArray(value)){
  if(Object.getPrototypeOf(value)!==Array.prototype)fail('INVALID_ARGUMENT');
  const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
  if(keys.some(k=>typeof k!=='string')||keys.length!==descriptors.length.value+1)fail('INVALID_ARGUMENT');
  result=[];for(let i=0;i<descriptors.length.value;i++){const row=descriptors[i];if(!row?.enumerable||!Object.hasOwn(row,'value'))fail('INVALID_ARGUMENT');result.push(data(row.value,ancestors));}
 }else{
  if(![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail('INVALID_ARGUMENT');
  const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
  if(keys.some(k=>typeof k!=='string')||keys.some(k=>!descriptors[k].enumerable||!Object.hasOwn(descriptors[k],'value')))fail('INVALID_ARGUMENT');
  result=Object.fromEntries(keys.map(k=>[k,data(descriptors[k].value,ancestors)]));
 }
 ancestors.delete(value);return result;
}
function publicBytes(value){
 const fields=['descriptor','manifest','cleanReceipt','unsafeReceipt','gateSource'],rows=record(value,fields);
 return Object.fromEntries(fields.map(key=>{
  const bytes=rows[key];
  if(!(bytes instanceof Uint8Array)||![Uint8Array.prototype,Buffer.prototype].includes(Object.getPrototypeOf(bytes)))fail('INVALID_ARGUMENT');
  const descriptors=Object.getOwnPropertyDescriptors(bytes),keys=Reflect.ownKeys(descriptors);
  if(keys.some(k=>typeof k!=='string'||!/^(0|[1-9][0-9]*)$/.test(k))||keys.some(k=>!descriptors[k].enumerable||!Object.hasOwn(descriptors[k],'value'))||keys.length!==bytes.length)fail('INVALID_ARGUMENT');
  return [key,Buffer.from(bytes)];
 }));
}

// The gate has already copied exactly these manifest rows into the caller's own stage.
function stagedBytes(directory,row){
 const file=path.join(directory,row.path);
 let fd;
 try{
  if(fs.realpathSync(file)!==file)fail('PUBLIC_STAGE_CHANGED');
  const before=fs.lstatSync(file,{bigint:true});
  if(!before.isFile()||before.size!==BigInt(row.bytes))fail('PUBLIC_STAGE_CHANGED');
  const same=stat=>stat.dev===before.dev&&stat.ino===before.ino&&stat.mode===before.mode
    &&stat.size===before.size&&stat.mtimeNs===before.mtimeNs&&stat.ctimeNs===before.ctimeNs;
  fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  if(!same(fs.fstatSync(fd,{bigint:true})))fail('PUBLIC_STAGE_CHANGED');
  const bytes=Buffer.alloc(row.bytes);
  for(let offset=0;offset<bytes.length;){
   const count=fs.readSync(fd,bytes,offset,bytes.length-offset,null);
   if(!count)fail('PUBLIC_STAGE_CHANGED');
   offset+=count;
  }
  if(!same(fs.fstatSync(fd,{bigint:true}))||!same(fs.lstatSync(file,{bigint:true}))
    ||createHash('sha256').update(bytes).digest('hex')!==row.sha256)fail('PUBLIC_STAGE_CHANGED');
  return bytes;
 }catch{
  fail('PUBLIC_STAGE_CHANGED');
 }finally{
  if(fd!==undefined)fs.closeSync(fd);
 }
}

function verifyPublicCIAssets(directory,manifest){
 for(const row of manifest.files){
  const bytes=stagedBytes(directory,row);
  try{assertSafeTextAsset(row.path,bytes,{rejectPrototype:true});}
  catch(error){
   if(error.code==='UNSAFE_TEXT_ASSET')fail('UNSAFE_PUBLIC_TEXT',error.rule);
   throw error;
  }
 }
}

/** Source callers retain the default policy. The fixed CI runner requests strict scanning. */
export async function qualifyPublicRelease(options,policy){
 const rejectPrototype=policy===undefined?false:record(policy,['rejectPrototype']).rejectPrototype;
 if(typeof rejectPrototype!=='boolean')fail('INVALID_ARGUMENT');
 const input=record(options,['sourceDirectory','manifestPath','expectedManifestSHA256','destinationDirectory','contractOptions']);
 const contract=record(input.contractOptions,['descriptor','descriptorPin','publicBytes','expectedDeploymentScopeSHA256','expectedModules','expectedAdapterPin','expectedGatePin']);
 const snapshot=Object.fromEntries(Object.entries(contract).map(([key,value])=>[key,key==='publicBytes'?publicBytes(value):data(value)]));
 const assetOptions=Object.fromEntries(['sourceDirectory','manifestPath','expectedManifestSHA256','destinationDirectory'].map(key=>{
  if(typeof input[key]!=='string')fail('INVALID_ARGUMENT');return [key,input[key]];
 }));
 const gate=await copyQualifiedPublicAssets(assetOptions);
 if(rejectPrototype)verifyPublicCIAssets(assetOptions.destinationDirectory,gate.manifest);
 const qualified=validateReleaseManifestContract(snapshot);
 const manifest=JSON.parse(snapshot.publicBytes.manifest.toString('utf8'));
 const totalBytes=manifest.files.reduce((sum,row)=>sum+row.bytes,0);
 if(gate.manifestSHA256!==qualified.descriptor.publicAssets.sha256||gate.count!==manifest.files.length||gate.totalBytes!==totalBytes)fail('PUBLIC_MANIFEST_ASSOCIATION');
 return {manifestSHA256:gate.manifestSHA256,count:gate.count,totalBytes:gate.totalBytes,contractSHA256:qualified.sha256};
}
