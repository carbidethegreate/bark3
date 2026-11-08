import {copyQualifiedPublicAssets} from '../public/lib/reviewed-asset-gate.mjs';
import {validateReleaseManifestContract} from '../public/lib/release-manifest-contract.mjs';

const fail=code=>{const error=new Error('Public release entry rejected ['+code+']');error.name='PublicReleaseEntryError';error.code=code;throw error;};
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

/** Shared awaited entry for the CI runner and future Source constructors. */
export async function qualifyPublicRelease(options){
 const input=record(options,['sourceDirectory','manifestPath','expectedManifestSHA256','destinationDirectory','contractOptions']);
 const contract=record(input.contractOptions,['descriptor','descriptorPin','publicBytes','expectedDeploymentScopeSHA256','expectedModules','expectedAdapterPin','expectedGatePin']);
 const snapshot=Object.fromEntries(Object.entries(contract).map(([key,value])=>[key,key==='publicBytes'?publicBytes(value):data(value)]));
 const assetOptions=Object.fromEntries(['sourceDirectory','manifestPath','expectedManifestSHA256','destinationDirectory'].map(key=>{
  if(typeof input[key]!=='string')fail('INVALID_ARGUMENT');return [key,input[key]];
 }));
 const gate=await copyQualifiedPublicAssets(assetOptions);
 const qualified=validateReleaseManifestContract(snapshot);
 const manifest=JSON.parse(snapshot.publicBytes.manifest.toString('utf8'));
 const totalBytes=manifest.files.reduce((sum,row)=>sum+row.bytes,0);
 if(gate.manifestSHA256!==qualified.descriptor.publicAssets.sha256||gate.count!==manifest.files.length||gate.totalBytes!==totalBytes)fail('PUBLIC_MANIFEST_ASSOCIATION');
 return {manifestSHA256:gate.manifestSHA256,count:gate.count,totalBytes:gate.totalBytes,contractSHA256:qualified.sha256};
}
