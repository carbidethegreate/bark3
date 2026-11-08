import {createHash} from 'node:crypto';

const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const SHA256=/^[a-f0-9]{64}$/;
const moduleNames=['card-renderer.wasm','worker.bundle.mjs'];
const selectors=new Set(['owner','ownerid','ownerselector','account','accountid','accountname','accountselector','worker','workername','workerselector','scope','deploymentscope','environment','profile','host','zone','zoneid']);
const reject=code=>{const error=new Error('Release manifest contract rejected ['+code+']');error.name='ReleaseManifestContractError';error.code=code;throw error;};
function text(value){if(typeof value!=='string'||!value.length||/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value))reject('STRING');return value;}
function hash(value){if(typeof value!=='string'||!SHA256.test(value))reject('SHA256');return value;}
function integer(value,positive=false){if(!Number.isSafeInteger(value)||value<0||Object.is(value,-0)||positive&&value===0)reject('INTEGER');return value;}
function object(value){if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value))||Object.getOwnPropertySymbols(value).length)reject('OBJECT');return value;}
function keys(value,names){object(value);const descriptors=Object.getOwnPropertyDescriptors(value);if(Object.keys(descriptors).sort().join(',')!==[...names].sort().join(',')||Object.values(descriptors).some(d=>!d.enumerable||!Object.hasOwn(d,'value')))reject('FIELDS');return value;}

// The single canonical JSON algorithm; CONTRACT.json defines the same byte rules.
function canonicalJSON(value,ancestors=new Set()){
 if(value===null)return 'null';
 if(typeof value==='string'){if(value.length)text(value);return JSON.stringify(value);}
 if(typeof value==='boolean')return String(value);
 if(typeof value==='number'){if(!Number.isFinite(value)||Object.is(value,-0))reject('JSON_NUMBER');return JSON.stringify(value);}
 if(typeof value!=='object'||ancestors.has(value))reject('JSON_VALUE');
 ancestors.add(value);let result;
 if(Array.isArray(value)){
  if(Object.getPrototypeOf(value)!==Array.prototype||Object.getOwnPropertySymbols(value).length)reject('JSON_ARRAY');
  const descriptors=Object.getOwnPropertyDescriptors(value);if(Object.keys(descriptors).length!==value.length+1)reject('JSON_ARRAY');
  const items=[];for(let i=0;i<value.length;i++){const d=descriptors[i];if(!d?.enumerable||!Object.hasOwn(d,'value'))reject('JSON_ARRAY');items.push(canonicalJSON(d.value,ancestors));}result='['+items.join(',')+']';
 }else{
  object(value);const descriptors=Object.getOwnPropertyDescriptors(value),parts=[];
  for(const key of Object.keys(descriptors).sort()){if(key.length)text(key);const d=descriptors[key];if(!d.enumerable||!Object.hasOwn(d,'value'))reject('JSON_OBJECT');parts.push(JSON.stringify(key)+':'+canonicalJSON(d.value,ancestors));}result='{'+parts.join(',')+'}';
 }
 ancestors.delete(value);return result;
}
const clone=value=>JSON.parse(canonicalJSON(value));
function freeze(value){if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;}
const equal=(a,b)=>canonicalJSON(a)===canonicalJSON(b);
function pin(value){keys(value,['path','bytes','sha256']);return {path:text(value.path),bytes:integer(value.bytes,true),sha256:hash(value.sha256)};}
function samePin(a,b){if(!equal(pin(a),pin(b)))reject('PIN_ASSOCIATION');}
function modules(value){
 // Validate and copy the whole data array before any caller method or element read.
 value=clone(value);
 if(!Array.isArray(value)||value.length!==2)reject('MODULE_COUNT');
 const result=value.map(row=>{keys(row,['name','bytes','sha256']);return {name:text(row.name),bytes:integer(row.bytes,true),sha256:hash(row.sha256)};}).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
 if(!equal(result.map(r=>r.name),moduleNames))reject('MODULE_NAMES');return result;
}
function bytes(value){if(!(value instanceof Uint8Array))reject('PUBLIC_BYTES');return Buffer.from(value);}
function verifyBytes(value,expected){const data=bytes(value),reference=pin(expected);if(data.length!==reference.bytes||digest(data)!==reference.sha256)reject('PUBLIC_BYTE_PIN');return data;}
function uniqueJSONKeys(source){
 const tokens=source.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g)??[];let i=0;
 function value(depth=0){if(depth>64)reject('PUBLIC_JSON');const token=tokens[i++];if(token==='{'){const seen=new Set();if(tokens[i]==='}'){i++;return;}for(;;){const key=JSON.parse(tokens[i++]);if(seen.has(key))reject('DUPLICATE_JSON_KEY');seen.add(key);i++;value(depth+1);const next=tokens[i++];if(next==='}')break;if(next!==',')reject('PUBLIC_JSON');}}else if(token==='['){if(tokens[i]===']'){i++;return;}for(;;){value(depth+1);const next=tokens[i++];if(next===']')break;if(next!==',')reject('PUBLIC_JSON');}}}
 value();if(i!==tokens.length)reject('PUBLIC_JSON');
}
function publicJSON(data){const source=data.toString('utf8');if(!Buffer.from(source,'utf8').equals(data))reject('PUBLIC_JSON_UTF8');let value;try{value=JSON.parse(source);}catch{reject('PUBLIC_JSON');}uniqueJSONKeys(source);canonicalJSON(value);return value;}
function descriptor(value){const result=clone(value);object(result);for(const name of Object.keys(result))if(selectors.has(name.replace(/[-_]/g,'').toLowerCase()))reject('OWNER_SELECTOR');result.candidateModules=modules(result.candidateModules);return result;}

/** Opaque Source-private operands; only their digest is returned. No provider claim. */
export function computeDeploymentScopeSHA256(value){
 keys(value,['accountId','workerName']);
 return digest(Buffer.from(canonicalJSON({kind:'barkive-main-release-scope-v1',accountId:text(value.accountId),workerName:text(value.workerName),environment:'staging-review'}),'utf8'));
}

/** Pure linkage of existing Source public shapes; performs no path or process I/O. */
export function validateReleaseManifestContract(options){
 keys(options,['descriptor','descriptorPin','publicBytes','expectedDeploymentScopeSHA256','expectedModules','expectedAdapterPin','expectedGatePin']);
 keys(options.publicBytes,['descriptor','manifest','cleanReceipt','unsafeReceipt','gateSource']);
 const supplied=options.publicBytes,expectedScope=hash(options.expectedDeploymentScopeSHA256),candidate=descriptor(options.descriptor);
 if(!Object.hasOwn(candidate,'deploymentScopeSHA256'))reject('MISSING_SCOPE');
 if(hash(candidate.deploymentScopeSHA256)!==expectedScope)reject('SCOPE_MISMATCH');
 const original=descriptor(publicJSON(verifyBytes(supplied.descriptor,options.descriptorPin))),comparison=clone(candidate);
 if(!Object.hasOwn(original,'deploymentScopeSHA256'))delete comparison.deploymentScopeSHA256;
 if(!equal(comparison,original))reject('DESCRIPTOR_ASSOCIATION');
 keys(candidate.base,['version','deployment','workerSHA256']);text(candidate.base.version);text(candidate.base.deployment);hash(candidate.base.workerSHA256);
 const expectedModules=modules(options.expectedModules);
 if(!equal(candidate.candidateModules,expectedModules))reject('MODULE_INVENTORY');
 const publicAssetPin=pin(candidate.publicAssets),manifest=publicJSON(verifyBytes(supplied.manifest,publicAssetPin));keys(manifest,['files']);
 if(!Array.isArray(manifest.files)||manifest.files.length===0)reject('ASSET_COUNT');
 const paths=new Set();let totalBytes=0;
 for(const row of manifest.files){keys(row,['path','bytes','sha256']);const name=text(row.path);if(paths.has(name))reject('DUPLICATE_ASSET');paths.add(name);totalBytes+=integer(row.bytes);hash(row.sha256);if(!Number.isSafeInteger(totalBytes))reject('ASSET_BYTES');}
 object(candidate.preSRequired);
 const cleanPin=pin(candidate.preSRequired.actualClean938ThroughReviewedSourceAdapter),unsafePin=pin(candidate.preSRequired.actualUnsafeControlRefusedBeforeCLI);
 const clean=publicJSON(verifyBytes(supplied.cleanReceipt,cleanPin)),unsafe=publicJSON(verifyBytes(supplied.unsafeReceipt,unsafePin));object(clean);object(unsafe);
 const adapterPin=pin(options.expectedAdapterPin),gatePin=pin(options.expectedGatePin);samePin(clean.adapter,adapterPin);samePin(clean.gate,gatePin);verifyBytes(supplied.gateSource,gatePin);
 samePin(clean.actualManifest,publicAssetPin);
 const receipt=clean.publicReceipt;keys(receipt,['state','manifestSHA256','assets','modules','moduleScanRootFiles','nonLocationConfigFieldsUnchanged','outdirOutsideModuleScanRoot','providerCalls']);
 if(receipt.state!=='PUBLIC_GATE_AWAITED_BEFORE_CONFIG_READY')reject('GATE_BEFORE_READINESS');
 if(hash(receipt.manifestSHA256)!==publicAssetPin.sha256)reject('MANIFEST_ASSOCIATION');
 if(integer(receipt.assets,true)!==manifest.files.length||integer(clean.stagedPublicFiles,true)!==manifest.files.length)reject('ASSET_COUNT');
 if(integer(clean.stagedPublicBytes)!==totalBytes)reject('ASSET_BYTES');
 if(!equal(modules(receipt.modules),expectedModules)||integer(receipt.moduleScanRootFiles,true)!==expectedModules.length||clean.stagedTwoModulePinsMatch!==true)reject('MODULE_ASSOCIATION');
 if(receipt.nonLocationConfigFieldsUnchanged!==true||clean.privateConfigurationNonLocationFieldsExact!==true)reject('CONFIGURATION_CHANGED');
 if(receipt.outdirOutsideModuleScanRoot!==true)reject('OUTDIR_ASSOCIATION');
 if(receipt.providerCalls!==0||clean.providerCalls!==0||clean.CLIInvocations!==0)reject('CLEAN_SIDE_EFFECT_WITNESS');
 if(unsafe.state!=='REFUSED_BEFORE_READY_OR_CLI'||unsafe.providerCalls!==0||unsafe.CLIInvocations!==0)reject('UNSAFE_REFUSAL');
 if(hash(unsafe.adapterSHA256)!==adapterPin.sha256||hash(unsafe.gateSHA256)!==gatePin.sha256||unsafe.manifestAndModulePinsMatched!==true)reject('UNSAFE_ASSOCIATION');
 const cleanup=unsafe.cleanup;object(cleanup);object(cleanup.upstream);
 if(cleanup.gateInvoked!==true||cleanup.publicationReady!==false||cleanup.assetsAdopted!==false||cleanup.outerRecursiveDeletion!==false||cleanup.currentStageIdentityVerified!==true||cleanup.disposition!=='removed_owned_partial'||cleanup.upstream.state!=='not_created')reject('UNSAFE_READINESS_OR_CLEANUP');
 integer(cleanup.outerUnlinks);integer(cleanup.outerRmdirs);
 for(const name of ['filesRemoved','directoriesRemoved']){if(!Object.hasOwn(cleanup.upstream,name))reject('UNKNOWN_COUNTER_MISSING');if(cleanup.upstream[name]!==null)integer(cleanup.upstream[name]);}
 const canonical=canonicalJSON(candidate);
 return freeze({descriptor:JSON.parse(canonical),canonicalJSON:canonical,sha256:digest(Buffer.from(canonical,'utf8'))});
}
