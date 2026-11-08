import * as fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {assertSafeTextAsset} from './safety.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sha256=/^[a-f0-9]{64}$/;
const publicExtensions=new Set(['.html','.css','.js','.json','.svg','.txt','.wasm','.webp','.png','.jpg','.jpeg','.avif','.gif','.ico','.woff','.woff2','.ttf','.otf','.mp4','.webm','.mp3','.ogg']);
const privateDirectories=new Set(['src','scripts','config','configs','migrations','knowledge-migrations','node_modules','evidence','release','private','native','captures','fixtures','tests','__tests__','backend']);
const privateName=/^(?:worker(?:[._-].*)?|wrangler(?:[._-].*)?|staff-access-config(?:[._-].*)?|staff-defines(?:[._-].*)?|private(?:[._-].*)?|native-capture(?:[._-].*)?|(?:package(?:-lock)?|manifest|inputs?|result|claim|seal|target-map|provenance|source-contract|candidate-assets|fixture-contract|fixture-inputs|mutation-claim)(?:[._-].*)?\.json)$/i;
const maxFileBytes=25*1024*1024; // Existing review builder's per-file platform limit.

function failure(code,asset,rule){
 const error=new Error('Public asset qualification failed ['+code+']'+(asset?' '+asset:'')+(rule?' ['+rule+']':''));
 error.name='PublicAssetQualificationError';error.code=code;
 if(asset)error.asset=asset;if(rule)error.rule=rule;return error;
}
const fail=(code,asset,rule)=>{throw failure(code,asset,rule);};
const stat=file=>fs.lstatSync(file,{bigint:true});
const sameNode=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode;
const sameFile=(a,b)=>sameNode(a,b)&&a.nlink===b.nlink&&a.size===b.size&&a.mtimeNs===b.mtimeNs&&a.ctimeNs===b.ctimeNs;
function present(file){try{return stat(file);}catch(error){if(error.code==='ENOENT')return null;throw error;}}
function absolute(value){
 if(typeof value!=='string'||!value.startsWith('/')||/[\\\x00-\x1f\x7f]/.test(value)||path.resolve(value)!==value||value==='/')fail('INVALID_ARGUMENT');
 return value;
}
function directoryChain(directory){
 const chain=[];let current='/';
 for(const part of directory.split('/').filter(Boolean)){
  current=path.join(current,part);const value=stat(current);
  if(value.isSymbolicLink()||!value.isDirectory())fail('SYMLINK_OR_NON_DIRECTORY');
  chain.push({path:current,stat:value});
 }
 return chain;
}
function checkChain(chain){for(const row of chain){const now=stat(row.path);if(now.isSymbolicLink()||!now.isDirectory()||!sameNode(now,row.stat))fail('DIRECTORY_CHANGED');}}
function publicPath(name){
 if(typeof name!=='string'||!name||!/[A-Za-z0-9]/.test(name)||!/^[A-Za-z0-9._/-]+$/.test(name))fail('INVALID_PUBLIC_PATH');
 const parts=name.split('/');
 if(parts.some(p=>!p||p==='.'||p==='..'||p.startsWith('.')||privateDirectories.has(p.toLowerCase())))fail('PRIVATE_OR_INTERNAL_PATH');
 if(parts.length>1&&!['admin','assets','data'].includes(parts[0]))fail('PRIVATE_OR_INTERNAL_PATH');
 const leaf=parts.at(-1),extension=path.posix.extname(leaf).toLowerCase();
 if(!publicExtensions.has(extension)||privateName.test(leaf)||leaf.toLowerCase().endsWith('.map')||parts.length===1&&['runtime.js','build.js','safety.js','release-paths.js'].includes(leaf.toLowerCase()))fail('PRIVATE_OR_INTERNAL_PATH');
 if(extension==='.json'&&parts[0]!=='data')fail('PRIVATE_OR_INTERNAL_PATH');
 return parts;
}
function rejectDuplicateJSONKeys(text){
 const tokens=text.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g)??[];let at=0;
 function value(depth=0){
  if(depth>8)fail('INVALID_PUBLIC_MANIFEST');
  const token=tokens[at++];
  if(token==='{'){
   const seen=new Set();if(tokens[at]==='}'){at++;return;}
   for(;;){const key=JSON.parse(tokens[at++]);if(seen.has(key))fail('DUPLICATE_MANIFEST_KEY');seen.add(key);at++;value(depth+1);const next=tokens[at++];if(next==='}')break;if(next!==',')fail('INVALID_PUBLIC_MANIFEST');}
  }else if(token==='['){if(tokens[at]===']'){at++;return;}for(;;){value(depth+1);const next=tokens[at++];if(next===']')break;if(next!==',')fail('INVALID_PUBLIC_MANIFEST');}}
 }
 value();if(at!==tokens.length)fail('INVALID_PUBLIC_MANIFEST');
}
function parseManifest(bytes){
 let value;try{value=JSON.parse(bytes.toString('utf8'));}catch{fail('INVALID_PUBLIC_MANIFEST');}
 rejectDuplicateJSONKeys(bytes.toString('utf8'));
 if(!value||Array.isArray(value)||Object.keys(value).join(',')!=='files'||!Array.isArray(value.files))fail('INVALID_PUBLIC_MANIFEST');
 const root={children:new Map()},seen=new Set(),prefixes=new Map();let totalBytes=0;
 const files=value.files.map(row=>{
  if(!row||Array.isArray(row)||Object.keys(row).sort().join(',')!=='bytes,path,sha256'||!Number.isSafeInteger(row.bytes)||row.bytes<0||row.bytes>maxFileBytes||typeof row.sha256!=='string'||!sha256.test(row.sha256))fail('INVALID_PUBLIC_MANIFEST');
  const parts=publicPath(row.path),fold=row.path.toLowerCase();
  if(seen.has(fold))fail('DUPLICATE_PUBLIC_PATH');seen.add(fold);
  let node=root;
  for(const [i,part] of parts.entries()){
   const prefix=parts.slice(0,i+1).join('/'),folded=prefix.toLowerCase();if(prefixes.has(folded)&&prefixes.get(folded)!==prefix)fail('DUPLICATE_PUBLIC_PATH');prefixes.set(folded,prefix);
   if(node.file)fail('PUBLIC_PATH_CONFLICT');
   if(!node.children.has(part))node.children.set(part,{children:new Map()});
   node=node.children.get(part);
   if(i===parts.length-1){if(node.file||node.children.size)fail('PUBLIC_PATH_CONFLICT');node.file=row;}
  }
  totalBytes+=row.bytes;if(!Number.isSafeInteger(totalBytes))fail('INVALID_PUBLIC_MANIFEST');
  return Object.freeze({path:row.path,bytes:row.bytes,sha256:row.sha256});
 });
 return {manifest:Object.freeze({files:Object.freeze(files)}),tree:root,totalBytes};
}
function scanTree(directory,node,rootChain){
 const files=new Map(),directories=new Map();
 function walk(dir,trie,relative=''){
  checkChain(rootChain);const before=stat(dir);
  if(before.isSymbolicLink()||!before.isDirectory())fail('SYMLINK_OR_NON_DIRECTORY');
  const names=fs.readdirSync(dir).sort();
  // Validate the complete entry list before opening any child payload/directory.
  for(const name of names){if(!/^[A-Za-z0-9._-]+$/.test(name)||name.startsWith('.')||!trie.children.has(name))fail('EXTRA_OR_PRIVATE_ENTRY');}
  if(names.length!==trie.children.size)fail('MISSING_PUBLIC_ASSET');
  directories.set(dir,before);
  for(const name of names){
   const child=trie.children.get(name),file=path.join(dir,name),label=relative?relative+'/'+name:name,info=stat(file);
   if(info.isSymbolicLink())fail('SYMLINK_ASSET');
   if(child.file){if(!info.isFile())fail('NON_REGULAR_ASSET');if(info.size!==BigInt(child.file.bytes))fail('ASSET_SIZE',label);files.set(label,{path:file,stat:info});}
   else{if(!info.isDirectory())fail('PUBLIC_PATH_CONFLICT');walk(file,child,label);}
  }
  if(!sameFile(before,stat(dir)))fail('SOURCE_TREE_CHANGED');
 }
 walk(directory,node);return {files,directories};
}
function checkSnapshot(first,next){
 if(first.files.size!==next.files.size||first.directories.size!==next.directories.size)fail('SOURCE_TREE_CHANGED');
 for(const [name,row] of first.files)if(!next.files.has(name)||!sameFile(row.stat,next.files.get(name).stat))fail('SOURCE_CHANGED',name);
 for(const [name,value] of first.directories)if(!next.directories.has(name)||!sameFile(value,next.directories.get(name)))fail('SOURCE_TREE_CHANGED');
}
function readExact(file,expected,chain,label){
 checkChain(chain);const before=stat(file);
 if(before.isSymbolicLink()||!before.isFile()||!sameFile(before,expected))fail('SOURCE_CHANGED',label);
 let fd;
 try{
  fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  if(!sameFile(fs.fstatSync(fd,{bigint:true}),expected))fail('SOURCE_CHANGED',label);
  checkChain(chain);
  const bytes=Buffer.alloc(Number(expected.size));let offset=0;
  while(offset<bytes.length){const read=fs.readSync(fd,bytes,offset,bytes.length-offset,null);if(read<=0)fail('ASSET_SIZE',label);offset+=read;}
  if(fs.readSync(fd,Buffer.alloc(1),0,1,null)!==0||!sameFile(fs.fstatSync(fd,{bigint:true}),expected))fail('SOURCE_CHANGED',label);
  checkChain(chain);return bytes;
 }finally{if(fd!==undefined)fs.closeSync(fd);}
}
function sourceChainFor(file,rootChain,snapshot){
 const directories=[...snapshot.directories].filter(([name])=>file.startsWith(name+'/')).map(([name,value])=>({path:name,stat:value}));
 return rootChain.concat(directories);
}
function destinationChain(journal,directory){
 return journal.parentChain.concat([...journal.directories].filter(([name])=>directory===name||directory.startsWith(name+'/')).map(([name,value])=>({path:name,stat:value})));
}
function ownDirectory(journal,directory){
 if(journal.directories.has(directory)){checkChain(destinationChain(journal,directory));return;}
 const parent=path.dirname(directory);checkChain(destinationChain(journal,parent));
 fs.mkdirSync(directory,{mode:0o700});const info=stat(directory);
 if(info.isSymbolicLink()||!info.isDirectory())fail('DESTINATION_CHANGED');
 journal.directories.set(directory,info);checkChain(destinationChain(journal,directory));
}
function copyBuffer(journal,row,bytes){
 const dest=path.join(journal.destination,row.path),parent=path.dirname(dest);
 const relative=path.relative(journal.destination,parent).split(path.sep).filter(Boolean);let dir=journal.destination;
 for(const part of relative){dir=path.join(dir,part);ownDirectory(journal,dir);}
 checkChain(destinationChain(journal,parent));
 let fd,owned;
 try{
  fd=fs.openSync(dest,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  owned={path:dest,stat:fs.fstatSync(fd,{bigint:true}),expected:Buffer.alloc(0)};journal.files.set(row.path,owned);
  checkChain(destinationChain(journal,parent));if(!sameNode(stat(dest),owned.stat))fail('DESTINATION_CHANGED');
  let written=0;
  while(written<bytes.length){const n=fs.writeSync(fd,bytes,written,bytes.length-written,null);if(n<=0)fail('DESTINATION_WRITE',row.path);written+=n;owned.expected=bytes.subarray(0,written);}
  if(bytes.length===0)owned.expected=bytes;
 }finally{
  if(fd!==undefined){try{if(owned){owned.stat=fs.fstatSync(fd,{bigint:true});if(owned.stat.size<=BigInt(bytes.length))owned.expected=bytes.subarray(0,Number(owned.stat.size));}}finally{fs.closeSync(fd);}}
 }
 checkChain(destinationChain(journal,parent));
 if(!sameFile(stat(dest),owned.stat))fail('DESTINATION_CHANGED');
}
function ownedTree(journal){
 const tree={children:new Map()};
 for(const directory of journal.directories.keys()){
  const parts=path.relative(journal.destination,directory).split(path.sep).filter(Boolean);let node=tree;
  for(const part of parts){if(!node.children.has(part))node.children.set(part,{children:new Map()});node=node.children.get(part);}
 }
 for(const [name,row] of journal.files){let node=tree;const parts=name.split('/');for(const part of parts){if(!node.children.has(part))node.children.set(part,{children:new Map()});node=node.children.get(part);}node.owned=row;}
 return tree;
}
function verifyOwnedDestination(journal){
 checkChain(destinationChain(journal,journal.destination));const directoryStates=[];
 function walk(dir,node){
  const before=stat(dir),expected=journal.directories.get(dir);
  if(!expected||!sameNode(before,expected)||before.isSymbolicLink()||!before.isDirectory())fail('DESTINATION_CHANGED');
  const names=fs.readdirSync(dir).sort();if(names.length!==node.children.size||names.some(n=>!node.children.has(n)))fail('FOREIGN_DESTINATION_ENTRY');
  directoryStates.push([dir,before]);
  for(const name of names){
   const child=node.children.get(name),file=path.join(dir,name);
   if(child.owned){const owned=child.owned,now=stat(file);if(now.isSymbolicLink()||!now.isFile()||!sameFile(now,owned.stat))fail('DESTINATION_CHANGED');const bytes=readExact(file,owned.stat,destinationChain(journal,dir));if(!bytes.equals(owned.expected))fail('DESTINATION_CHANGED');}
   else walk(file,child);
  }
 }
 walk(journal.destination,ownedTree(journal));
 for(const [dir,value] of directoryStates)if(!sameFile(stat(dir),value))fail('DESTINATION_CHANGED');
}
function cleanup(journal){
 if(!journal.created)return Object.freeze({state:'not_created'});
 let filesRemoved=0,directoriesRemoved=0;
 try{
  // A mixed/replaced/changed tree is preserved, rather than recursively removed.
  verifyOwnedDestination(journal);
  for(const row of [...journal.files.values()].reverse()){
   checkChain(destinationChain(journal,path.dirname(row.path)));
   if(!sameFile(stat(row.path),row.stat))fail('DESTINATION_CHANGED');
   fs.unlinkSync(row.path);filesRemoved++;
  }
  for(const [directory,value] of [...journal.directories].sort(([a],[b])=>b.length-a.length)){
   checkChain(journal.parentChain);const now=stat(directory);
   if(!sameNode(now,value)||now.isSymbolicLink()||!now.isDirectory())fail('DESTINATION_CHANGED');
   fs.rmdirSync(directory);directoriesRemoved++;
  }
  return Object.freeze({state:'removed_owned_partial',filesRemoved,directoriesRemoved});
 }catch{return Object.freeze({state:'preserved_changed_or_foreign_tree',filesRemoved,directoriesRemoved});}
}

/** Synchronous, public-only qualification/copy under the caller's exclusive stage custody. */
export function copyQualifiedPublicAssets(options){
 const journal={created:false,files:new Map(),directories:new Map()};
 try{
  if(path.sep!=='/'||!Number.isInteger(fs.constants.O_NOFOLLOW))fail('UNSUPPORTED_PLATFORM');
  if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).sort().join(',')!=='destinationDirectory,expectedManifestSHA256,manifestPath,sourceDirectory'||Object.values(Object.getOwnPropertyDescriptors(options)).some(d=>!Object.hasOwn(d,'value')))fail('INVALID_ARGUMENT');
  const source=absolute(options.sourceDirectory),manifestPath=absolute(options.manifestPath),destination=absolute(options.destinationDirectory);
  const expectedManifestSHA256=options.expectedManifestSHA256;
  if(typeof expectedManifestSHA256!=='string'||!sha256.test(expectedManifestSHA256)||path.basename(manifestPath).startsWith('.')||path.extname(manifestPath).toLowerCase()!=='.json'||privateName.test(path.basename(manifestPath))&&!/^(?:manifest|candidate-assets)\.json$/i.test(path.basename(manifestPath)))fail('INVALID_ARGUMENT');
  if(destination===source||destination.startsWith(source+'/')||source.startsWith(destination+'/')||manifestPath.startsWith(source+'/')||manifestPath===destination||manifestPath.startsWith(destination+'/'))fail('OVERLAPPING_PATHS');
  journal.destination=destination;journal.parentChain=directoryChain(path.dirname(destination));
  if(present(destination))fail('DESTINATION_EXISTS');
  const sourceChain=directoryChain(source),manifestChain=directoryChain(path.dirname(manifestPath)),manifestStat=stat(manifestPath);
  if(manifestStat.isSymbolicLink()||!manifestStat.isFile()||manifestStat.size>BigInt(Buffer.constants?.MAX_LENGTH??0x7fffffff))fail('INVALID_PUBLIC_MANIFEST');
  const manifestBytes=readExact(manifestPath,manifestStat,manifestChain);
  if(hash(manifestBytes)!==expectedManifestSHA256)fail('MANIFEST_HASH');
  const {manifest,tree,totalBytes}=parseManifest(manifestBytes),snapshot=scanTree(source,tree,sourceChain),buffers=[];
  for(const row of manifest.files){
   const file=snapshot.files.get(row.path),bytes=readExact(file.path,file.stat,sourceChainFor(file.path,sourceChain,snapshot),row.path);
   if(bytes.length!==row.bytes||hash(bytes)!==row.sha256)fail('ASSET_HASH',row.path);
   try{assertSafeTextAsset(row.path,bytes);}catch(error){if(error.code==='UNSAFE_TEXT_ASSET')fail('UNSAFE_PUBLIC_TEXT',row.path,/^[a-z_]+$/.test(error.rule??'')?error.rule:undefined);throw error;}
   buffers.push(bytes);
  }
  checkSnapshot(snapshot,scanTree(source,tree,sourceChain));checkChain(manifestChain);
  if(!sameFile(stat(manifestPath),manifestStat))fail('MANIFEST_CHANGED');
  checkChain(journal.parentChain);if(present(destination))fail('DESTINATION_EXISTS');
  fs.mkdirSync(destination,{mode:0o700});journal.created=true;
  const rootStat=stat(destination);if(rootStat.isSymbolicLink()||!rootStat.isDirectory())fail('DESTINATION_CHANGED');journal.directories.set(destination,rootStat);
  for(const [i,row] of manifest.files.entries()){if(hash(buffers[i])!==row.sha256)fail('BUFFER_CHANGED',row.path);copyBuffer(journal,row,buffers[i]);}
  verifyOwnedDestination(journal);checkSnapshot(snapshot,scanTree(source,tree,sourceChain));checkChain(manifestChain);
  if(!sameFile(stat(manifestPath),manifestStat))fail('MANIFEST_CHANGED');
  verifyOwnedDestination(journal);
  return Object.freeze({manifest,count:manifest.files.length,totalBytes,manifestSHA256:expectedManifestSHA256});
 }catch(error){
  const result=error?.name==='PublicAssetQualificationError'?error:failure('IO_FAILURE');
  if(result.code==='IO_FAILURE'&&/^[A-Z0-9_]{1,24}$/.test(error?.code??''))result.ioCode=error.code;
  result.cleanup=cleanup(journal);throw result;
 }
}
