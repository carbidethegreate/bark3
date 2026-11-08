import { readFileSync, readdirSync, lstatSync } from 'node:fs';
import { resolve, relative, extname } from 'node:path';
export function verifyConfig(root) {
  for(const part of ['wrangler.jsonc','src','src/worker.js','migrations','public','scripts'])if(lstatSync(resolve(root,part)).isSymbolicLink())throw new Error('Symlinked environment input forbidden');
  const config=JSON.parse(readFileSync(resolve(root,'wrangler.jsonc'),'utf8'));
  const exactKeys=(object,allowed)=>{if(Object.keys(object).some(k=>!allowed.includes(k)))throw new Error('Unexpected configuration key or binding');};
  exactKeys(config,['name','account_id','main','compatibility_date','compatibility_flags','workers_dev','preview_urls','send_metrics','dev','assets','vars','d1_databases','r2_buckets','durable_objects','migrations']);
  if(config.main!=='src/worker.js'||config.compatibility_date!=='2026-09-28'||config.send_metrics!==false||JSON.stringify(config.compatibility_flags)!=='["nodejs_compat"]')throw new Error('Entrypoint/runtime isolation failed');
  exactKeys(config.dev,['ip','port','local_protocol']);
  exactKeys(config.assets,['directory','binding','run_worker_first']);
  exactKeys(config.vars,['APP_ENV','RELEASE_STATE']);
  if(config.name!=='barkive-community-local-only'||config.account_id!=='00000000000000000000000000000000')throw new Error('Local identity isolation failed');
  if(config.workers_dev!==false||config.preview_urls!==false||config.routes?.length||config.triggers||config.services)throw new Error('Remote routing/binding is forbidden in local config');
  if(config.vars.APP_ENV!=='local'||config.vars.RELEASE_STATE!=='review-required')throw new Error('Release guard missing');
  if(config.dev.ip!=='127.0.0.1'||config.assets.directory!=='./dist'||config.assets.run_worker_first!==true)throw new Error('Local server/asset isolation failed');
  if(config.dev.port!==4180||config.dev.local_protocol!=='http'||config.assets.binding!=='ASSETS')throw new Error('Local server/asset identity failed');
  if(config.d1_databases.length!==1||config.d1_databases[0].database_id!=='00000000-0000-4000-8000-000000000001'||config.d1_databases[0].remote!==false)throw new Error('Database isolation failed');
  exactKeys(config.d1_databases[0],['binding','database_name','database_id','migrations_dir','remote']);
  if(config.d1_databases[0].binding!=='COMMUNITY_DB'||config.d1_databases[0].database_name!=='barkive-community-local'||config.d1_databases[0].migrations_dir!=='migrations')throw new Error('Database/migration source isolation failed');
  if(config.r2_buckets.length!==1||config.r2_buckets[0].bucket_name!=='barkive-community-local-media'||config.r2_buckets[0].remote!==false)throw new Error('Media isolation failed');
  exactKeys(config.r2_buckets[0],['binding','bucket_name','remote']);
  if(config.r2_buckets[0].binding!=='PRIVATE_MEDIA')throw new Error('Media binding identity failed');
  if(JSON.stringify(config.durable_objects)!==JSON.stringify({bindings:[{name:'AUTH_MFA_GATES',class_name:'BarkiveIdentityGate'}]}))throw new Error('Local identity actor binding mismatch');
  if(JSON.stringify(config.migrations)!==JSON.stringify([{tag:'identity-gate-v1',new_sqlite_classes:['BarkiveIdentityGate']}]))throw new Error('Local identity actor migration mismatch');
  for(const value of Object.values(config))if(JSON.stringify(value).includes('barkive-translations'))throw new Error('Live archive binding detected');
  return config;
}
export function listFiles(dir) {
  if(lstatSync(dir).isSymbolicLink())throw new Error('Symlinked input directory forbidden');
  return readdirSync(dir).flatMap(name=>{
    const p=resolve(dir,name),s=lstatSync(p);
    if(s.isSymbolicLink())throw new Error('Symlinks are not allowed in release inputs: '+p);
    return s.isDirectory()?listFiles(p):[p];
  });
}
// Current release media formats stay byte-only, including generated WASM.
const binaryAssets=new Set(['.wasm','.webp','.png','.jpg','.jpeg','.avif','.gif','.ico','.woff','.woff2','.ttf','.otf','.mp4','.webm','.mp3','.ogg']);
const sensitiveRules=[
  ['private_key',/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/],
  ['credential_token',/\b(?:sk-proj-|sk-live-|xox[baprs]-)[A-Za-z0-9_-]{12,}/],
  ['bearer_token',/Bearer\s+[A-Za-z0-9._-]{24,}/],
  ['assigned_secret',/\b(?:client_secret|api_key|access_token)\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']/i]
];
const emittedRules=[...sensitiveRules,['local_home_path',/\/Users\/david\b/]];
const prototypeRule=['prototype_marker',/window\.barkiveDemo|social-complete|123456|member=1/];
const isBinaryAsset=name=>binaryAssets.has(extname(name).toLowerCase());

/** Guard the exact public text bytes; review keeps its existing demo controls. */
function checkTextAsset(name, bytes, rules, {rejectPrototype=false}={}) {
  if(isBinaryAsset(name))return;
  const text=typeof bytes==='string'?bytes:Buffer.from(bytes).toString('utf8');
  const rule=rules.find(([,pattern])=>pattern.test(text))??(rejectPrototype&&prototypeRule[1].test(text)?prototypeRule:null);
  if(rule){const error=new Error('Unsafe text asset '+name+' ['+rule[0]+']');error.code='UNSAFE_TEXT_ASSET';error.rule=rule[0];error.asset=name;throw error;}
}
export function assertSafeTextAsset(name, bytes, options) {
  checkTextAsset(name,bytes,emittedRules,options);
}
export function scanFile(path, root, options) {
  const name=relative(root,path);
  if(isBinaryAsset(name))return;
  checkTextAsset(name,readFileSync(path),sensitiveRules,options);
}
