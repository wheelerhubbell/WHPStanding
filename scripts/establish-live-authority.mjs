// Deliberate production mutation. Entry point is the authorization-gated workflow.
// Secrets exist only in memory and in authenticated Netlify environment custody.
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {canonical,parseStrict,demand,hash,publicDer,keyId} from '../src/canonical.mjs';
import {AUTHORIZATION,ORIGIN,newCustody,establish,verifyAuthority,authorityNegativeProof} from './authority-core.mjs';
const SITE='914e2d6d-ec82-4b03-aa58-785fcf3b453b';
const ACCOUNT='6aa6fb2da06f6afa962eee67';
const PREFIX='/accounts/'+ACCOUNT+'/env';
const DIR='evidence/live-authority';
const token=process.env.NETLIFY_AUTH_TOKEN;
demand(token,'NETLIFY_AUTH_TOKEN_REQUIRED');
demand(process.env.AUTHORIZATION_TEXT===AUTHORIZATION,'EXPLICIT_AUTHORIZATION_REQUIRED');
async function api(path,{method='GET',body}={}){
  const r=await fetch('https://api.netlify.com/api/v1'+path,{method,headers:{Authorization:'Bearer '+token,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(30000)});
  if(!r.ok)console.error('NETLIFY_OPERATION_FAILED',method,path.split('?')[0],r.status);
  demand(r.ok,'NETLIFY_HTTP_'+r.status,503);return r.status===204?null:r.json();
}
const value=(e,context)=>e?.values?.find(v=>v.context===context)?.value;
async function put(key,data,context='production',secret=false){
  // Standard encrypted environment storage is supported on this account.
  // Optional Secrets Controller requires unavailable granular scopes.
  // Explicit deploy contexts keep the root out of production.
  const body={key,values:[{context,value:data}]};
  const vars=await api(PREFIX+'?site_id='+SITE);
  return vars.some(e=>e.key===key)?api(PREFIX+'/'+key+'?site_id='+SITE,{method:'PUT',body}):api(PREFIX+'?site_id='+SITE,{method:'POST',body:[body]});
}
try{
  const site=await api('/sites/'+SITE);demand(site.name==='whpstanding'&&site.ssl_url===ORIGIN,'CANONICAL_SITE_MISMATCH');
  let vars=await api(PREFIX+'?site_id='+SITE),record=vars.find(e=>e.key==='WHP_AUTHORITY_CUSTODY_V1');
  let saved,reused=false;
  if(record){demand(record.values.every(v=>v.context==='dev'),'ROOT_CUSTODY_CONTEXT_VIOLATION');demand(value(record,'dev'),'ROOT_CUSTODY_UNREADABLE');saved=parseStrict(value(record,'dev'),1048576);reused=true;}
  else{
    demand(!vars.some(e=>['WHP_ROOT_PIN','WHP_ISSUER_PRIVATE_KEY','WHP_TRUST_BUNDLE_JSON'].includes(e.key)),'EXISTING_AUTHORITY_REQUIRES_RECONCILIATION');
    const at=Math.floor(Date.now()/1000),custody=newCustody(at),authority=establish(custody,AUTHORIZATION,at);
    saved={custody,authority};
    // Save BEFORE publishing any identity; a partial run must recover, never rotate.
    await put('WHP_AUTHORITY_CUSTODY_V1',canonical(saved),'dev',true);
    vars=await api(PREFIX+'?site_id='+SITE);record=vars.find(e=>e.key==='WHP_AUTHORITY_CUSTODY_V1');
    demand(record&&record.values.every(v=>v.context==='dev'),'ROOT_CUSTODY_ISOLATION_NOT_ACCEPTED');
    const back=parseStrict(value(record,'dev'),1048576);
    demand(keyId(publicDer(back.custody.root_private_key))===authority.root_pin&&keyId(publicDer(back.custody.issuer_private_key))===authority.issuer_key_id,'CUSTODY_READBACK_MISMATCH');saved=back;
  }
  const {custody,authority:a}=saved,now=Math.floor(Date.now()/1000);
  demand(keyId(publicDer(custody.root_private_key))===a.root_pin,'ROOT_PRIVATE_PUBLIC_MISMATCH');
  try{const prior=parseStrict(await readFile(DIR+'/public-authority.json','utf8'),1048576);demand(prior.root_pin===a.root_pin,'ROOT_REPLACEMENT_NOT_AUTHORIZED');}catch(e){if(e.code!=='ENOENT')throw e;}
  const proof=verifyAuthority(a.bundle,a.root_pin,custody.issuer_private_key,now),negatives=authorityNegativeProof(a.bundle,a.root_pin,custody.issuer_private_key,now);
  await mkdir(DIR,{recursive:true});await mkdir('public/authority',{recursive:true});
  const publicObject={version:'WHP-PUBLIC-AUTHORITY-v1',canonical_origin:ORIGIN,root_pin:a.root_pin,root_public_key:a.bundle.root_public_key,issuer_key_id:a.issuer_key_id,
    authorization_act:a.act,trust_bundle:a.bundle,profile:a.act.payload.profile,
    pinning:'Admit this root fingerprint through an independently authenticated Wheeler Hubbell Publishing origin or trusted issuer record. Embedded certificates do not appoint their own root.',
    custody:'Root and recovery material: authenticated, encrypted Netlify environment variable, dev context only; never production runtime. Production issuer: encrypted production environment value. Optional Secrets Controller is not enabled; authorized account API access can read values. This is provider-managed software key custody, not offline or hardware custody.'};
  await writeFile(DIR+'/public-authority.json',canonical(publicObject)+'\n');
  await writeFile('public/authority/root.json',canonical(publicObject)+'\n');
  await writeFile('public/authority/trust-bundle.json',canonical(a.bundle)+'\n');
  const python="import sys,json;sys.path.insert(0,'verify');import verify_mark as v;from jsonschema import Draft202012Validator;a=json.load(open(sys.argv[1]));b=a['trust_bundle'];pa,keys,rev=v.trust(b,a['root_pin'],int(sys.argv[2]));assert pa['environment']=='LIVE' and pa['issuer']=='Wheeler Hubbell Publishing';assert {'ISSUER','REGISTRY'}.issubset(keys[a['issuer_key_id']]['roles']);v.unseal(a['authorization_act'],'WHP-AUTHORITY-ESTABLISHMENT-v1',b['root_public_key']);Draft202012Validator(json.load(open('schemas/trust-bundle.schema.json'))).validate(b);print('INDEPENDENT_PRODUCTION_AUTHORITY_AND_SCHEMA_VERIFIED')";
  const r=spawnSync('python3',['-c',python,DIR+'/public-authority.json',String(now)],{encoding:'utf8',timeout:30000});
  demand(r.status===0,'INDEPENDENT_PRODUCTION_AUTHORITY_PROOF_FAILED',503);
  await put('WHP_ORIGIN',ORIGIN);await put('WHP_ROOT_PIN',a.root_pin);
  await put('WHP_TRUST_BUNDLE_JSON',canonical(a.bundle));
  await put('WHP_ISSUER_PRIVATE_KEY',custody.issuer_private_key,'production',true);
  vars=await api(PREFIX+'?site_id='+SITE);
  demand(value(vars.find(e=>e.key==='WHP_ROOT_PIN'),'production')===a.root_pin,'PIN_CONFIGURATION_READBACK_FAILED');
  demand(hash(parseStrict(value(vars.find(e=>e.key==='WHP_TRUST_BUNDLE_JSON'),'production'),1048576))===hash(a.bundle),'TRUST_CONFIGURATION_READBACK_FAILED');
  const issuer=vars.find(e=>e.key==='WHP_ISSUER_PRIVATE_KEY');demand(issuer&&issuer.values.every(v=>v.context==='production'),'ISSUER_SECRET_CONTEXT_NOT_ACCEPTED');
  const production=await api(PREFIX+'?site_id='+SITE+'&context_name=production&scope=functions');
  const rootEntry=production.find(e=>e.key==='WHP_AUTHORITY_CUSTODY_V1');
  demand(!rootEntry||!rootEntry.values.some(v=>['all','production'].includes(v.context)),'ROOT_PRESENT_IN_PRODUCTION_CONTEXT');
  const report={version:'WHP-AUTHORITY-CEREMONY-PROOF-v1',verified_at:new Date().toISOString(),source_commit:process.env.GITHUB_SHA,run_id:process.env.GITHUB_RUN_ID,
    authority_state:'VERIFIED',service_live:false,root_pin:a.root_pin,issuer_key_id:a.issuer_key_id,profile:a.act.payload.profile,
    existing_identity_reused:reused,canonical_primitives:'src/canonical.mjs seal/publicDer/keyId/hash; src/authority.mjs validateTrust/issuerAuthority/authorize',
    production_verifier:proof,independent_python_authority_verified:true,published_schema_validated:true,negative_proofs:negatives,
    secret_custody_readback_verified:true,root_excluded_from_production_context:true,issuer_production_context_accepted:true,secrets_controller_enabled:false,
    private_keys_committed:false,private_keys_uploaded_as_artifacts:false,private_keys_printed:false,
    trust_status_valid_until:a.bundle.status_snapshot.payload.valid_until,automatic_trust_refresh_established:false,
    payment_authorized:false,payment_settled:false,live_mark_issued:false,
    remaining:'Production database, rail readiness, deployment, and public execution must be independently established; authority proof alone is not a LIVE service.'};
  await writeFile(DIR+'/verification.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
}catch(e){console.error('AUTHORITY_CEREMONY_FAILED',e.code??'SAFE_INTERNAL_FAILURE');process.exitCode=1;}
