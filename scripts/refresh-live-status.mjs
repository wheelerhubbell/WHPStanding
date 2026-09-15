// Refresh only the existing root-signed status epoch; never rotate or enlarge authority.
import {readFile,writeFile} from 'node:fs/promises';
import {canonical,parseStrict,seal,hash,demand,keyId,publicDer} from '../src/canonical.mjs';
import {validateTrust} from '../src/authority.mjs';
const SITE='914e2d6d-ec82-4b03-aa58-785fcf3b453b',ACCOUNT='6aa6fb2da06f6afa962eee67',PREFIX='/accounts/'+ACCOUNT+'/env';
async function api(path,method='GET',body){const r=await fetch('https://api.netlify.com/api/v1'+path,{method,headers:{Authorization:'Bearer '+process.env.NETLIFY_AUTH_TOKEN,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(30000)});demand(r.ok,'STATUS_CUSTODY_HTTP_'+r.status);return r.status===204?null:r.json();}
const value=(e,c)=>e?.values?.find(v=>v.context===c)?.value;
try{
 const vars=await api(PREFIX+'?site_id='+SITE),record=vars.find(e=>e.key==='WHP_AUTHORITY_CUSTODY_V1');
 demand(record?.values.every(v=>v.context==='dev'),'ROOT_CONTEXT_INVALID');
 const saved=parseStrict(value(record,'dev')),a=saved.authority,c=saved.custody,now=Math.floor(Date.now()/1000);
 const pub=parseStrict(await readFile('public/authority/root.json','utf8'));
 demand(keyId(publicDer(c.root_private_key))===a.root_pin&&a.root_pin===pub.root_pin,'ROOT_IDENTITY_CHANGED');
 const b=a.bundle,prior=b.status_snapshot;
 // Validate the old epoch at its own valid time; expired current state remains fail-closed until replacement is deployed.
 validateTrust(b,a.root_pin,Math.max(prior.payload.valid_from,Math.min(now,prior.payload.valid_until-1)));
 const until=Math.min(now+86400,b.profile_authorization.payload.valid_until,...b.certificates.map(e=>e.payload.valid_until));
 demand(until>now+3600,'AUTHORITY_RENEWAL_REQUIRED');
 if(prior.payload.valid_until<now+64800){
 b.status_snapshot=seal('WHP-TRUST-STATUS-v1',{...prior.payload,sequence:prior.payload.sequence+1,previous_hash:hash(prior),valid_from:now-30,valid_until:until},c.root_private_key);
 validateTrust(b,a.root_pin,now);
 // Persist first; an interrupted retry resumes the same epoch and identity.
 await api(PREFIX+'/WHP_AUTHORITY_CUSTODY_V1?site_id='+SITE,'PUT',{key:'WHP_AUTHORITY_CUSTODY_V1',values:[{context:'dev',value:canonical(saved)}]});
 }
 validateTrust(b,a.root_pin,now);
 await api(PREFIX+'/WHP_TRUST_BUNDLE_JSON?site_id='+SITE,'PUT',{key:'WHP_TRUST_BUNDLE_JSON',values:[{context:'production',value:canonical(b)}]});
 const back=await api(PREFIX+'?site_id='+SITE);
 demand(hash(parseStrict(value(back.find(e=>e.key==='WHP_TRUST_BUNDLE_JSON'),'production')))===hash(b),'STATUS_READBACK_MISMATCH');
 pub.trust_bundle=b;
 await writeFile('public/authority/root.json',canonical(pub)+'\n');
 await writeFile('public/authority/trust-bundle.json',canonical(b)+'\n');
 await writeFile('evidence/live-authority/status-refresh.json',JSON.stringify({checked_at:new Date().toISOString(),root_pin:a.root_pin,status_sequence:b.status_snapshot.payload.sequence,previous_hash:b.status_snapshot.payload.previous_hash,valid_until:b.status_snapshot.payload.valid_until,root_rotated:false,profile_changed:false,certificates_changed:false,payment_executed:false},null,2)+'\n');
 console.log('EXISTING_ROOT_STATUS_REFRESH_VERIFIED');
}catch(e){console.error(e.code??'STATUS_REFRESH_FAILED');process.exitCode=1;}
