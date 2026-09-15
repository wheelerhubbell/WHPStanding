import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {AUTHORIZATION,newCustody,establish,verifyAuthority,authorityNegativeProof} from '../scripts/authority-core.mjs';
import {validateTrust} from '../src/authority.mjs';
import {clone,seal,hash} from '../src/canonical.mjs';
import {fixture,NOW} from './fixtures.mjs';

// Ephemeral authority fixtures. These keys are never WHP's production identity.
test('authority ceremony uses exact canonical contracts and requires the authorized act',()=>{
  const c=newCustody(NOW);assert.throws(()=>establish(c,'',NOW),/EXPLICIT_AUTHORIZATION_REQUIRED/);
  const a=establish(c,AUTHORIZATION,NOW);assert(verifyAuthority(a.bundle,a.root_pin,c.issuer_private_key,NOW).issuer_and_registry_roles_verified);
  assert.equal(authorityNegativeProof(a.bundle,a.root_pin,c.issuer_private_key,NOW).length,6);
  assert.equal(establish(c,AUTHORIZATION,NOW).root_pin,a.root_pin);
});

test('TEST authority cannot become institutional LIVE through relabeling or its own root signature',()=>{
  const f=fixture(),c=newCustody(NOW),a=establish(c,AUTHORIZATION,NOW),b=clone(f.trustBundle);
  b.profile_authorization.payload.environment='LIVE';assert.throws(()=>validateTrust(b,f.rootPin,NOW));
  b.profile_authorization=seal('WHP-PROFILE-AUTHORIZATION-v1',{...b.profile_authorization.payload,issuer:'Wheeler Hubbell Publishing'},f.root.privateKey);
  b.status_snapshot=seal('WHP-TRUST-STATUS-v1',{...b.status_snapshot.payload,profile_authorization_hash:hash(b.profile_authorization)},f.root.privateKey);
  assert.throws(()=>validateTrust(b,a.root_pin,NOW),/UNTRUSTED_ROOT/);
});

test('independent Python authority verifier and published trust schema accept canonical ceremony',async()=>{
  const c=newCustody(NOW),a=establish(c,AUTHORIZATION,NOW),dir=await mkdtemp(join(tmpdir(),'authority-proof-'));
  try{const file=join(dir,'public.json');await writeFile(file,JSON.stringify(a));
    const code="import sys,json;sys.path.insert(0,'verify');import verify_mark as v;from jsonschema import Draft202012Validator;a=json.load(open(sys.argv[1]));b=a['bundle'];pa,keys,rev=v.trust(b,a['root_pin'],int(sys.argv[2]));assert pa['environment']=='LIVE';assert {'ISSUER','REGISTRY'}.issubset(keys[a['issuer_key_id']]['roles']);v.unseal(a['act'],'WHP-AUTHORITY-ESTABLISHMENT-v1',b['root_public_key']);Draft202012Validator(json.load(open('schemas/trust-bundle.schema.json'))).validate(b);print('INDEPENDENT_AUTHORITY_AND_SCHEMA_VERIFIED')";
    const r=spawnSync('python3',['-c',code,file,String(NOW)],{encoding:'utf8'});assert.equal(r.status,0,r.stdout+r.stderr);
  }finally{await rm(dir,{recursive:true,force:true});}
});
