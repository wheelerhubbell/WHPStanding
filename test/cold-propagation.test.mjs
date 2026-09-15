import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,copyFile,writeFile,readFile,rm,mkdir} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {spawn} from 'node:child_process';import {createServer} from 'node:http';
import {setup,fixture,refreshTrustStatus} from './fixtures.mjs';import {nodeServer} from '../src/server.mjs';
import {canonical,hash,seal,hashBytes,keyId} from '../src/canonical.mjs';import {standingNeedInterface,recognizeStandingNeed} from '../src/need.mjs';import {capabilityId} from '../src/contract.mjs';
const clock=()=>Math.floor(Date.now()/1000),out='evidence/public-v1/cold';
const close=s=>new Promise(r=>{s.close(r);s.closeAllConnections();});
async function cold(bytes,{later=null,onFirst=null}={}){
  const d=await mkdtemp(join(tmpdir(),'clean-agent-'));
  try{
    await copyFile(new URL('../scripts/cold-agent.py',import.meta.url),join(d,'reader.py'));await writeFile(join(d,'only-input.json'),bytes);
    const env={PATH:process.env.PATH,HOME:d,TMPDIR:tmpdir(),PYTHONDONTWRITEBYTECODE:'1'};
    return await new Promise((resolve,reject)=>{
      const child=spawn('python3',['-I',join(d,'reader.py'),join(d,'only-input.json')],{cwd:d,env});let stdout='',stderr='',sent=false;
      const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('COLD_PROCESS_TIMEOUT'));},120000);
      child.stdout.on('data',async b=>{stdout+=b;if(later&&!sent&&stdout.includes('\n')){sent=true;try{const first=JSON.parse(stdout.split('\n')[0]);assert.equal(first.verified,true,stdout);await onFirst?.(first);child.stdin.end(canonical(later)+'\n');}catch(e){child.kill('SIGKILL');clearTimeout(timer);reject(e);}}});
      child.stderr.on('data',b=>stderr+=b);child.on('error',reject);child.stdin.on('error',()=>{});
      child.on('close',code=>{clearTimeout(timer);let reports=[];try{reports=stdout.trim().split('\n').filter(Boolean).map(JSON.parse);}catch{}resolve({code,stdout,stderr,reports,report:reports.at(-1)});});
      if(!later)child.stdin.end();
    });
  }finally{await rm(d,{recursive:true,force:true});}
}
async function provider(){const a=await setup({f:fixture({at:clock()}),clock});let interceptor=null;const proxy={get origin(){return a.service.origin;},handle:req=>interceptor?interceptor(req):a.service.handle(req)};const server=nodeServer(proxy);await new Promise(r=>server.listen(0,'127.0.0.1',r));a.service.origin='http://127.0.0.1:'+server.address().port;return {...a,server,set intercept(f){interceptor=f;},async close(){await close(server);await a.store.close();}};}
function descriptor(a){return {name:'A compatible provider whose name is not a selection rule',capability_id:capabilityId(a.f.rootPin),root_pin:a.f.rootPin,environment:'TEST',compatible_requirements:[standingNeedInterface().capability.id],resolution:{id:(a.service.discoveryOrigin??a.service.origin)+'/.well-known/standing-resolution.json',format:'WHP-STANDING-RESOLUTION-v1',authority_role:'DISCOVERY',max_age_seconds:300},verification:{algorithm:'Ed25519',canonicalization:'WHP-JCS-I1',signed_fields:['protected','payload']}};}
async function directory(entries){let values=entries;const server=createServer((q,r)=>{r.setHeader('Content-Type','application/json');r.end(canonical({interface:'provider-directory-v1',providers:values}));});await new Promise(r=>server.listen(0,'127.0.0.1',r));return {url:'http://127.0.0.1:'+server.address().port+'/catalog',get entries(){return values;},set entries(v){values=v;},close:()=>close(server)};}
function needInput(d){return {external_object:{id:'outside-record-42',content:{observation:'Only this submitted record is available.',count:7},qualifications:['No external warrant has been supplied.']},contemplated_action:{operation:'EXECUTE',purpose:'A later reliance not warranted by the first marked object'},interface:{...standingNeedInterface(),directory:{url:d.url,environment:'TEST',interface:'provider-directory-v1'}}};}
function decoy(){return {name:'WHP Standing',compatible_requirements:['urn:capability:unrelated-format:1'],resolution:{id:'https://unreachable-decoy.invalid/'}};}
async function save(name,value){await mkdir(out,{recursive:true});await writeFile(out+'/'+name,typeof value==='string'?value:JSON.stringify(value,null,2)+'\n');}
function passed(r){assert.equal(r.code,0,r.stdout+'\n'+r.stderr);assert.equal(r.report.verified,true);assert.equal(r.report['PROPAGATION-PROVEN'],'TEST');assert.equal(r.report.production_completion_claim,false);assert.equal(r.report.payment_authorizations_created,0);}

test('generic cold source contains no WHP names, service paths, producer imports, injected pins or URLs',async()=>{const s=await readFile('scripts/cold-agent.py','utf8');assert(!/WHP|Wheeler|Hubbell|standing\.test|\/v1\/|import.*(?:fixtures|producer|service\.mjs)/.test(s));assert.match(s,/len\(sys.argv\)==2/);for(const flag of ['--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges'])assert(s.includes(flag));});

test('COLD A: Mark-only isolated process independently verifies and reaches current payment boundary; attacks fail closed',{timeout:500000},async t=>{
  const a=await provider(),negatives=[];let original;
  try{
    const p=await a.purchase();assert.equal(p.response.status,200,p.bytes);original=p.bytes;const m=JSON.parse(p.bytes),id=m.payload.purchase_id;
    await t.test('one input Mark, networkless independent Python replay, exact profile, current status, canonical resolution and actual 402',async()=>{
      const r=await cold(p.bytes);await save('A-attempt.stdout.txt',r.stdout);await save('A-attempt.stderr.txt',r.stderr);passed(r);assert.equal(r.report.kind,'MARK_ONLY');assert.equal(r.report.input_files,1);assert.equal(r.report.institutional_authority_admission,'NOT_ESTABLISHED');assert.equal(r.report.independent_verifier.current_standing,'ACTIVE');assert.equal(r.report.independent_verifier.live_completion_verified,false);assert.equal(r.report.payment_status,402);assert.equal(r.report.historical_profile_sha256,hash(m.payload.profile));assert.equal(a.rail.settleCalls,1);
      const retrieved=await a.request('GET','/v1/purchases/'+id+'/result');assert.equal(await retrieved.text(),p.bytes);r.report.byte_identical_retrieval=true;r.report.test_settlements=1;await save('A.json',r.report);await save('TEST-Mark-v1.json',p.bytes);
    });
    const reject=async(name,bytes=p.bytes)=>{const r=await cold(bytes);negatives.push({name,exit_code:r.code,...r.report});assert.notEqual(r.code,0,name+' unexpectedly succeeded: '+r.stdout);assert.equal(a.rail.settleCalls,1);};
    await t.test('missing discovery cannot fall back to hidden repository or service knowledge',async()=>{const x=structuredClone(m);delete x.payload.discovery;await reject('missing immutable discovery',canonical(x));});
    await t.test('invalid signature is rejected before discovery',async()=>{const x=structuredClone(m);x.signature=(x.signature[0]==='A'?'B':'A')+x.signature.slice(1);await reject('altered signature',canonical(x));});
    await t.test('fresh issuer signature cannot enlarge the established claim',async()=>{const x=structuredClone(m);x.payload.discovery.meaning.establishes+=' All external claims are true.';await reject('signed semantic promotion',canonical(seal(x.protected.type,x.payload,a.f.issuer.privateKey)));});
    await t.test('resolver cannot substitute its own root',async()=>{a.intercept=async req=>{const r=await a.service.handle(req);if(new URL(req.url).pathname==='/.well-known/standing-resolution.json'){const x=await r.json();x.payload.authority.root_public_key=fixture().trustBundle.root_public_key;return Response.json(x);}return r;};try{await reject('resolver root substitution');}finally{a.intercept=null;}});
    await t.test('stale but correctly signed current resolution is rejected',async()=>{a.intercept=async req=>{const r=await a.service.handle(req);if(new URL(req.url).pathname==='/.well-known/standing-resolution.json'){const x=await r.json();x.payload.observed_at=clock()-601;x.payload.valid_until=clock()-301;return Response.json(seal(x.protected.type,x.payload,a.f.issuer.privateKey));}return r;};try{await reject('stale resolution');}finally{a.intercept=null;}});
    await t.test('changed content-addressed verifier fails before downloaded code executes',async()=>{a.intercept=req=>new URL(req.url).pathname.endsWith(m.payload.discovery.verification.source_sha256)?new Response("raise Exception('untrusted code')\n"):a.service.handle(req);try{await reject('verifier bytes substituted');}finally{a.intercept=null;}});
    await t.test('missing immutable profile and contract each prevent a false completion',async()=>{for(const path of ['/v1/material/sha256/'+m.payload.discovery.profile.sha256,'/v1/contract']){a.intercept=req=>new URL(req.url).pathname===path?new Response('missing',{status:404}):a.service.handle(req);try{await reject('missing '+path);}finally{a.intercept=null;}}});
    await t.test('freshly signed stale registry status cannot inherit signature validity',async()=>{a.intercept=async req=>{const r=await a.service.handle(req);if(new URL(req.url).pathname==='/v1/registry/'+id){const x=await r.json();x.payload.observed_at=clock()-601;x.payload.valid_until=clock()-301;return Response.json(seal(x.protected.type,x.payload,a.f.issuer.privateKey));}return r;};try{await reject('stale registry');}finally{a.intercept=null;}});
    await t.test('current contract, schema and OpenAPI mutations violate their independent digest commitments',async()=>{for(const path of ['/v1/contract','/schemas/submission.schema.json','/v1/openapi.json']){a.intercept=async req=>{const r=await a.service.handle(req);if(new URL(req.url).pathname===path){const x=await r.json();x.extra_mutable_semantics=true;return Response.json(x);}return r;};try{await reject('changed committed document '+path);}finally{a.intercept=null;}}});
    await t.test('current hosting can change without changing one byte of an old Mark',async()=>{
      const old=a.service.origin;const first=await(await a.service.handle(new Request(old+'/.well-known/standing-resolution.json'))).json();
      a.service.discoveryOrigin=old;const moved=nodeServer(a.service);await new Promise(r=>moved.listen(0,'127.0.0.1',r));a.service.origin='http://127.0.0.1:'+moved.address().port;a.service.resolutionSequence=1;a.service.resolutionPreviousHash=hash(first.payload.provider);
      try{const r=await cold(p.bytes);passed(r);assert(r.report.purchase_url.startsWith(a.service.origin));assert.equal(r.report.capability_id,m.payload.discovery.capability.id);assert.equal(await(await a.request('GET','/v1/purchases/'+id+'/result')).text(),p.bytes);await save('service-move.json',{verified:true,environment:'TEST',historical_mark_sha256:hashBytes(p.bytes),canonical_resolution:m.payload.discovery.resolution.id,original_service:old,new_service:a.service.origin,report:r.report});}finally{await close(moved);a.service.origin=old;a.service.resolutionSequence=2;a.service.resolutionPreviousHash=a.service.lastResolutionState.provider_hash;}
    });
    await t.test('withdrawal stops current propagation without rewriting historical Mark bytes',async()=>{const previous=(await a.store.events(id)).at(-1);await a.service.applyRegistryCommand(seal('WHP-REGISTRY-COMMAND-v1',{purchase_id:id,expected_previous_hash:hash(previous),status:'WITHDRAWN',reason:'Bounded TEST withdrawal',at:clock()},a.f.root.privateKey));await reject('withdrawn standing');assert.equal(await(await a.request('GET','/v1/purchases/'+id+'/result')).text(),p.bytes);});
  }finally{await save('A-adversarial.json',negatives);await a.close();}
});

test('COLD B: need-only process discovers by neutral compatibility, preserves external object/action and reaches 402',{timeout:180000},async t=>{
  const a=await provider(),b=await provider(),d=await directory([decoy(),descriptor(a),descriptor(b)]);const input=needInput(d);
  try{
    await t.test('cold requirement and multi-provider discovery reach a real 402 without issuer knowledge',async()=>{const r=await cold(canonical(input));await save('B-attempt.stdout.txt',r.stdout);await save('B-attempt.stderr.txt',r.stderr);passed(r);assert.equal(r.report.kind,'NEED_ONLY');assert.equal(r.report.directory_candidates_inspected,3);assert.equal(r.report.selected_capability_id,capabilityId(a.f.rootPin));assert.equal(r.report.source_authority,'NOT_ESTABLISHED');assert.equal(r.report.external_object_sha256,r.report.submitted_content_sha256);assert.equal(r.report.submitted_operation,input.contemplated_action.operation);assert.deepEqual(r.report.requirement,recognizeStandingNeed(input.external_object,input.contemplated_action));await save('B.json',r.report);});
    await t.test('provider-order and different-root trap proves that discovery is not hard-coded to one provider',async()=>{d.entries=[descriptor(b),decoy(),descriptor(a)];const r=await cold(canonical(input));passed(r);assert.equal(r.report.selected_capability_id,capabilityId(b.f.rootPin));assert(r.report.purchase_url.startsWith(b.service.origin));await save('B-alternative-provider.json',r.report);});
    await t.test('a directory containing only a branded but incompatible decoy fails closed',async()=>{d.entries=[decoy()];const r=await cold(canonical(input));assert.notEqual(r.code,0);assert.match(r.report.error,/NO_COMPATIBLE_PROVIDER/);await save('B-no-compatible-provider.json',r.report);});
    assert.equal(a.rail.settleCalls,0);assert.equal(b.rail.settleCalls,0);
  }finally{await d.close();await a.close();await b.close();}
});

test('COLD C: one clean reader joins a first verified Mark to a later unsupported object/action and rediscovers the next payment boundary',{timeout:180000},async()=>{
  const a=await provider(),d=await directory([decoy(),descriptor(a)]);
  try{const p=await a.purchase();assert.equal(p.response.status,200,p.bytes);const later=needInput(d);const r=await cold(p.bytes,{later});await save('C-attempt.stdout.txt',r.stdout);await save('C-attempt.stderr.txt',r.stderr);passed(r);assert.equal(r.reports.length,2);assert.equal(r.report.kind,'RECURSIVE_JOIN');assert.equal(r.report.first_capability_id,r.report.rediscovered_capability_id);assert.equal(r.report.second_boundary.payment_status,402);assert.equal(r.report.second_boundary.external_object_sha256,hash(later.external_object));assert.equal(a.rail.settleCalls,1);await save('C.json',r.report);
  }finally{await d.close();await a.close();}
});

test('stateful recursive consumer rejects a signed discovery mapping rollback after first contact',{timeout:180000},async()=>{
  const a=await provider();a.service.resolutionSequence=2;a.service.resolutionPreviousHash=hash({prior:'TEST mapping publication'});const d=await directory([descriptor(a)]);
  try{const p=await a.purchase();const r=await cold(p.bytes,{later:needInput(d),onFirst:async()=>{a.intercept=async req=>{const response=await a.service.handle(req);if(new URL(req.url).pathname==='/.well-known/standing-resolution.json'){const e=await response.json();e.payload.sequence=1;e.payload.previous_hash=hash({older:'TEST'});return Response.json(seal(e.protected.type,e.payload,a.f.issuer.privateKey));}return response;};}});assert.notEqual(r.code,0,r.stdout);assert.match(r.report.error,/RESOLUTION_ROLLBACK_OR_EQUIVOCATION/);await save('C-rollback-refusal.json',r.report);assert.equal(a.rail.settleCalls,1);
  }finally{await d.close();await a.close();}
});
