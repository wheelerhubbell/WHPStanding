import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { recognizeStandingNeed } from '../src/need.mjs';
const read=p=>JSON.parse(fs.readFileSync(p));

test('cold agent recognizes vendor-neutral missing capability and finds compatible provider metadata',()=>{
  const need=recognizeStandingNeed({provenance:{present:true}},{operation:'EXECUTE'});
  assert.equal(need.result,'NO_STANDING_EVIDENCE');
  assert.equal(need.capability_required.vendor_neutral,true);
  const index=read('public/discovery/provider-index.json');
  const provider=index.providers.find(p=>p.description===need.capability_required.description);
  assert(provider);
  const capability=read('public'+provider.capability);
  assert.equal(capability.capability.id,need.capability_required.id);
  assert.equal(capability.evaluation.path,'/v1/evaluations');
  assert.equal(capability.commerce.protocol,'x402-v2');
  assert.equal(capability.commerce.network,'eip155:8453');
});

test('provider index is open rather than WHP-required',()=>{
  const index=read('public/discovery/provider-index.json');
  assert.equal(index.open_provider_model,true);
  assert.equal(index.capability,'urn:capability:machine-verifiable-standing:1');
});
