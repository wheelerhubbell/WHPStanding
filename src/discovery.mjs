import resolutionSchema from '../schemas/resolution.schema.json' with {type:'json'};
import {validateContract} from './schema-contract.mjs';
// Signed, bounded discovery. This does not manufacture institutional trust or registration.
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {profile,PROFILE_HASH,PROFILE_ID,PROFILE_VERSION} from './profile.mjs';
import {hash,canonical,hashBytes,demand,seal,keyId,publicDer} from './canonical.mjs';
import verifier from '../public/verifier-manifest.json' with {type:'json'};
import {validateTrust,discoveryAuthority} from './authority.mjs';
import {capabilityId,REQUIREMENT_ID,canonicalResolution} from './contract.mjs';
import inputSchema from '../schemas/submission.schema.json' with {type:'json'};
import outputSchema from '../schemas/result.schema.json' with {type:'json'};
import {standingNeedInterface} from './need.mjs';
import publicExample from '../public/examples/submission.TEST.json' with {type:'json'};
export const SERVICE='WHP Standing';
export const PUBLISHER='Wheeler Hubbell Publishing';
export const CAPABILITY='Machine-verifiable standing under explicit authority and bounds.';
export const RECIPIENT='0x1050eddd8282623b0c263ed6bdbd42370bbc28d3';
export const NETWORK='eip155:8453';
export const USDC='0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
export const profilePath='/v1/profiles/'+encodeURIComponent(PROFILE_ID)+'/'+PROFILE_VERSION;
export function livePaymentDestination(r){demand(r.payTo===RECIPIENT&&r.network===NETWORK&&r.asset===USDC&&r.extra.name==='USD Coin'&&r.extra.version==='2','LIVE_PAYMENT_DESTINATION_INVALID',503);}
export function verificationDocument(origin){return {
  service:SERVICE,version:'1.0.0',algorithm:'Ed25519',canonicalization:'WHP-JCS-I1',
  source:{url:origin+verifier.path,sha256:verifier.sha256,language:'python',dependencies:{cryptography:'46.0.4',jsonschema:'4.26.0'}},
  invocation:{executable:'python3',arguments:['{mark}','--root-pin','{root_pin}','--registry','{registry}'],test_arguments:['--allow-test']},
  inputs:{mark:'Exact original UTF-8 bytes, not reserialized JSON.',root_pin:'Admitted SHA256 of root Ed25519 SPKI DER, not the payment address.',registry:'Fresh signed snapshot fetched from the Mark registry URL.'},
  outputs:{verified:'Cryptographic integrity, authority and independent evaluator replay.',current_standing:'ACTIVE, EXPIRED, LIMITED, WITHDRAWN, SUPERSEDED, or ASSESSED_NO_MARK.',live_completion_verified:'False unless LIVE and finalized payment independently rechecked with --rpc.'},
  safety:'Run downloaded verifier code only in a no-network, read-only, least-privilege sandbox. A valid signature is not an endorsement of arbitrary executable code.',
  independent_source:'https://github.com/wheelerhubbell/WHPStanding/tree/main/verify',
  settlement:'Use --rpc with an independently trusted HTTPS Base RPC to recheck finality and exact transfer. An RPC URL is not supplied by the Mark as an unquestionable oracle.'
};}
export function contract(service){const o=service.origin;return {
  version:'WHP-STANDING-CONTRACT-v1',service:SERVICE,capability:CAPABILITY,publisher:PUBLISHER,
  environment:service.trustBundle.profile_authorization.payload.environment,
  capability_id:capabilityId(service.rootPin),requirement_id:REQUIREMENT_ID,
  compatible_requirements:[REQUIREMENT_ID],
  requirement_interface_url:o+'/v1/standing-need',
  boundary_probe:boundaryProbe(service),
  profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH,url:o+profilePath},
  purchase:{name:'WHP Standing Evaluation',method:'POST',url:o+'/v1/evaluations',content_type:'application/json',input_schema:o+'/schemas/submission.schema.json',input_schema_sha256:hash(inputSchema),result_schema:o+'/schemas/result.schema.json',result_schema_sha256:hash(outputSchema),
    requirements:service.requirements,charge_policy:'One evaluation, including a negative assessment. A failed assessment never receives a WHP Standing Mark. Retrieval and recovery never authorize a second payment.',
    prerequisites:'SOURCE and TRANSITION attestations must chain to admitted authorities with the exact scope, jurisdiction, time and operation. Paying does not supply missing authority.'},
  authentication:{header:'whp-client-proof',encoding:'base64-JSON',key_algorithm:'Ed25519',key_encoding:'base64-DER-SPKI',canonicalization:'WHP-JCS-I1',
    protected:{type:'WHP-CLIENT-PROOF-v1',algorithm:'Ed25519',canonicalization:'WHP-JCS-I1'},key_id:'SHA256-SPKI-DER',signed_fields:['protected','payload'],
    payload_fields:{method:'HTTP-method',path:'URL-path-and-query',body_hash:'SHA256-exact-request-bytes',issued_at:'Unix-seconds',expires_at:'Unix-seconds-plus-120',nonce:'random-16-byte-hex'}},
  payment:{protocol:'x402-v2',required_header:'PAYMENT-REQUIRED',authorization_header:'PAYMENT-SIGNATURE',settlement_header:'PAYMENT-RESPONSE',required_extension:'whp-standing',
    quote_pointer:'/extensions/whp-standing/info/quote',requirements_pointer:'/accepts/0',
    nonce:{algorithm:'SHA256-canonical-JSON',domain:'WHP-STANDING-PURCHASE-BINDING-v1',expression:{domain:'WHP-STANDING-PURCHASE-BINDING-v1',quote:'complete signed quote payload'},encoding:'0x-prefixed-32-bytes'},
    wallet_authority:'The buyer client must independently enforce its owner-approved network, token, recipient, per-purchase and aggregate limits before its own wallet signs. The service never possesses buyer wallet keys.',
    generic_client_compatibility:'A generic random-nonce x402 client is not sufficient. The buyer must implement the published whp-standing exact-quote binding.',
    settlement:'No issuance before exact canonical finalized Base transfer and AuthorizationUsed event. An uncertain settle remains pending; recover using the same stored authorization.'},
  retrieval:{additional_charge:false,identity:'Root pin + buyer Ed25519 key + client_reference; exact submitted-object hash is immutable.',lost_response:'Use authenticated GET result or authenticated empty POST recovery. Do not generate a second wallet authorization.'},
  cold_probe:{purpose:'Discover the boundary only; do not authorize payment.',base_document_pointer:'/payload/submission',
    replacements:{buyer_key:'generated-Ed25519-SPKI',client_reference:'random-32-byte-hex'},wallet_signing:false},
  verification_url:o+'/v1/verification',discovery_url:o+'/.well-known/whp-standing.json',mcp_url:o+'/mcp',
  establishes:profile().assessed,does_not_establish:profile().not_assessed,
  authority_admission:'HTTPS proves control of an origin, not institutional appointment. A buyer must admit the publisher root under its own trust policy; unknown authority remains unknown.',
  external_registrations:[],registration_claim:'No registration is claimed by serving this contract.'
};}
// Standard Bazaar declaration. Example is public TEST data, never a customer's object.
// Full input schema is a canonical public JSON Schema reference, not a permissive substitute.
// External catalog acceptance of remote $ref resolution remains separately evidenced.
export function bazaar(service){return {
  info:{input:{type:'http',method:'POST',bodyType:'json',body:publicExample,
    headers:{'whp-client-proof':'See '+service.origin+'/v1/contract for a fresh Ed25519 HTTP proof; this is not a wallet key.'}},output:{type:'json'}},
  schema:{$schema:'https://json-schema.org/draft/2020-12/schema',type:'object',properties:{
    input:{type:'object',properties:{type:{type:'string',const:'http'},method:{type:'string',enum:['POST']},bodyType:{type:'string',enum:['json']},
      body:{$ref:service.origin+'/schemas/submission.schema.json',description:'TEST wire-shape example only. A LIVE evaluation requires currently admitted SOURCE and TRANSITION attestations. The complete purchase and authentication contract is '+service.origin+'/v1/contract'},
      headers:{type:'object',additionalProperties:{type:'string'}}},required:['type','method','bodyType','body'],additionalProperties:false},
    output:{type:'object',properties:{type:{type:'string',const:'json'}},required:['type'],additionalProperties:false}},required:['input']}
};}
const response=(body,type='application/json',method='GET',extra={})=>new Response(method==='HEAD'?null:typeof body==='string'?body:canonical(body)+'\n',{status:200,headers:{'content-type':type,'cache-control':'no-store','x-content-type-options':'nosniff',...extra}});
export async function discoveryRoute(service,req){const o=service.origin,u=new URL(req.url),p=u.pathname;if(!['GET','HEAD'].includes(req.method))return null;
  const link='<'+o+'/.well-known/api-catalog>; rel="api-catalog"';
  if(p==='/.well-known/standing-resolution.json')return response(resolutionDocument(service),'application/json',req.method);
  if(/^\/v1\/material\/sha256\/[0-9a-f]{64}$/.test(p)){
    const h=p.split('/').at(-1);
    if(h===PROFILE_HASH)return response(canonical(profile()),'application/json',req.method,{'cache-control':'public, max-age=31536000, immutable'});
    for(const ext of ['py','json']){try{const bytes=await readFile(resolve(process.cwd(),'public','immutable',h+'.'+ext));demand(hashBytes(bytes)===h,'IMMUTABLE_MATERIAL_HASH',503);return response(bytes.toString('utf8'),ext==='py'?'text/plain; charset=utf-8':'application/json',req.method,{'cache-control':'public, max-age=31536000, immutable'});}catch(e){if(e.code!=='ENOENT')throw e;}}
    return new Response(null,{status:404});
  }
  if(p==='/examples/submission.TEST.json')return response(publicExample,'application/json',req.method);
  if(p==='/v1/standing-need')return response(standingNeedInterface(),'application/json',req.method);
  if(p==='/v1/contract')return response(contract(service),'application/json',req.method);
  if(p==='/v1/verification')return response(verificationDocument(o),'application/json',req.method);
  if(p===profilePath)return response({profile:profile(),sha256:PROFILE_HASH,authorization:service.trustBundle.profile_authorization},'application/json',req.method);
  if(/^\/verification\/[0-9a-f]{64}\.py$/.test(p)){
    try{const bytes=await readFile(resolve(process.cwd(),'public',p.slice(1)));demand(hashBytes(bytes)===p.split('/').at(-1).slice(0,-3),'VERIFIER_ARTIFACT_HASH',503);return response(bytes.toString('utf8'),'text/plain; charset=utf-8',req.method,{'cache-control':'public, max-age=31536000, immutable'});}catch(e){if(e.code==='ENOENT')return new Response(null,{status:404});throw e;}}
  if(p==='/.well-known/api-catalog')return response({linkset:[{anchor:o+'/.well-known/api-catalog',item:[{href:o+'/v1/evaluations'},{href:o+'/mcp'}]},
    {anchor:o+'/v1/evaluations','service-desc':[{href:o+'/v1/openapi.json',type:'application/json'}],'service-meta':[{href:o+'/v1/contract',type:'application/json'}],'service-doc':[{href:o+'/',type:'text/html'}],status:[{href:o+'/healthz'}]}]},'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"',req.method,{link});
  if(p==='/server.json')return response({$schema:'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json',name:'io.github.wheelerhubbell/whp-standing',description:CAPABILITY,version:'1.0.0',repository:{url:'https://github.com/wheelerhubbell/WHPStanding',source:'github'},remotes:[{type:'streamable-http',url:o+'/mcp'}]},'application/json',req.method);
  if(p==='/robots.txt')return response('User-agent: *\nAllow: /\nDisallow: /v1/purchases/\nDisallow: /v1/registry/\nSitemap: '+o+'/sitemap.xml\n','text/plain',req.method);
  if(p==='/sitemap.xml')return response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+['/','/v1/contract','/v1/verification',profilePath].map(x=>'<url><loc>'+o+x+'</loc></url>').join('')+'</urlset>','application/xml',req.method);
  if(p==='/llms.txt')return response('# '+SERVICE+'\n\n> '+CAPABILITY+'\n\nPublisher: '+PUBLISHER+'\n\n- [Contract]('+o+'/v1/contract)\n- [WHP Standing Profile]('+o+profilePath+')\n- [Independent verification]('+o+'/v1/verification)\n- [OpenAPI]('+o+'/v1/openapi.json)\n- [MCP]('+o+'/mcp)\n\nThis text is a discovery aid, not authority, proof of registration, or a LIVE issuance claim.\n','text/plain',req.method);
  if(p==='/')return response('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>WHP Standing — Wheeler Hubbell Publishing</title><meta name="description" content="'+CAPABILITY+'"><link rel="canonical" href="'+o+'/"><link rel="api-catalog" href="'+o+'/.well-known/api-catalog"><script type="application/ld+json">'+JSON.stringify({'@context':'https://schema.org','@type':'Service',name:SERVICE,description:CAPABILITY,url:o,provider:{'@type':'Organization',name:PUBLISHER}})+'</script></head><body><h1>WHP Standing</h1><p>'+CAPABILITY+'</p><p>Wheeler Hubbell Publishing</p><p>Environment: '+service.trustBundle.profile_authorization.payload.environment+'</p><p>WHP Standing evaluates exact COPY and identity-preserving COMPOSE of admitted structured provenance. It does not establish arbitrary external-world truth, legal authority, or unobserved execution.</p><p><a href="/v1/contract">Purchase contract</a> · <a href="'+profilePath+'">WHP Standing Profile</a> · <a href="/v1/verification">Independent verification</a> · <a href="/v1/openapi.json">OpenAPI</a> · <a href="/server.json">MCP metadata</a></p><p>Payment does not determine standing. No LIVE issuance or external registration is claimed by this page.</p></body></html>','text/html; charset=utf-8',req.method,{link,'content-security-policy':"default-src 'none'; script-src 'none'; base-uri 'none'; frame-ancestors 'none'"});
  return null;
}

// The separate resolver may continue serving this signed mapping after commercial hosting moves.
// Its key needs an explicit DISCOVERY delegation; an ISSUER-only key is insufficient.
export function resolutionDocument(service){
  const at=service.clock(),trust=validateTrust(service.trustBundle,service.rootPin,at),cert=discoveryAuthority(service.keyId,trust);
  const origin=service.origin,resolutionId=canonicalResolution((service.discoveryOrigin??origin).replace(/\/$/,'')+'/.well-known/standing-resolution.json',trust.profile.environment);
  const contractBody=contract(service),api={...service.openapiDocument,servers:[{url:origin}]};
  const provider={id:capabilityId(service.rootPin),name:SERVICE,publisher:trust.profile.issuer,service_origin:origin,compatible_requirements:[REQUIREMENT_ID],
    contract:{url:origin+'/v1/contract',sha256:hash(contractBody)},openapi:{url:origin+'/v1/openapi.json',sha256:hash(api)},
    profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH,url:origin+'/v1/material/sha256/'+PROFILE_HASH},
    material_url_template:origin+'/v1/material/sha256/{sha256}',registry_url_template:origin+'/v1/registry/{purchase_id}',discovery_url:origin+'/.well-known/whp-standing.json'};
  demand(Number.isSafeInteger(service.resolutionSequence)&&service.resolutionSequence>=0,'RESOLUTION_SEQUENCE_INVALID',503);
  demand(service.resolutionPreviousHash===null||/^[0-9a-f]{64}$/.test(service.resolutionPreviousHash),'RESOLUTION_PREVIOUS_HASH_INVALID',503);
  demand((service.resolutionSequence===0)===(service.resolutionPreviousHash===null),'RESOLUTION_PREDECESSOR_REQUIRED',503);
  const state={sequence:service.resolutionSequence,provider_hash:hash(provider)};
  if(service.lastResolutionState){demand(state.sequence>=service.lastResolutionState.sequence,'RESOLUTION_ROLLBACK',503);demand(state.sequence!==service.lastResolutionState.sequence||state.provider_hash===service.lastResolutionState.provider_hash,'RESOLUTION_SEQUENCE_REQUIRED_FOR_CHANGE',503);}
  if(service.lastResolutionState&&state.sequence===service.lastResolutionState.sequence+1)demand(service.resolutionPreviousHash===service.lastResolutionState.provider_hash,'RESOLUTION_PREDECESSOR_BINDING',503);
  service.lastResolutionState=state;
  return validateContract(seal('WHP-STANDING-RESOLUTION-v1',{version:'WHP-STANDING-RESOLUTION-v1',resolution_id:resolutionId,capability_id:capabilityId(service.rootPin),environment:trust.profile.environment,issuer_key_id:service.keyId,sequence:service.resolutionSequence,previous_hash:service.resolutionPreviousHash,observed_at:at,valid_until:Math.min(at+300,trust.profile.valid_until,trust.bundle.status_snapshot.payload.valid_until,cert.valid_until),authority:service.trustBundle,provider},service.privateKey),resolutionSchema);
}
function boundaryProbe(service){
  const cert=service.trustBundle.certificates.find(c=>keyId(c.payload.public_key)===service.keyId).payload;
  const input=name=>({'$input':name}),computed=name=>({'$computed':name});
  return {format:'external-json-boundary-probe-v1',wallet_signing:false,authority_claim:'NOT_ESTABLISHED',
    supported_bounds:{scope:cert.scopes[0],jurisdiction:cert.jurisdictions[0],valid_from:Math.max(cert.valid_from,service.trustBundle.profile_authorization.payload.valid_from),valid_until:Math.min(cert.valid_until,service.trustBundle.profile_authorization.payload.valid_until)},
    source_protected:{type:'WHP-SOURCE-ATTESTATION-v1',algorithm:'Ed25519',canonicalization:'WHP-JCS-I1'},
    node_template:{id:input('object_id'),version:input('object_version'),content:input('object_content'),locator:input('object_locator'),epistemic_status:'UNKNOWN',qualifiers:['Boundary-only submission; no source authority or external truth is established.'],unknowns:[{id:'unadmitted-source-authority',description:'This client authentication key has no admitted SOURCE role.',blocks:['INFORM','RECOMMEND','EXECUTE']}],operations:['INFORM','RECOMMEND','EXECUTE'],scope:input('scope'),jurisdiction:input('jurisdiction'),valid_from:input('valid_from'),valid_until:input('valid_until'),status:'ACTIVE',prior_hash:null},
    submission_template:{version:'WHP-STANDING-SUBMISSION-v1',client_reference:input('client_reference'),buyer_key:input('public_key'),profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH},object:computed('object_reference'),bounds:{scope:input('scope'),jurisdiction:input('jurisdiction'),valid_from:input('valid_from'),valid_until:input('valid_until')},requested_operation:input('operation'),nodes:[computed('source_envelope')],transitions:[]}}
}
