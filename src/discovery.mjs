// Signed, bounded discovery. This does not manufacture institutional trust or registration.
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {profile,PROFILE_HASH,PROFILE_ID,PROFILE_VERSION} from './profile.mjs';
import {hash,canonical,hashBytes,demand} from './canonical.mjs';
import verifier from '../public/verifier-manifest.json' with {type:'json'};
import publicExample from '../public/examples/submission.TEST.json' with {type:'json'};
export const SERVICE='WHP Standing';
export const PUBLISHER='Wheeler Hubbell Publishing';
export const CAPABILITY='Machine-verifiable standing under explicit authority and bounds.';
export const RECIPIENT='0x1050eddd8282623b0c263ed6bdbd42370bbc28d3';
export const NETWORK='eip155:8453';
export const USDC='0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
export const profilePath='/v1/profiles/'+encodeURIComponent(PROFILE_ID)+'/'+PROFILE_VERSION;
export function livePaymentDestination(r){demand(r.payTo===RECIPIENT&&r.network===NETWORK&&r.asset===USDC&&r.extra.name==='USD Coin'&&r.extra.version==='2','LIVE_PAYMENT_DESTINATION_INVALID',503);}
export function carrier(origin,purchaseId,environment){
  return {
    format:'signed-artifact-discovery-v1',service:SERVICE,capability:CAPABILITY,environment,
    publisher:{name:PUBLISHER,relationship:environment==='LIVE'?'Issuer and seller of the WHP Standing Evaluation.':'Intended production publisher only. This TEST artifact is not issued by Wheeler Hubbell Publishing.'},
    meaning:{establishes:profile().assessed,does_not_establish:profile().not_assessed,
      scope_pointer:'/payload/standing/bounds',authority_pointer:'/payload/authority',provenance_pointer:'/payload/submission',limitations_pointer:'/payload/limitations',
      statement:'The exact submitted object meets only the declared Standing Profile checks, at issuance, under its signed authority and bounds. Current standing is separately checked.'},
    service_url:origin,service_id:origin+'/#whp-standing',discovery_url:origin+'/.well-known/whp-standing.json',
    contract_url:origin+'/v1/contract',profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH,url:origin+profilePath},
    registry_url:origin+'/v1/registry/'+purchaseId,
    verification:{url:origin+'/v1/verification',source_url:origin+verifier.path,source_sha256:verifier.sha256,
      algorithm:'Ed25519',canonicalization:'WHP-JCS-I1',signed_fields:['protected','payload'],key_encoding:'base64-DER-SPKI',
      root_pointer:'/root_public_key',pin_pointer:'/root_pin',embedded_root_pointer:'/payload/authority/root_public_key',
      certificates_pointer:'/payload/authority/certificates',certificate_key_pointer:'/payload/public_key',
      trust_rule:'An embedded key cannot appoint itself. Obtain and admit the root pin through the authenticated canonical issuer service or an independently trusted issuer record. HTTPS authenticates an origin, not the legal existence or authority of a company.'},
    purchase:{name:'WHP Standing Evaluation',url:origin+'/v1/evaluations',method:'POST',input_schema:origin+'/schemas/submission.schema.json',payment_protocol:'x402-v2',required_extension:'whp-standing',owner_authorization_required:true},
    links:[{rel:'service-meta',href:origin+'/.well-known/whp-standing.json'},{rel:'service-desc',href:origin+'/v1/openapi.json'},
      {rel:'profile',href:origin+profilePath},{rel:'status',href:origin+'/v1/registry/'+purchaseId},{rel:'api-catalog',href:origin+'/.well-known/api-catalog'}]
  };
}
export function verificationDocument(origin){return {
  service:SERVICE,version:'1.0.0',algorithm:'Ed25519',canonicalization:'WHP-JCS-I1',
  source:{url:origin+verifier.path,sha256:verifier.sha256,language:'python',dependencies:{cryptography:'46.0.4'}},
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
  profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH,url:o+profilePath},
  purchase:{name:'WHP Standing Evaluation',method:'POST',url:o+'/v1/evaluations',content_type:'application/json',input_schema:o+'/schemas/submission.schema.json',result_schema:o+'/schemas/result.schema.json',
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
  if(p==='/examples/submission.TEST.json')return response(publicExample,'application/json',req.method);
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
