import {hash,keyId,exact,demand} from './canonical.mjs';
import {profile,PROFILE_HASH,PROFILE_ID,PROFILE_VERSION} from './profile.mjs';
import verifier from '../public/verifier-manifest.json' with {type:'json'};
export const REQUIREMENT_ID='urn:capability:machine-verifiable-standing:1';
export const capabilityId=pin=>'urn:whp:standing:v1:'+pin;
export const CURRENT_STATUS_RULE='This immutable record proves issuance-time assessment. Current standing requires a fresh signed registry response and current trust/revocation information.';
export const ASSESSOR='WHP Standing deterministic Structured Passage evaluator 1.0.0';
export const commerceRelationship=env=>env==='TEST'?'Simulated buyer and test issuer only. No Wheeler Hubbell Publishing sale or real funds transfer occurred.':'The buyer pays Wheeler Hubbell Publishing for assessment. Payment does not determine the assessment outcome.';
export const attribution=env=>env==='TEST'?'TEST key identity only; not institutional WHP issuance.':'Institutional attribution requires independently admitted root authority.';
export const PAYLOAD_FIELDS=['version','environment','issuer','issuer_key_id','purchase_id','mark_id','issued_at','effective_at','expires_at','object','profile','profile_authorization','authority','submission','submission_hash','decision_record','decision_record_ref','standing','commerce','retrieval','limitations','discovery','current_status_rule'];
export function canonicalResolution(url,environment){
  demand(typeof url==='string' && url.length<=4096,'RESOLUTION_ID_REQUIRED',503);
  let u;try{u=new URL(url);}catch{demand(false,'RESOLUTION_ID_INVALID',503);}
  demand(u.href===url && /^[\x21-\x7e]+$/.test(url) && u.pathname==='/.well-known/standing-resolution.json' && !u.username&&!u.password&&!u.search&&!u.hash && (u.protocol==='https:' || (environment==='TEST'&&u.protocol==='http:'&&u.hostname==='127.0.0.1')),'RESOLUTION_ID_INVALID',503);
  return url;
}
export function immutableDiscovery(p,resolutionId){
  const pin=keyId(p.authority.root_public_key),established=p.decision_record.outcome==='ESTABLISHED';
  return {
    format:'signed-artifact-discovery-v1',
    artifact:{name:established?'WHP Standing Mark v1':'WHP Standing Assessment v1',contract:'WHP-STANDING-RESULT-v1',historical:true},
    issuer:{id:'urn:sha256:'+pin,name:p.issuer,root_pin:pin,institutional_attribution:attribution(p.environment)},
    capability:{id:capabilityId(pin),requirement_id:REQUIREMENT_ID},
    meaning:{determination:p.decision_record.outcome,establishes:established?profile().assessed:'No standing established. See the signed negative decision record.',does_not_establish:profile().not_assessed,
      claim_pointer:'/payload/decision_record',bounds_pointer:'/payload/submission/bounds',authority_pointer:'/payload/authority',provenance_pointer:'/payload/submission',qualifications_pointer:'/payload/submission/nodes',unknowns_pointer:'/payload/decision_record/unknowns',limitations_pointer:'/payload/limitations'},
    profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH,embedded_pointer:'/payload/profile'},
    resolution:{id:canonicalResolution(resolutionId,p.environment),format:'WHP-STANDING-RESOLUTION-v1',authority_role:'DISCOVERY',max_age_seconds:300},
    verification:{algorithm:'Ed25519',canonicalization:'WHP-JCS-I1',signed_fields:['protected','payload'],key_encoding:'base64-DER-SPKI',embedded_root_pointer:'/payload/authority/root_public_key',certificates_pointer:'/payload/authority/certificates',certificate_key_pointer:'/payload/public_key',source_sha256:verifier.sha256,source_id:'urn:sha256:'+verifier.sha256,
      invocation:{arguments:['{mark}','--root-pin','{root_pin}','--registry','{registry}'],test_arguments:['--allow-test']}},
    status:{type:'WHP-REGISTRY-SNAPSHOT-v1',requires_fresh:true,max_age_seconds:300}
  };
}
export function assertResultContract(p){
  exact(p,PAYLOAD_FIELDS);
  demand(p.version==='WHP-STANDING-RESULT-v1'&&hash(p.profile)===PROFILE_HASH,'PUBLIC_V1_PROFILE_BINDING',503);
  demand(hash(p.discovery)===hash(immutableDiscovery(p,p.discovery.resolution.id)),'PUBLIC_V1_DISCOVERY_BINDING',503);
  demand(p.current_status_rule===CURRENT_STATUS_RULE && p.commerce.relationship===commerceRelationship(p.environment) && p.commerce.assessor===ASSESSOR,'PUBLIC_V1_SEMANTIC_TEXT',503);
}
