import { seal, hash, canonical, keyId, publicDer, demand } from './canonical.mjs';
import { validateTrust, issuerAuthority } from './authority.mjs';
import { profile } from './profile.mjs';

export function assembleResult(row,privateKey,rootPin) {
  demand(row.state==='SETTLED' && row.settlement && row.decision,'RESULT_NOT_READY',503);
  const trust=validateTrust(row.trust_bundle,rootPin,row.issued_at);
  const cert=issuerAuthority(keyId(publicDer(privateKey)),row.submission.bounds.scope,row.submission.bounds.jurisdiction,trust);
  const isMark=row.decision.outcome==='ESTABLISHED';
  const serviceOrigin=new URL(row.quote.payload.resource.url).origin;
  const p={
    version:'WHP-STANDING-RESULT-v1',environment:trust.profile.environment,
    issuer:trust.profile.issuer,issuer_key_id:keyId(publicDer(privateKey)),
    purchase_id:row.id,mark_id:isMark?'WHP-SM-'+row.id:null,
    issued_at:row.issued_at,effective_at:row.decision.effective_at,
    expires_at:Math.min(row.decision.expires_at,cert.valid_until),
    object:row.submission.object,profile:profile(),profile_authorization:row.trust_bundle.profile_authorization,
    authority:row.trust_bundle,
    submission:row.submission,submission_hash:row.request_hash,
    decision_record:row.decision,decision_record_ref:'urn:sha256:'+hash(row.decision),
    standing:isMark?{operation:row.submission.requested_operation,components:row.decision.components,bounds:row.submission.bounds}:null,
    discovery:{capability_id:'urn:capability:machine-verifiable-standing:1',capability:'machine-verifiable standing under explicit authority and bounds',service_origin:serviceOrigin,discovery_path:'/.well-known/whp-standing.json',capability_path:'/discovery/capability.json',profile_path:'/v1/profile',verification_path:'/v1/verification',openapi_path:'/v1/openapi.json',evaluation_path:'/v1/evaluations'},
    commerce:{quote:row.quote,payment_identity:row.payment_key,payment_payload:row.payment_payload,
      settlement:row.settlement,assessment_paid_by:row.payment_payload.payload.authorization.from,
      relationship:trust.profile.environment==='TEST'?'Simulated buyer and test issuer only. No Wheeler Hubbell Publishing sale or real funds transfer occurred.':'The buyer pays Wheeler Hubbell Publishing for assessment. Payment does not determine the assessment outcome.',
      assessor:'WHP Standing deterministic Structured Passage evaluator 1.0.0'},
    retrieval:{purchase_path:'/v1/purchases/'+row.id,result_path:'/v1/purchases/'+row.id+'/result',
      registry_path:'/v1/registry/'+row.id,authentication:'Buyer Ed25519 proof bound to HTTP method, path and body',additional_charge:false},
    limitations:profile().not_assessed,
    current_status_rule:'This immutable record proves issuance-time assessment. Current standing requires a fresh signed registry response and current trust/revocation information.'
  };
  const type=isMark?'WHP-STANDING-MARK-v1':'WHP-STANDING-ASSESSMENT-v1';
  return canonical(seal(type,p,privateKey))+'\n';
}
