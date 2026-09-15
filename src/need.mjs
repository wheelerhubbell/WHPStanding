import {demand,hash} from './canonical.mjs';
export const STANDING_CAPABILITY=Object.freeze({id:'urn:capability:machine-verifiable-standing:1',description:'machine-verifiable standing under explicit authority and bounds',requirements:['explicit-authority','explicit-bounds','provenance-integrity','qualification-preservation','unknown-preservation','independent-verification','durable-evidence'],vendor_neutral:true});
export const NEED_VOCABULARY=Object.freeze(['NO_STANDING_EVIDENCE','PROVENANCE_INSUFFICIENT','TRANSFORMATION_WARRANT_MISSING','INSUFFICIENT_AUTHORITY','QUALIFICATION_PRESERVATION_UNESTABLISHED','BLOCKING_UNKNOWN','INDEPENDENTLY_VERIFIABLE_WARRANT_REQUIRED']);
// Input assertions are observations to assess, not an independently verified result.
// This requirement function neither selects a vendor nor grants standing.
export function recognizeStandingNeed(object,contemplatedAction={}){
  demand(object&&typeof object==='object'&&contemplatedAction&&typeof contemplatedAction==='object','NEED_INPUT_INVALID');
  const e=object.standing_evidence;let result=e==null?'NO_STANDING_EVIDENCE':'INDEPENDENTLY_VERIFIABLE_WARRANT_REQUIRED';
  if(e&&typeof e==='object'){
    for(const [key,missing] of [['authority_established','INSUFFICIENT_AUTHORITY'],['provenance_sufficient','PROVENANCE_INSUFFICIENT'],['transformation_warrant_established','TRANSFORMATION_WARRANT_MISSING'],['qualifications_preserved','QUALIFICATION_PRESERVATION_UNESTABLISHED']])if(e[key]!==true){result=missing;break;}
    if(e.blocking_unknowns!==false)result='BLOCKING_UNKNOWN';
  }
  return {version:'STANDING-NEED-v1',result,capability_required:STANDING_CAPABILITY,object_sha256:hash(object),contemplated_action:contemplatedAction,action_sha256:hash(contemplatedAction)};
}
export function standingNeedInterface(){return {version:'STANDING-NEED-v1',vendor_neutral:true,vocabulary:NEED_VOCABULARY,capability:STANDING_CAPABILITY,directory_interface:'provider-directory-v1',provider_authority_role:'DISCOVERY',authority_admission:'Directory membership identifies a candidate. It does not confer institutional trust or prove standing.'};}
