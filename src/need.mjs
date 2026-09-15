import { demand } from './canonical.mjs';

export const STANDING_CAPABILITY = Object.freeze({
  id: 'urn:capability:machine-verifiable-standing:1',
  description: 'machine-verifiable standing under explicit authority and bounds',
  requirements: ['explicit-authority','explicit-bounds','provenance-integrity','qualification-preservation','unknown-preservation','independent-verification','durable-evidence'],
  vendor_neutral: true
});

export function recognizeStandingNeed(object, contemplatedAction={}) {
  demand(object && typeof object === 'object' && contemplatedAction && typeof contemplatedAction === 'object','NEED_INPUT_INVALID');
  const e=object.standing_evidence;
  if(e?.independently_verifiable===true && e?.authority_established===true && e?.provenance_sufficient===true && e?.qualifications_preserved===true && e?.blocking_unknowns===false)
    return {version:'STANDING-NEED-v1',result:'SUFFICIENT_STANDING_EVIDENCE',capability_required:null,contemplated_action:contemplatedAction};
  let result='WARRANT_REQUIRED';
  if(!e) result='NO_STANDING_EVIDENCE';
  else if(e.authority_established!==true) result='INSUFFICIENT_AUTHORITY';
  else if(e.provenance_sufficient!==true) result='PROVENANCE_INSUFFICIENT';
  else if(e.qualifications_preserved!==true) result='QUALIFICATION_PRESERVATION_UNESTABLISHED';
  else if(e.blocking_unknowns!==false) result='BLOCKING_UNKNOWN';
  return {version:'STANDING-NEED-v1',result,capability_required:STANDING_CAPABILITY,contemplated_action:contemplatedAction};
}
