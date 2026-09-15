"""Build inspectable schemas from the frozen v1 wire contract, not runtime inference."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROFILE=json.loads((ROOT/'profiles/structured-passage-1.0.0.json').read_text())
H='dc25aa63cadad8b5b02ba3cbaac552ca8273c6d6793b4eefdef16aadd180046e'
def ref(n):return {'$ref':'#/$defs/'+n}
def obj(p,required=None):return {'type':'object','properties':p,'required':list(p) if required is None else required,'additionalProperties':False}
def arr(x,max=128,min=0,unique=False):return {'type':'array','items':x,'minItems':min,'maxItems':max,**({'uniqueItems':True} if unique else {})}
def enum(*x):return {'enum':list(x)}
def const(x):return {'const':x}
S={'type':'string','minLength':1,'maxLength':4096}
I={'type':'integer','minimum':0,'maximum':9007199254740991}
HASH={'type':'string','pattern':'^[0-9a-f]{64}$'}
HEX={'type':'string','pattern':'^0x[0-9a-fA-F]{64}$'}
ADDR={'type':'string','pattern':'^0x[0-9a-fA-F]{40}$'}
NUM={'type':'string','pattern':'^(0|[1-9][0-9]{0,77})$','x-whp-uint256':True}
OPS=enum('INFORM','RECOMMEND','EXECUTE')
OPLIST=arr(OPS,3,unique=True)
PUB={'type':'string','maxLength':256,'description':'Canonical base64 DER SubjectPublicKeyInfo containing exactly an Ed25519 public key.'}
BOUNDS=obj({'scope':S,'jurisdiction':S,'valid_from':I,'valid_until':I})
OBJECT=obj({'id':S,'version':S,'root':HASH})
SIG={'type':'string','pattern':'^[A-Za-z0-9+/]{86}==$'}
def envelope(kind,payload):return obj({'protected':obj({'type':const(kind),'algorithm':const('Ed25519'),'canonicalization':const('WHP-JCS-I1'),'key_id':HASH}),'payload':payload,'signature':SIG})
D={'hash':HASH,'bounds':BOUNDS,'object':OBJECT,'public_key':PUB,'operation':OPS}
D['value']={'oneOf':[{'type':'null'},{'type':'boolean'},{'type':'integer','minimum':-9007199254740991,'maximum':9007199254740991},{'type':'string'},{'type':'array','items':ref('value')},{'type':'object','additionalProperties':ref('value')}],'description':'WHP-JCS-I1 additionally forbids lone surrogates, negative zero, duplicate object keys and excessive nesting.'}
D['unknown']=obj({'id':S,'description':S,'blocks':OPLIST})
unknowns=arr(ref('unknown'),64,unique=True);unknowns['x-whp-unique-key']='id'
D['node_payload']=obj({'id':S,'version':S,'content':ref('value'),'locator':S,'epistemic_status':enum('OBSERVATION','REPORT','FINDING','INFERENCE','HYPOTHESIS','UNKNOWN'),'qualifiers':arr(S,128,unique=True),'unknowns':unknowns,'operations':OPLIST,'scope':S,'jurisdiction':S,'valid_from':I,'valid_until':I,'status':enum('ACTIVE','CORRECTED','SUPERSEDED','DISPUTED','WITHDRAWN'),'prior_hash':{'anyOf':[HASH,{'type':'null'}]}})
D['source']=envelope('WHP-SOURCE-ATTESTATION-v1',ref('node_payload'))
D['transition_payload']=obj({'from':arr(HASH,64,1,True),'to':HASH,'transform':enum('COPY','COMPOSE'),'operations':OPLIST,'scope':S,'jurisdiction':S,'valid_from':I,'valid_until':I,'warrant':obj({'statement':S,'evidence_hashes':arr(HASH,64,unique=True)})})
D['transition']=envelope('WHP-TRANSITION-WARRANT-v1',ref('transition_payload'))
D['profile_ref']=const({'id':PROFILE['id'],'version':PROFILE['version'],'sha256':H})
D['submission']=obj({'version':const('WHP-STANDING-SUBMISSION-v1'),'client_reference':{'type':'string','pattern':'^[A-Za-z0-9_-]{16,96}$'},'buyer_key':PUB,'profile':ref('profile_ref'),'object':OBJECT,'bounds':BOUNDS,'requested_operation':OPS,'nodes':arr(ref('source'),64,1),'transitions':arr(ref('transition'),64)})
D['profile_authorization']=envelope('WHP-PROFILE-AUTHORIZATION-v1',obj({'profile_hash':const(H),'ratified':const(True),'issuer':S,'environment':enum('TEST','LIVE'),'valid_from':I,'valid_until':I}))
D['certificate']=envelope('WHP-AUTHORITY-CERTIFICATE-v1',obj({'public_key':PUB,'subject':S,'roles':arr(enum('SOURCE','TRANSITION','ISSUER','REGISTRY'),64),'scopes':arr(S,64),'jurisdictions':arr(S,64),'operations':OPLIST,'profile_hash':const(H),'valid_from':I,'valid_until':I}))
D['revocation']=envelope('WHP-KEY-REVOCATION-v1',obj({'key_id':HASH,'effective_at':I,'reason':S}))
D['trust_status']=envelope('WHP-TRUST-STATUS-v1',obj({'sequence':I,'previous_hash':{'anyOf':[HASH,{'type':'null'}]},'profile_authorization_hash':HASH,'certificates_hash':HASH,'revocations_hash':HASH,'valid_from':I,'valid_until':I}))
D['trust_bundle']=obj({'root_public_key':PUB,'profile_authorization':ref('profile_authorization'),'certificates':arr(ref('certificate'),128),'revocations':arr(ref('revocation'),128),'status_snapshot':ref('trust_status')})
D['requirements']=obj({'scheme':const('exact'),'network':{'type':'string','pattern':'^eip155:[1-9][0-9]*$'},'amount':NUM,'asset':ADDR,'payTo':ADDR,'maxTimeoutSeconds':{'type':'integer','minimum':1,'maximum':300},'extra':obj({'assetTransferMethod':const('eip3009'),'paymentFlow':const('authorization'),'name':S,'version':S})})
D['resource']=obj({'url':S,'description':S,'mimeType':const('application/json')})
D['quote']=envelope('WHP-STANDING-QUOTE-v1',obj({'purchase_id':HASH,'request_hash':HASH,'buyer_key':PUB,'profile_hash':const(H),'issuer':S,'environment':enum('TEST','LIVE'),'issued_at':I,'expires_at':I,'resource':ref('resource'),'payment_requirements':ref('requirements'),'charge_policy':S}))
D['payment']=obj({'x402Version':const(2),'resource':ref('resource'),'accepted':ref('requirements'),'payload':obj({'signature':{'type':'string','pattern':'^0x[0-9a-fA-F]{128}(00|01|1[bBcC])$'},'authorization':obj({'from':ADDR,'to':ADDR,'value':NUM,'validAfter':NUM,'validBefore':NUM,'nonce':HEX})})})
D['components']=obj({k:enum('ESTABLISHED','NOT_ESTABLISHED','NOT_ASSESSED') for k in ['SOURCE','CONTEXT','RELATION','PASSAGE','UNKNOWN','CONTINUITY','ACTION_BOUNDARY']})
D['decision']=obj({'version':const('WHP-STANDING-DECISION-v1'),'evaluated_at':I,'submission_hash':HASH,'object':OBJECT,'profile':ref('profile_ref'),'bounds':BOUNDS,'requested_operation':OPS,'outcome':enum('ESTABLISHED','NOT_ESTABLISHED'),'permitted_operations':OPLIST,'components':ref('components'),'effective_at':I,'expires_at':I,'checks':arr(obj({'rule':S,'object':HASH,'passed':{'type':'boolean'},'detail':S}),1024),'unknowns':arr(obj({'source_hash':HASH,'unknowns':unknowns}),64),'assessment_boundary':const(PROFILE['assessed']),'not_assessed':const(PROFILE['not_assessed']),'review_triggers':const(PROFILE['review_triggers'])})
common={'version':S,'environment':enum('TEST','LIVE'),'network':S,'asset':ADDR,'payer':ADDR,'pay_to':ADDR,'amount':NUM,'nonce':HEX,'transaction':HEX,'block_number':I,'block_hash':HEX,'finality':S,'observed_at':I,'verification_boundary':S}
D['settlement_test']=obj({**common,'version':const('WHP-TEST-SETTLEMENT-EVIDENCE-v1'),'environment':const('TEST'),'finality':const('SIMULATED_NOT_LIVE')})
D['settlement_live']=obj({**common,'version':const('WHP-EIP3009-SETTLEMENT-EVIDENCE-v1'),'environment':const('LIVE'),'finality':const('finalized'),'finalized_head':obj({'number':S,'hash':HEX}),'authorization_log':ref('value'),'transfer_log':ref('value'),'transaction_input':S})
D['commerce']=obj({'quote':ref('quote'),'payment_identity':HASH,'payment_payload':ref('payment'),'settlement':{'oneOf':[ref('settlement_test'),ref('settlement_live')]},'assessment_paid_by':ADDR,'relationship':S,'assessor':S})
D['result_payload']=obj({'version':const('WHP-STANDING-RESULT-v1'),'environment':enum('TEST','LIVE'),'issuer':S,'issuer_key_id':HASH,'purchase_id':HASH,'mark_id':{'anyOf':[{'type':'string','pattern':'^WHP-SM-[0-9a-f]{64}$'},{'type':'null'}]},'issued_at':I,'effective_at':I,'expires_at':I,'object':OBJECT,'profile':const(PROFILE),'profile_authorization':ref('profile_authorization'),'authority':ref('trust_bundle'),'submission':ref('submission'),'submission_hash':HASH,'decision_record':ref('decision'),'decision_record_ref':{'type':'string','pattern':'^urn:sha256:[0-9a-f]{64}$'},'standing':{'anyOf':[{'type':'null'},obj({'operation':OPS,'components':ref('components'),'bounds':BOUNDS})]},'commerce':ref('commerce'),'retrieval':obj({'purchase_path':S,'result_path':S,'registry_path':S,'authentication':S,'additional_charge':const(False)}),'limitations':const(PROFILE['not_assessed']),'current_status_rule':S})
D['mark']=envelope('WHP-STANDING-MARK-v1',ref('result_payload'))
D['assessment']=envelope('WHP-STANDING-ASSESSMENT-v1',ref('result_payload'))
def document(name,body):return {'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:whp:standing:v1:'+name,'title':'WHP Standing v1 '+name,'$defs':D,**body,'x-whp-canonicalization':'WHP-JCS-I1','x-whp-cross-field-constraints':'See docs/WIRE-CONTRACT.md; signatures, dates, graph closure, binding, authority and issuance conditions require semantic verification.'}
for name,body in {'submission':ref('submission'),'result':{'oneOf':[ref('mark'),ref('assessment')]},'trust-bundle':ref('trust_bundle'),'payment-requirements':ref('requirements')}.items():
    # Each file is self-contained so agents need no hidden remote schema fetches.
    (ROOT/'schemas'/f'{name}.schema.json').write_text(json.dumps(document(name,body),indent=2,ensure_ascii=False)+'\n')
