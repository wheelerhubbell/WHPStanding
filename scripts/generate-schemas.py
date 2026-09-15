"""Build inspectable schemas from the frozen v1 wire contract, not runtime inference."""
import json,hashlib,base64,zlib,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROFILE=json.loads((ROOT/'profiles/structured-passage-1.0.0.json').read_text())
H=hashlib.sha256(json.dumps(PROFILE,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
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
D['certificate']=envelope('WHP-AUTHORITY-CERTIFICATE-v1',obj({'public_key':PUB,'subject':S,'roles':arr(enum('SOURCE','TRANSITION','ISSUER','REGISTRY','DISCOVERY'),64),'scopes':arr(S,64),'jurisdictions':arr(S,64),'operations':OPLIST,'profile_hash':const(H),'valid_from':I,'valid_until':I}))
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
D['discovery']=obj({
 'format':const('signed-artifact-discovery-v1'),
 'artifact':obj({'name':enum('WHP Standing Mark v1','WHP Standing Assessment v1'),'contract':const('WHP-STANDING-RESULT-v1'),'historical':const(True)}),
 'issuer':obj({'id':{'type':'string','pattern':'^urn:sha256:[0-9a-f]{64}$'},'name':S,'root_pin':HASH,'institutional_attribution':enum('TEST key identity only; not institutional WHP issuance.','Institutional attribution requires independently admitted root authority.')}),
 'capability':obj({'id':{'type':'string','pattern':'^urn:whp:standing:v1:[0-9a-f]{64}$'},'requirement_id':const('urn:capability:machine-verifiable-standing:1')}),
 'meaning':obj({'determination':enum('ESTABLISHED','NOT_ESTABLISHED'),'establishes':enum(PROFILE['assessed'],'No standing established. See the signed negative decision record.'),'does_not_establish':const(PROFILE['not_assessed']),'claim_pointer':const('/payload/decision_record'),'bounds_pointer':const('/payload/submission/bounds'),'authority_pointer':const('/payload/authority'),'provenance_pointer':const('/payload/submission'),'qualifications_pointer':const('/payload/submission/nodes'),'unknowns_pointer':const('/payload/decision_record/unknowns'),'limitations_pointer':const('/payload/limitations')}),
 'profile':obj({'id':const(PROFILE['id']),'version':const(PROFILE['version']),'sha256':const(H),'embedded_pointer':const('/payload/profile')}),
 'resolution':obj({'id':S,'format':const('WHP-STANDING-RESOLUTION-v1'),'authority_role':const('DISCOVERY'),'max_age_seconds':const(300)}),
 'verification':obj({'algorithm':const('Ed25519'),'canonicalization':const('WHP-JCS-I1'),'signed_fields':const(['protected','payload']),'key_encoding':const('base64-DER-SPKI'),'embedded_root_pointer':const('/payload/authority/root_public_key'),'certificates_pointer':const('/payload/authority/certificates'),'certificate_key_pointer':const('/payload/public_key'),'source_sha256':HASH,'source_id':{'type':'string','pattern':'^urn:sha256:[0-9a-f]{64}$'},'invocation':obj({'arguments':const(['{mark}','--root-pin','{root_pin}','--registry','{registry}']),'test_arguments':const(['--allow-test'])})}),
 'status':obj({'type':const('WHP-REGISTRY-SNAPSHOT-v1'),'requires_fresh':const(True),'max_age_seconds':const(300)})})
D['result_payload']['properties']['discovery']=ref('discovery')
D['result_payload']['required'].append('discovery')
D['result_payload']['properties']['current_status_rule']=const('This immutable record proves issuance-time assessment. Current standing requires a fresh signed registry response and current trust/revocation information.')
D['commerce']['properties']['assessor']=const('WHP Standing deterministic Structured Passage evaluator 1.0.0')
D['commerce']['properties']['relationship']=enum('Simulated buyer and test issuer only. No Wheeler Hubbell Publishing sale or real funds transfer occurred.','The buyer pays Wheeler Hubbell Publishing for assessment. Payment does not determine the assessment outcome.')
FIXED_DETAILS=dict(re.findall(r"check\('([A-Z_]+)'[^\n]*?,'([^']+)'\)",(ROOT/'src/evaluator.mjs').read_text()))
assert len(FIXED_DETAILS)==16
D['decision']['properties']['checks']['items']={'oneOf':[obj({'rule':const(rule),'object':HASH,'passed':{'type':'boolean'},'detail':const(detail)}) for rule,detail in FIXED_DETAILS.items()]}
D['mark']=envelope('WHP-STANDING-MARK-v1',ref('result_payload'))
D['assessment']=envelope('WHP-STANDING-ASSESSMENT-v1',ref('result_payload'))
D['registry_command']=envelope('WHP-REGISTRY-COMMAND-v1',obj({'purchase_id':HASH,'expected_previous_hash':HASH,'status':enum('ACTIVE','SUSPENDED','WITHDRAWN','SUPERSEDED','DISPUTED','LIMITED'),'reason':S,'at':I}))
D['registry_event']=envelope('WHP-REGISTRY-EVENT-v1',obj({'purchase_id':HASH,'sequence':I,'previous_hash':{'anyOf':[HASH,{'type':'null'}]},'result_hash':HASH,'mark_id':{'anyOf':[S,{'type':'null'}]},'status':enum('ACTIVE','ASSESSED_NO_MARK','SUSPENDED','WITHDRAWN','SUPERSEDED','DISPUTED','LIMITED'),'at':I,'reason':S,'command':{'anyOf':[ref('registry_command'),{'type':'null'}]}}))
D['registry_snapshot']=envelope('WHP-REGISTRY-SNAPSHOT-v1',obj({'purchase_id':HASH,'result_hash':HASH,'mark_id':{'anyOf':[S,{'type':'null'}]},'status':enum('ACTIVE','ASSESSED_NO_MARK','SUSPENDED','WITHDRAWN','SUPERSEDED','DISPUTED','LIMITED','EXPIRED'),'observed_at':I,'valid_until':I,'events':arr(ref('registry_event'),4096,1),'trust_bundle':ref('trust_bundle')}))
D['provider']=obj({'id':S,'name':S,'publisher':S,'service_origin':S,'compatible_requirements':arr(S,64,1,True),'contract':obj({'url':S,'sha256':HASH}),'openapi':obj({'url':S,'sha256':HASH}),'profile':obj({'id':S,'version':S,'sha256':HASH,'url':S}),'material_url_template':S,'registry_url_template':S,'discovery_url':S})
D['resolution']=envelope('WHP-STANDING-RESOLUTION-v1',obj({'version':const('WHP-STANDING-RESOLUTION-v1'),'resolution_id':S,'capability_id':S,'environment':enum('TEST','LIVE'),'issuer_key_id':HASH,'sequence':I,'previous_hash':{'anyOf':[HASH,{'type':'null'}]},'observed_at':I,'valid_until':I,'authority':ref('trust_bundle'),'provider':ref('provider')}))
def document(name,body):return {'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:whp:standing:v1:'+name,'title':'WHP Standing v1 '+name,'$defs':D,**body,'x-whp-canonicalization':'WHP-JCS-I1','x-whp-cross-field-constraints':'See contracts/WHP-STANDING-v1.md; signatures, dates, graph closure, binding, authority and issuance conditions require semantic verification.'}
for name,body in {'submission':ref('submission'),'result':{'oneOf':[ref('mark'),ref('assessment')]},'trust-bundle':ref('trust_bundle'),'payment-requirements':ref('requirements'),'registry':ref('registry_snapshot'),'resolution':ref('resolution')}.items():
    # Each file is self-contained so agents need no hidden remote schema fetches.
    (ROOT/'schemas'/f'{name}.schema.json').write_text(json.dumps(document(name,body),indent=2,ensure_ascii=False)+'\n')

# Freeze the same closed grammar into the standalone verifier; it imports no producer modules.
v=ROOT/'verify/verify_mark.py';code=v.read_text()
code=re.sub(r"PROFILE_HASH = '[0-9a-f]{64}'", "PROFILE_HASH = '"+H+"'",code)
schema=json.loads((ROOT/'schemas/result.schema.json').read_text())
encoded=base64.b64encode(zlib.compress(json.dumps(schema,separators=(',',':'),ensure_ascii=False).encode(),9)).decode()
code=re.sub(r"RESULT_SCHEMA_B64 = '[^']*'", "RESULT_SCHEMA_B64 = '"+encoded+"'",code)
source=(ROOT/'src/evaluator.mjs').read_text()
details=dict(re.findall(r"check\('([A-Z_]+)'[^\n]*?,'([^']+)'\)",source))
assert len(details)==16,details
code=re.sub(r"CHECK_DETAILS = .*?  # generated fixed diagnostic text", "CHECK_DETAILS = "+repr(details)+"  # generated fixed diagnostic text",code)
v.write_text(code)
h=hashlib.sha256(code.encode()).hexdigest()
for folder in ['public/verification','public/immutable']:(ROOT/folder).mkdir(parents=True,exist_ok=True)
# Preserve previously committed immutable reference material. There is no runtime
# format fallback: each Mark binds exactly one independently checkable source digest.
(ROOT/'public/verification'/f'{h}.py').write_text(code)
(ROOT/'public/immutable'/f'{h}.py').write_text(code)
(ROOT/'public/immutable'/f'{H}.json').write_text(json.dumps(PROFILE,sort_keys=True,ensure_ascii=False,separators=(',',':')))
(ROOT/'public/verifier-manifest.json').write_text(json.dumps({'version':'WHP-STANDING-VERIFIER-v1','path':'/verification/'+h+'.py','sha256':h,'profile_sha256':H},indent=2)+'\n')
print('PUBLIC_V1_PROFILE',H,'INDEPENDENT_VERIFIER',h)
