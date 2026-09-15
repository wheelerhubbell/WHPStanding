#!/usr/bin/env python3
"""Independent WHP Standing verifier. Imports no producer modules.
Requires Python >=3.11 and cryptography. Never treats an embedded root as trust.
Offline validity, current registry standing and chain settlement are separate outputs.
"""
import argparse, base64, hashlib, json, re, sys, time, urllib.request, urllib.parse, zlib
from jsonschema import Draft202012Validator
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE_HASH = 'c31929b04e3ca4e267b45ae0d76d65feb3d9ed249612a32b6190808c385a4da5'
OPS = ['INFORM', 'RECOMMEND', 'EXECUTE']
RESULT_SCHEMA_B64 = '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'  # generated closed public grammar; no producer imports
CHECK_DETAILS = {'SOURCE_IDENTITY': 'Root hash, identifier and version must identify the same submitted object.', 'ASSESSMENT_TIME': 'The assessment must fall within the requested time window.', 'SOURCE_AUTHORITY': 'An admitted source key must attest within its signed scope, operations and validity.', 'SOURCE_ACTIVE': 'Non-active source versions cannot carry operative standing in this profile.', 'SOURCE_BOUNDS': 'Source jurisdiction and scope must match the requested bounds exactly.', 'SOURCE_TIME': 'Source validity must contain the requested time window.', 'GRAPH_CLOSURE': 'Every submitted source must be connected to the root; cycles and missing references are forbidden.', 'TRANSITION_AUTHORITY': 'A separately admitted transition authority must sign the exact passage.', 'TRANSITION_BOUNDS': 'The warrant must contain the requested temporal and jurisdictional bounds.', 'WARRANT_EVIDENCE': 'The signed warrant must name inspectable evidence in the submitted graph.', 'TRANSITION_REFERENCES': 'Unknown source or target hash.', 'EXACT_TRANSFORMATION': 'COPY preserves content and epistemic status. COMPOSE retains distinct hash-addressed members without fusion.', 'QUALIFIERS_PRESERVED': 'All source qualifiers must survive unchanged; this profile permits no waiver.', 'UNKNOWNS_PRESERVED': 'Unknowns, their descriptions and blocked operations must survive unchanged.', 'NO_FORCE_ESCALATION': 'No target operation may exceed its parents or the exact transition grant.', 'REQUESTED_OPERATION': 'The requested operation must survive every source, warrant and unresolved blocking unknown.'}  # generated fixed diagnostic text
def public_schema(e):
    schema=json.loads(zlib.decompress(base64.b64decode(RESULT_SCHEMA_B64)))
    errors=list(Draft202012Validator(schema).iter_errors(e))
    need(not errors, 'RESULT_SCHEMA_INVALID:'+ ('/'.join(map(str,errors[0].absolute_path)) if errors else ''))

def need(value, code):
    if not value: raise ValueError(code)

def pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out

def canonical(x, depth=0):
    need(depth <= 64, 'JSON_DEPTH')
    if x is None: return 'null'
    if isinstance(x, bool): return 'true' if x else 'false'
    if isinstance(x, int):
        need(abs(x) <= 9007199254740991, 'INTEGER_RANGE')
        return str(x)
    if isinstance(x, str):
        need(not any(0xD800 <= ord(c) <= 0xDFFF for c in x), 'INVALID_UNICODE')
        return json.dumps(x, ensure_ascii=False, separators=(',', ':'))
    if isinstance(x, list): return '[' + ','.join(canonical(v, depth+1) for v in x) + ']'
    need(isinstance(x, dict), 'I_JSON_REQUIRED')
    return '{' + ','.join(canonical(k,depth+1)+':'+canonical(x[k],depth+1) for k in sorted(x,key=lambda k:k.encode('utf-16be'))) + '}'

def digest(x): return hashlib.sha256(canonical(x).encode()).hexdigest()
def bytehash(x): return hashlib.sha256(x).hexdigest()
def integer_lexeme(s):
    need(s!='-0','NEGATIVE_ZERO');return int(s)
def read(path):
    raw = Path(path).read_bytes()
    need(len(raw) <= 2_000_000, 'FILE_TOO_LARGE')
    x = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,parse_int=integer_lexeme,
                   parse_float=lambda _: (_ for _ in ()).throw(ValueError('FLOAT_NOT_ALLOWED')),
                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_NOT_ALLOWED')))
    canonical(x)
    return x, raw

def exact(x, fields): need(isinstance(x,dict) and set(x)==set(fields), 'FIELDS_INVALID')
def keyid(pub):
    der=base64.b64decode(pub,validate=True);need(base64.b64encode(der).decode()==pub,'NONCANONICAL_PUBLIC_KEY')
    key=load_der_public_key(der);need(isinstance(key,Ed25519PublicKey) and key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)==der,'ED25519_SPKI_REQUIRED')
    return bytehash(der)
def unseal(e, kind, pub):
    exact(e,['protected','payload','signature'])
    exact(e['protected'],['type','algorithm','canonicalization','key_id'])
    need(e['protected']=={'type':kind,'algorithm':'Ed25519','canonicalization':'WHP-JCS-I1','key_id':keyid(pub)}, 'SIGNATURE_CONTEXT')
    k=load_der_public_key(base64.b64decode(pub,validate=True))
    need(isinstance(k,Ed25519PublicKey),'ED25519_REQUIRED')
    sig=base64.b64decode(e['signature'],validate=True); need(len(sig)==64 and base64.b64encode(sig).decode()==e['signature'],'SIGNATURE_LENGTH_OR_ENCODING')
    k.verify(sig,canonical({'protected':e['protected'],'payload':e['payload']}).encode())
    return e['payload']

def trust(bundle,pin,at):
    exact(bundle,['root_public_key','profile_authorization','certificates','revocations','status_snapshot'])
    root=bundle['root_public_key']; need(keyid(root)==pin,'UNTRUSTED_ROOT')
    pa=unseal(bundle['profile_authorization'],'WHP-PROFILE-AUTHORIZATION-v1',root)
    exact(pa,['profile_hash','ratified','issuer','environment','valid_from','valid_until'])
    need(pa['profile_hash']==PROFILE_HASH and pa['ratified'] is True and pa['valid_from']<=at<pa['valid_until'],'PROFILE_NOT_AUTHORIZED')
    need(pa['environment'] in ['LIVE','TEST'],'ENVIRONMENT_INVALID')
    status=unseal(bundle['status_snapshot'],'WHP-TRUST-STATUS-v1',root)
    exact(status,['sequence','previous_hash','profile_authorization_hash','certificates_hash','revocations_hash','valid_from','valid_until'])
    need(status['valid_from']<=at<status['valid_until'],'TRUST_STATUS_EXPIRED')
    need(status['profile_authorization_hash']==digest(bundle['profile_authorization']) and status['certificates_hash']==digest(bundle['certificates']) and status['revocations_hash']==digest(bundle['revocations']),'TRUST_STATUS_MANIFEST_MISMATCH')
    keys={}
    for e in bundle['certificates']:
        c=unseal(e,'WHP-AUTHORITY-CERTIFICATE-v1',root)
        exact(c,['public_key','subject','roles','scopes','jurisdictions','operations','profile_hash','valid_from','valid_until'])
        need(c['profile_hash']==PROFILE_HASH,'CERTIFICATE_PROFILE')
        kid=keyid(c['public_key']); need(kid not in keys,'DUPLICATE_AUTHORITY');keys[kid]=c
    rev=[unseal(e,'WHP-KEY-REVOCATION-v1',root) for e in bundle['revocations']]
    return pa,keys,rev

def grant(e,kind,role,ctx,keys,rev,at):
    c=keys[e['protected']['key_id']]
    unseal(e,kind,c['public_key'])
    need(role in c['roles'],'ROLE_NOT_AUTHORIZED')
    need(ctx['scope'] in c['scopes'] and ctx['jurisdiction'] in c['jurisdictions'],'AUTHORITY_OUT_OF_BOUNDS')
    need(c['valid_from']<=at<c['valid_until'],'AUTHORITY_EXPIRED')
    need(not any(r['key_id']==e['protected']['key_id'] and r['effective_at']<=at for r in rev),'AUTHORITY_REVOKED')
    need(all(op in c['operations'] for op in ctx.get('operations',[])),'AUTHORITY_OPERATION_DENIED')
    return c

def input_shape(s):
    # Independently enforce the closed structural contract; bool is NOT an integer.
    canonical(s,16)
    exact(s,['version','client_reference','buyer_key','profile','object','bounds','requested_operation','nodes','transitions'])
    def text(v):need(isinstance(v,str) and 0<len(v.encode('utf-16be'))//2<=4096,'TEXT_REQUIRED')
    def integer(v):need(type(v) is int and 0<=v<=9007199254740991,'INTEGER_REQUIRED')
    def window(v):integer(v['valid_from']);integer(v['valid_until']);need(v['valid_until']>v['valid_from'],'INVALID_TIME_WINDOW')
    def array(v,maximum=128):need(isinstance(v,list) and len(v)<=maximum,'ARRAY_INVALID')
    def unique(v):need(len({canonical(x) for x in v})==len(v),'DUPLICATE_ITEM')
    def operations(v):array(v,3);unique(v);need(all(x in OPS for x in v),'OPERATION_INVALID')
    def hashed(v):need(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) is not None,'HASH_INVALID')
    need(re.fullmatch('[A-Za-z0-9_-]{16,96}',s['client_reference']) is not None,'CLIENT_REFERENCE_INVALID')
    der=base64.b64decode(s['buyer_key'],validate=True);key=load_der_public_key(der)
    need(isinstance(key,Ed25519PublicKey) and key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)==der,'INVALID_BUYER_KEY')
    exact(s['object'],['id','version','root']);text(s['object']['id']);text(s['object']['version']);hashed(s['object']['root'])
    exact(s['bounds'],['scope','jurisdiction','valid_from','valid_until']);text(s['bounds']['scope']);text(s['bounds']['jurisdiction']);window(s['bounds'])
    array(s['nodes'],64);array(s['transitions'],64)
    for e in s['nodes']:
        x=e['payload'];exact(x,['id','version','content','locator','epistemic_status','qualifiers','unknowns','operations','scope','jurisdiction','valid_from','valid_until','status','prior_hash'])
        for k in ['id','version','locator','scope','jurisdiction']:text(x[k])
        window(x);operations(x['operations']);array(x['qualifiers']);unique(x['qualifiers'])
        for q in x['qualifiers']:text(q)
        array(x['unknowns'],64);unique(x['unknowns']);unique([u['id'] for u in x['unknowns']])
        for u in x['unknowns']:exact(u,['id','description','blocks']);text(u['id']);text(u['description']);operations(u['blocks'])
        if x['prior_hash'] is not None:hashed(x['prior_hash'])
        need(x['epistemic_status'] in ['OBSERVATION','REPORT','FINDING','INFERENCE','HYPOTHESIS','UNKNOWN'] and x['status'] in ['ACTIVE','CORRECTED','SUPERSEDED','DISPUTED','WITHDRAWN'],'SOURCE_ENUM_INVALID')
    for e in s['transitions']:
        t=e['payload'];exact(t,['from','to','transform','operations','scope','jurisdiction','valid_from','valid_until','warrant']);array(t['from'],64);unique(t['from']);hashed(t['to'])
        for h in t['from']:hashed(h)
        window(t);operations(t['operations']);text(t['scope']);text(t['jurisdiction']);exact(t['warrant'],['statement','evidence_hashes']);text(t['warrant']['statement']);array(t['warrant']['evidence_hashes'],64);unique(t['warrant']['evidence_hashes'])
        for h in t['warrant']['evidence_hashes']:hashed(h)

def assess(s,bundle,pin,at,profile):
    input_shape(s)
    exact(s,['version','client_reference','buyer_key','profile','object','bounds','requested_operation','nodes','transitions'])
    need(s['version']=='WHP-STANDING-SUBMISSION-v1','SUBMISSION_VERSION')
    need(s['profile']=={'id':profile['id'],'version':profile['version'],'sha256':PROFILE_HASH},'SUBMISSION_PROFILE')
    need(s['requested_operation'] in OPS and 0<len(s['nodes'])<=64 and len(s['transitions'])<=64,'SUBMISSION_LIMITS')
    pa,keys,rev=trust(bundle,pin,at)
    checks=[]
    def check(rule,obj,passed): checks.append([rule,obj,bool(passed)])
    n={digest(e['payload']):e for e in s['nodes']}
    need(len(n)==len(s['nodes']),'DUPLICATE_NODES')
    need(len({(e['payload']['id'],e['payload']['version']) for e in s['nodes']})==len(n),'DUPLICATE_VERSIONS')
    edges={e['payload']['to']:e for e in s['transitions']}; need(len(edges)==len(s['transitions']),'MULTIPLE_INCOMING_WARRANTS')
    root=n.get(s['object']['root'],{}).get('payload')
    check('SOURCE_IDENTITY',s['object']['root'],root and root['id']==s['object']['id'] and root['version']==s['object']['version'])
    b=s['bounds'];check('ASSESSMENT_TIME',s['object']['root'],b['valid_from']<=at<b['valid_until'])
    expiry=min(b['valid_until'],pa['valid_until'],at+profile['max_validity_seconds']); allowed=set(OPS)
    for h,e in n.items():
        x=e['payload']
        exact(x,['id','version','content','locator','epistemic_status','qualifiers','unknowns','operations','scope','jurisdiction','valid_from','valid_until','status','prior_hash'])
        try:
            c=grant(e,'WHP-SOURCE-ATTESTATION-v1','SOURCE',{**b,'operations':x['operations']},keys,rev,at)
            check('SOURCE_AUTHORITY',h,c['valid_from']<=b['valid_from'] and b['valid_until']<=c['valid_until']);expiry=min(expiry,c['valid_until'])
        except Exception: check('SOURCE_AUTHORITY',h,False)
        check('SOURCE_ACTIVE',h,x['status']=='ACTIVE')
        check('SOURCE_BOUNDS',h,x['scope']==b['scope'] and x['jurisdiction']==b['jurisdiction'])
        check('SOURCE_TIME',h,x['valid_from']<=b['valid_from'] and b['valid_until']<=x['valid_until']);expiry=min(expiry,x['valid_until'])
        allowed.intersection_update(x['operations'])
        for u in x['unknowns']: allowed.difference_update(u['blocks'])
    seen=set();visiting=set();invalid=[False]
    def visit(h):
        if h in visiting or h not in n: invalid[0]=True;return
        if h in seen:return
        visiting.add(h)
        if h in edges:
            for ph in edges[h]['payload']['from']:visit(ph)
        visiting.remove(h);seen.add(h)
    visit(s['object']['root'])
    check('GRAPH_CLOSURE',s['object']['root'],not invalid[0] and len(seen)==len(n) and all(h in n for h in edges))
    for e in s['transitions']:
        t=e['payload'];h=digest(t)
        exact(t,['from','to','transform','operations','scope','jurisdiction','valid_from','valid_until','warrant'])
        need(len(t['from'])>0 and len(t['from'])==len(set(t['from'])) and t['transform'] in ['COPY','COMPOSE'],'TRANSITION_SHAPE')
        try:
            c=grant(e,'WHP-TRANSITION-WARRANT-v1','TRANSITION',{**b,'operations':t['operations']},keys,rev,at)
            check('TRANSITION_AUTHORITY',h,c['valid_from']<=b['valid_from'] and b['valid_until']<=c['valid_until']);expiry=min(expiry,c['valid_until'])
        except Exception:check('TRANSITION_AUTHORITY',h,False)
        check('TRANSITION_BOUNDS',h,t['scope']==b['scope'] and t['jurisdiction']==b['jurisdiction'] and t['valid_from']<=b['valid_from'] and b['valid_until']<=t['valid_until'])
        expiry=min(expiry,t['valid_until']);allowed.intersection_update(t['operations'])
        check('WARRANT_EVIDENCE',h,bool(t['warrant']['evidence_hashes']) and all(x in n for x in t['warrant']['evidence_hashes']))
        target=n.get(t['to'],{}).get('payload');parents=[n.get(ph,{}).get('payload') for ph in t['from']]
        if not target or any(p is None for p in parents):check('TRANSITION_REFERENCES',h,False);continue
        if t['transform']=='COPY':
            ok=len(parents)==1 and canonical(target['content'])==canonical(parents[0]['content']) and target['epistemic_status']==parents[0]['epistemic_status']
        else:
            ok=canonical(target['content'])==canonical({'kind':'COMPOSE','members':[{'hash':ph,'content':n[ph]['payload']['content']} for ph in sorted(t['from'])]}) and target['epistemic_status']=='REPORT'
        check('EXACT_TRANSFORMATION',h,ok)
        check('QUALIFIERS_PRESERVED',h,all(q in target['qualifiers'] for p in parents for q in p['qualifiers']))
        check('UNKNOWNS_PRESERVED',h,all(u in target['unknowns'] for p in parents for u in p['unknowns']))
        check('NO_FORCE_ESCALATION',h,all(op in t['operations'] and all(op in p['operations'] for p in parents) for op in target['operations']))
    check('REQUESTED_OPERATION',s['object']['root'],s['requested_operation'] in allowed)
    ok=all(c[2] for c in checks)
    components={k:('ESTABLISHED' if ok else 'NOT_ESTABLISHED') for k in ['SOURCE','CONTEXT','UNKNOWN']}
    components.update({k:(('ESTABLISHED' if ok else 'NOT_ESTABLISHED') if s['transitions'] else 'NOT_ASSESSED') for k in ['RELATION','PASSAGE']})
    components.update({'CONTINUITY':'NOT_ASSESSED','ACTION_BOUNDARY':'NOT_ASSESSED'})
    return ok,[op for op in OPS if op in allowed] if ok else [],checks,max(0,expiry),components

def verify_result(e,pin,allow_test=False):
    public_schema(e)
    p=e['payload']
    exact(p,['version','environment','issuer','issuer_key_id','purchase_id','mark_id','issued_at','effective_at','expires_at','object','profile','profile_authorization','authority','submission','submission_hash','decision_record','decision_record_ref','standing','commerce','retrieval','limitations','current_status_rule','discovery'])
    need(p['version']=='WHP-STANDING-RESULT-v1','RESULT_VERSION')
    need(p['environment']=='LIVE' or (allow_test and p['environment']=='TEST'),'TEST_ARTIFACT_NOT_LIVE')
    need(p['environment']!='LIVE' or p['issuer']=='Wheeler Hubbell Publishing','LIVE_ISSUER_IDENTITY')
    need(digest(p['profile'])==PROFILE_HASH,'PROFILE_CONTENT_MISMATCH')
    pa,keys,rev=trust(p['authority'],pin,p['issued_at'])
    need(pa['environment']==p['environment'] and pa['issuer']==p['issuer'] and p['profile_authorization']==p['authority']['profile_authorization'],'ISSUER_AUTHORIZATION_MISMATCH')
    c=grant(e,e['protected']['type'],'ISSUER',p['submission']['bounds'],keys,rev,p['issued_at'])
    need(p['issuer_key_id']==e['protected']['key_id'],'ISSUER_KEY_MISMATCH')
    s=p['submission'];d=p['decision_record']
    exact(d,['version','evaluated_at','submission_hash','object','profile','bounds','requested_operation','outcome','permitted_operations','components','effective_at','expires_at','checks','unknowns','assessment_boundary','not_assessed','review_triggers']);need(d['version']=='WHP-STANDING-DECISION-v1','DECISION_VERSION')
    need(digest(s)==p['submission_hash']==d['submission_hash'],'SUBMISSION_HASH_MISMATCH')
    need(p['decision_record_ref']=='urn:sha256:'+digest(d),'DECISION_RECORD_HASH')
    need(p['object']==s['object']==d['object'] and d['profile']==s['profile'] and d['bounds']==s['bounds'] and d['requested_operation']==s['requested_operation'],'DECISION_BINDING')
    need(d['evaluated_at']<=p['issued_at'] and p['effective_at']==d['effective_at']==d['evaluated_at'],'ASSESSMENT_TIME_BINDING')
    ok,ops,checks,expiry,components=assess(s,p['authority'],pin,d['evaluated_at'],p['profile'])
    need(d['outcome']==('ESTABLISHED' if ok else 'NOT_ESTABLISHED') and d['permitted_operations']==ops,'EVALUATION_REPLAY_MISMATCH')
    need([[r['rule'],r['object'],r['passed']] for r in d['checks']]==checks,'CHECK_TRACE_REPLAY_MISMATCH')
    need(all(r['detail']==CHECK_DETAILS.get(r['rule']) for r in d['checks']),'CHECK_DETAIL_REPLAY_MISMATCH')
    need(d['components']==components and d['expires_at']==expiry and p['expires_at']==min(expiry,c['valid_until']),'STANDING_OR_EXPIRY_MISMATCH')
    need(d['unknowns']==[{'source_hash':digest(e['payload']),'unknowns':e['payload']['unknowns']} for e in s['nodes']],'UNKNOWNS_MISMATCH')
    need(p['limitations']==d['not_assessed']==p['profile']['not_assessed'] and d['assessment_boundary']==p['profile']['assessed'] and d['review_triggers']==p['profile']['review_triggers'],'ASSESSMENT_CEILING_MISMATCH')
    pid=digest({'domain':'WHP-STANDING-PURCHASE-v1','root_pin':pin,'buyer_key':s['buyer_key'],'client_reference':s['client_reference']})
    need(pid==p['purchase_id'],'PURCHASE_ID_MISMATCH')
    need(p['mark_id']==('WHP-SM-'+pid if ok else None),'MARK_ID_MISMATCH')
    need(e['protected']['type']==('WHP-STANDING-MARK-v1' if ok else 'WHP-STANDING-ASSESSMENT-v1'),'INVALID_MARK_PROMOTION')
    need(p['standing']==({'operation':s['requested_operation'],'components':components,'bounds':s['bounds']} if ok else None),'STANDING_BINDING')
    co=p['commerce'];exact(co,['quote','payment_identity','payment_payload','settlement','assessment_paid_by','relationship','assessor']);q=co['quote'];qp=unseal(q,'WHP-STANDING-QUOTE-v1',c['public_key'])
    exact(qp,['purchase_id','request_hash','buyer_key','profile_hash','issuer','environment','issued_at','expires_at','resource','payment_requirements','charge_policy'])
    need(qp['purchase_id']==pid and qp['request_hash']==digest(s) and qp['buyer_key']==s['buyer_key'] and qp['profile_hash']==PROFILE_HASH and qp['issuer']==p['issuer'] and qp['environment']==p['environment'],'QUOTE_BINDING')
    pay=co['payment_payload'];a=pay['payload']['authorization'];r=pay['accepted'];settle=co['settlement']
    need(all(isinstance(n,str) and re.fullmatch(r'(0|[1-9][0-9]*)',n) and 0<=int(n)<2**256 for n in [r['amount'],a['value'],a['validAfter'],a['validBefore']]),'PAYMENT_UINT256_RANGE')
    need(int(r['amount'])>0 and int(a['validAfter'])<d['evaluated_at']<int(a['validBefore'])<=qp['expires_at'] and int(a['validBefore'])-d['evaluated_at']<=r['maxTimeoutSeconds'],'PAYMENT_TIME_BINDING')
    need(pay['x402Version']==2 and r==qp['payment_requirements'] and pay['resource']==qp['resource'],'PAYMENT_TERMS_MISMATCH')
    nonce='0x'+digest({'domain':'WHP-STANDING-PURCHASE-BINDING-v1','quote':qp})
    need(a['nonce'].lower()==nonce and a['to'].lower()==r['payTo'].lower() and a['value']==r['amount'],'PAYMENT_PURCHASE_BINDING')
    identity=digest({'domain':'WHP-EIP3009-PAYMENT-IDENTITY-v1','network':r['network'],'asset':r['asset'].lower(),'authorizer':a['from'].lower(),'nonce':nonce})
    need(co['payment_identity']==identity and co['assessment_paid_by']==a['from'],'PAYMENT_IDENTITY_MISMATCH')
    for name,val in [('environment',p['environment']),('network',r['network']),('asset',r['asset']),('payer',a['from']),('pay_to',a['to']),('amount',a['value']),('nonce',a['nonce'])]: need(settle[name]==val,'SETTLEMENT_BINDING_'+name)
    need(re.fullmatch(r'0x[0-9a-f]{64}',settle['transaction']) is not None,'TRANSACTION_ID_INVALID')
    need(p['retrieval']=={'purchase_path':'/v1/purchases/'+pid,'result_path':'/v1/purchases/'+pid+'/result','registry_path':'/v1/registry/'+pid,'authentication':'Buyer Ed25519 proof bound to HTTP method, path and body','additional_charge':False},'RETRIEVAL_BINDING')
    verify_discovery(p)
    relationship='Simulated buyer and test issuer only. No Wheeler Hubbell Publishing sale or real funds transfer occurred.' if p['environment']=='TEST' else 'The buyer pays Wheeler Hubbell Publishing for assessment. Payment does not determine the assessment outcome.'
    need(co['relationship']==relationship and co['assessor']=='WHP Standing deterministic Structured Passage evaluator 1.0.0','COMMERCE_SEMANTIC_PROMOTION')
    return {'verified':True,'cryptographic_integrity':'VERIFIED','evaluation_replay':'VERIFIED','environment':p['environment'],'purchase_id':pid,'mark_id':p['mark_id'],'assessment':d['outcome'],'current_standing':'NOT_CHECKED','payment_chain_finality':'NOT_RECHECKED' if p['environment']=='LIVE' else 'SIMULATED_NOT_LIVE','expires_at':p['expires_at']}


def verify_discovery(p):
    x=p['discovery'];pin=keyid(p['authority']['root_public_key']);ok=p['decision_record']['outcome']=='ESTABLISHED'
    expected_artifact={'name':'WHP Standing Mark v1' if ok else 'WHP Standing Assessment v1','contract':'WHP-STANDING-RESULT-v1','historical':True}
    need(x['format']=='signed-artifact-discovery-v1' and x['artifact']==expected_artifact,'DISCOVERY_ARTIFACT_IDENTITY')
    attribution='TEST key identity only; not institutional WHP issuance.' if p['environment']=='TEST' else 'Institutional attribution requires independently admitted root authority.'
    need(x['issuer']=={'id':'urn:sha256:'+pin,'name':p['issuer'],'root_pin':pin,'institutional_attribution':attribution},'DISCOVERY_ISSUER_IDENTITY')
    need(x['capability']=={'id':'urn:whp:standing:v1:'+pin,'requirement_id':'urn:capability:machine-verifiable-standing:1'},'DISCOVERY_CAPABILITY_IDENTITY')
    meaning={'determination':p['decision_record']['outcome'],'establishes':p['profile']['assessed'] if ok else 'No standing established. See the signed negative decision record.','does_not_establish':p['limitations'],
      'claim_pointer':'/payload/decision_record','bounds_pointer':'/payload/submission/bounds','authority_pointer':'/payload/authority','provenance_pointer':'/payload/submission','qualifications_pointer':'/payload/submission/nodes','unknowns_pointer':'/payload/decision_record/unknowns','limitations_pointer':'/payload/limitations'}
    need(x['meaning']==meaning,'DISCOVERY_SEMANTIC_PROMOTION')
    need(x['profile']=={'id':p['profile']['id'],'version':p['profile']['version'],'sha256':PROFILE_HASH,'embedded_pointer':'/payload/profile'},'DISCOVERY_PROFILE_COMMITMENT')
    r=x['resolution'];u=urllib.parse.urlsplit(r['id'])
    need((u.scheme=='https' or (p['environment']=='TEST' and u.scheme=='http' and u.hostname=='127.0.0.1')) and u.netloc and not u.username and not u.password and not u.query and not u.fragment and r['id']==urllib.parse.urlunsplit(u) and u.path=='/.well-known/standing-resolution.json' and re.fullmatch(r'[\x21-\x7e]+',r['id']) and u.netloc==u.netloc.lower() and not (u.scheme=='https' and u.port==443) and not (u.scheme=='http' and u.port==80) and (u.port is None or str(u.port)==u.netloc.rsplit(':',1)[1]),'DISCOVERY_RESOLUTION_ID')
    need(r['format']=='WHP-STANDING-RESOLUTION-v1' and r['authority_role']=='DISCOVERY' and r['max_age_seconds']==300,'DISCOVERY_RESOLUTION_SEMANTICS')
    v=x['verification'];h=v['source_sha256'];need(h==bytehash(Path(__file__).read_bytes()),'REFERENCE_VERIFIER_BYTES_MISMATCH');need(re.fullmatch('[0-9a-f]{64}',h) is not None and v['source_id']=='urn:sha256:'+h,'DISCOVERY_VERIFIER_COMMITMENT')
    expected_v={'algorithm':'Ed25519','canonicalization':'WHP-JCS-I1','signed_fields':['protected','payload'],'key_encoding':'base64-DER-SPKI','embedded_root_pointer':'/payload/authority/root_public_key','certificates_pointer':'/payload/authority/certificates','certificate_key_pointer':'/payload/public_key','source_sha256':h,'source_id':'urn:sha256:'+h,'invocation':{'arguments':['{mark}','--root-pin','{root_pin}','--registry','{registry}'],'test_arguments':['--allow-test']}}
    need(v==expected_v,'DISCOVERY_VERIFICATION_SEMANTICS')
    need(x['status']=={'type':'WHP-REGISTRY-SNAPSHOT-v1','requires_fresh':True,'max_age_seconds':300},'DISCOVERY_STATUS_SEMANTICS')
    need(p['current_status_rule']=='This immutable record proves issuance-time assessment. Current standing requires a fresh signed registry response and current trust/revocation information.','CURRENT_STATUS_SEMANTICS')

def verify_registry(snapshot,result,raw_result,pin,at):
    schema=json.loads(zlib.decompress(base64.b64decode(RESULT_SCHEMA_B64)));schema.pop('oneOf',None);schema['$ref']='#/$defs/registry_snapshot'
    need(not list(Draft202012Validator(schema).iter_errors(snapshot)),'REGISTRY_SCHEMA_INVALID')
    p=result['payload'];sp=snapshot['payload']
    exact(sp,['purchase_id','result_hash','mark_id','status','observed_at','valid_until','events','trust_bundle'])
    pa,keys,rev=trust(sp['trust_bundle'],pin,at)
    need(pa['environment']==p['environment'] and pa['issuer']==p['issuer'],'REGISTRY_AUTHORITY_CONTEXT')
    grant(snapshot,'WHP-REGISTRY-SNAPSHOT-v1','REGISTRY',p['submission']['bounds'],keys,rev,at)
    need(sp['observed_at']<=at+30 and at<sp['valid_until']<=sp['observed_at']+300,'REGISTRY_SNAPSHOT_STALE')
    need(sp['purchase_id']==p['purchase_id'] and sp['result_hash']==bytehash(raw_result) and sp['mark_id']==p['mark_id'],'REGISTRY_RESULT_BINDING')
    previous=None;last=None
    for i,e in enumerate(sp['events']):
        ep=e['payload'];exact(ep,['purchase_id','sequence','previous_hash','result_hash','mark_id','status','at','reason','command']);grant(e,'WHP-REGISTRY-EVENT-v1','REGISTRY',p['submission']['bounds'],keys,rev,ep['at'])
        need(ep['sequence']==i and ep['previous_hash']==previous and ep['purchase_id']==p['purchase_id'] and ep['result_hash']==sp['result_hash'] and ep['mark_id']==p['mark_id'],'REGISTRY_CHAIN_INVALID')
        if i==0:need(ep['status']==('ACTIVE' if p['mark_id'] else 'ASSESSED_NO_MARK') and ep['command'] is None,'REGISTRY_ORIGIN_INVALID')
        else:
            cp=unseal(ep['command'],'WHP-REGISTRY-COMMAND-v1',sp['trust_bundle']['root_public_key'])
            exact(cp,['purchase_id','expected_previous_hash','status','reason','at'])
            need(cp['status'] in ['ACTIVE','SUSPENDED','WITHDRAWN','SUPERSEDED','DISPUTED','LIMITED'],'REGISTRY_COMMAND_STATUS')
            need(cp['expected_previous_hash']==previous and cp['purchase_id']==ep['purchase_id'] and cp['status']==ep['status'] and cp['reason']==ep['reason'] and cp['at']==ep['at'],'REGISTRY_COMMAND_BINDING')
            need(last['status'] not in ['WITHDRAWN','SUPERSEDED'] and ep['at']>=last['at'],'REGISTRY_TRANSITION_INVALID')
        previous=digest(e);last=ep
    need(last is not None,'REGISTRY_EMPTY')
    expected='EXPIRED' if last['status']=='ACTIVE' and at>=p['expires_at'] else last['status']
    if expected=='ACTIVE':
        try:
            grant(result,result['protected']['type'],'ISSUER',p['submission']['bounds'],keys,rev,at)
            for source in p['submission']['nodes']:grant(source,'WHP-SOURCE-ATTESTATION-v1','SOURCE',{**p['submission']['bounds'],'operations':source['payload']['operations']},keys,rev,at)
            for edge in p['submission']['transitions']:grant(edge,'WHP-TRANSITION-WARRANT-v1','TRANSITION',{**p['submission']['bounds'],'operations':edge['payload']['operations']},keys,rev,at)
        except Exception:expected='LIMITED'
    need(sp['status']==expected,'REGISTRY_STATUS_MISMATCH')
    return expected

def recheck_chain(p,rpc_url):
    need(rpc_url.startswith('https://'),'HTTPS_RPC_REQUIRED');need(p['environment']=='LIVE','TEST_PAYMENT_HAS_NO_CHAIN_FINALITY')
    pay=p['commerce']['payment_payload'];r=pay['accepted'];a=pay['payload']['authorization'];s=p['commerce']['settlement'];txid=s['transaction']
    def rpc(method,params):
        body=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
        req=urllib.request.Request(rpc_url,data=body,headers={'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=15) as f:answer=json.load(f)
        need('error' not in answer,'RPC_ERROR');return answer['result']
    need('eip155:'+str(int(rpc('eth_chainId',[]),16))==r['network'],'RPC_CHAIN_MISMATCH')
    receipt=rpc('eth_getTransactionReceipt',[txid]);tx=rpc('eth_getTransactionByHash',[txid]);head=rpc('eth_getBlockByNumber',['finalized',False])
    need(receipt and tx and head and receipt['status']=='0x1' and int(receipt['blockNumber'],16)<=int(head['number'],16),'SETTLEMENT_NOT_FINALIZED')
    block=rpc('eth_getBlockByNumber',[receipt['blockNumber'],False]);need(block['hash']==receipt['blockHash']==tx['blockHash']==s['block_hash'],'BLOCK_IDENTITY_MISMATCH')
    need(tx['to'].lower()==r['asset'].lower() and tx['hash'].lower()==txid,'WRONG_PAYMENT_TRANSACTION')
    w=lambda n:format(int(n),'064x')
    sig=pay['payload']['signature'][2:].lower();v=int(sig[-2:],16);v=v+27 if v<27 else v
    expected='0xe3ee160e'+a['from'][2:].lower().rjust(64,'0')+a['to'][2:].lower().rjust(64,'0')+w(a['value'])+w(a['validAfter'])+w(a['validBefore'])+a['nonce'][2:].lower()+w(v)+sig[:64]+sig[64:128]
    need(tx['input'].lower()==expected==s['transaction_input'].lower(),'TRANSFER_CALLDATA_MISMATCH')
    topic=lambda addr:'0x'+addr[2:].lower().rjust(64,'0')
    logs=[l for l in receipt['logs'] if l['address'].lower()==r['asset'].lower() and not l.get('removed',False) and l['transactionHash'].lower()==txid and l['blockHash']==receipt['blockHash']]
    auth=[l for l in logs if [x.lower() for x in l['topics']]==['0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5',topic(a['from']),a['nonce'].lower()]]
    transfer=[l for l in logs if [x.lower() for x in l['topics']]==['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',topic(a['from']),topic(a['to'])] and int(l['data'],16)==int(a['value'])]
    need(len(auth)==1 and len(transfer)==1,'PAYMENT_EVENT_IDENTITY_MISMATCH')
    return 'FINALIZED_RECHECKED_AGAINST_SUPPLIED_RPC'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('mark');parser.add_argument('--root-pin',required=True);parser.add_argument('--allow-test',action='store_true');parser.add_argument('--registry');parser.add_argument('--at',type=int);parser.add_argument('--rpc')
    args=parser.parse_args()
    try:
        e,raw=read(args.mark);report=verify_result(e,args.root_pin,args.allow_test)
        if args.registry:report['current_standing']=verify_registry(read(args.registry)[0],e,raw,args.root_pin,args.at or int(time.time()))
        if args.rpc:report['payment_chain_finality']=recheck_chain(e['payload'],args.rpc)
        report['live_completion_verified']=report['environment']=='LIVE' and report['mark_id'] is not None and report['current_standing']=='ACTIVE' and report['payment_chain_finality']=='FINALIZED_RECHECKED_AGAINST_SUPPLIED_RPC'
        print(json.dumps(report,indent=2));return 0
    except Exception as error:
        print(json.dumps({'verified':False,'error':str(error) or type(error).__name__}));return 1
if __name__=='__main__':sys.exit(main())
