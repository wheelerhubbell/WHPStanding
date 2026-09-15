#!/usr/bin/env python3
"""Independent WHP Standing verifier. Imports no producer modules.
Requires Python >=3.11 and cryptography. Never treats an embedded root as trust.
Offline validity, current registry standing and chain settlement are separate outputs.
"""
import argparse, base64, hashlib, json, re, sys, time, urllib.request, urllib.parse
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE_HASH = 'dc25aa63cadad8b5b02ba3cbaac552ca8273c6d6793b4eefdef16aadd180046e'
OPS = ['INFORM', 'RECOMMEND', 'EXECUTE']

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
def read(path):
    raw = Path(path).read_bytes()
    need(len(raw) <= 2_000_000, 'FILE_TOO_LARGE')
    x = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                   parse_float=lambda _: (_ for _ in ()).throw(ValueError('FLOAT_NOT_ALLOWED')),
                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_NOT_ALLOWED')))
    canonical(x)
    return x, raw

def exact(x, fields): need(isinstance(x,dict) and set(x)==set(fields), 'FIELDS_INVALID')
def keyid(pub): return bytehash(base64.b64decode(pub,validate=True))
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
    need(pay['x402Version']==2 and r==qp['payment_requirements'] and pay['resource']==qp['resource'],'PAYMENT_TERMS_MISMATCH')
    nonce='0x'+digest({'domain':'WHP-STANDING-PURCHASE-BINDING-v1','quote':qp})
    need(a['nonce'].lower()==nonce and a['to'].lower()==r['payTo'].lower() and a['value']==r['amount'],'PAYMENT_PURCHASE_BINDING')
    identity=digest({'domain':'WHP-EIP3009-PAYMENT-IDENTITY-v1','network':r['network'],'asset':r['asset'].lower(),'authorizer':a['from'].lower(),'nonce':nonce})
    need(co['payment_identity']==identity and co['assessment_paid_by']==a['from'],'PAYMENT_IDENTITY_MISMATCH')
    for name,val in [('environment',p['environment']),('network',r['network']),('asset',r['asset']),('payer',a['from']),('pay_to',a['to']),('amount',a['value']),('nonce',a['nonce'])]: need(settle[name]==val,'SETTLEMENT_BINDING_'+name)
    need(re.fullmatch(r'0x[0-9a-f]{64}',settle['transaction']) is not None,'TRANSACTION_ID_INVALID')
    need(p['retrieval']=={'purchase_path':'/v1/purchases/'+pid,'result_path':'/v1/purchases/'+pid+'/result','registry_path':'/v1/registry/'+pid,'authentication':'Buyer Ed25519 proof bound to HTTP method, path and body','additional_charge':False},'RETRIEVAL_BINDING')
    verify_discovery(p)
    return {'verified':True,'cryptographic_integrity':'VERIFIED','evaluation_replay':'VERIFIED','environment':p['environment'],'purchase_id':pid,'mark_id':p['mark_id'],'assessment':d['outcome'],'current_standing':'NOT_CHECKED','payment_chain_finality':'NOT_RECHECKED' if p['environment']=='LIVE' else 'SIMULATED_NOT_LIVE','expires_at':p['expires_at']}


def verify_discovery(p):
    x=p['discovery'];o=urllib.parse.urlsplit(p['commerce']['quote']['payload']['resource']['url'])
    origin=o.scheme+'://'+o.netloc
    need(o.scheme=='https' or (p['environment']=='TEST' and o.scheme=='http' and o.hostname=='127.0.0.1'),'DISCOVERY_ORIGIN')
    need(not o.username and not o.password,'DISCOVERY_CREDENTIALS')
    exact(x,['format','service','capability','environment','publisher','meaning','service_url','service_id','discovery_url','contract_url','profile','registry_url','verification','purchase','links'])
    need(x['format']=='signed-artifact-discovery-v1' and x['service']=='WHP Standing' and x['environment']==p['environment'],'DISCOVERY_IDENTITY')
    need(x['capability']=='Machine-verifiable standing under explicit authority and bounds.','DISCOVERY_CAPABILITY')
    need(x['service_url']==origin and x['service_id']==origin+'/#whp-standing','DISCOVERY_SERVICE')
    need(x['publisher']['name']=='Wheeler Hubbell Publishing','DISCOVERY_PUBLISHER')
    relation='Issuer and seller of the WHP Standing Evaluation.' if p['environment']=='LIVE' else 'Intended production publisher only. This TEST artifact is not issued by Wheeler Hubbell Publishing.'
    need(x['publisher']['relationship']==relation,'DISCOVERY_ISSUER_RELATIONSHIP')
    meaning=x['meaning'];need(meaning['establishes']==p['profile']['assessed'] and meaning['does_not_establish']==p['limitations'],'DISCOVERY_SEMANTIC_PROMOTION')
    need(meaning['scope_pointer']=='/payload/standing/bounds' and meaning['authority_pointer']=='/payload/authority' and meaning['provenance_pointer']=='/payload/submission' and meaning['limitations_pointer']=='/payload/limitations','DISCOVERY_MEANING_POINTERS')
    expected=origin+'/v1/profiles/'+urllib.parse.quote(p['profile']['id'],safe='')+'/'+p['profile']['version']
    need(x['profile']=={'id':p['profile']['id'],'version':p['profile']['version'],'sha256':PROFILE_HASH,'url':expected},'DISCOVERY_PROFILE')
    for k,path in [('discovery_url','/.well-known/whp-standing.json'),('contract_url','/v1/contract'),('registry_url','/v1/registry/'+p['purchase_id'])]:need(x[k]==origin+path,'DISCOVERY_URL_'+k)
    v=x['verification'];need(v['url']==origin+'/v1/verification' and re.fullmatch('[0-9a-f]{64}',v['source_sha256']) and v['source_url']==origin+'/verification/'+v['source_sha256']+'.py','DISCOVERY_VERIFIER')
    need(v['algorithm']=='Ed25519' and v['canonicalization']=='WHP-JCS-I1' and v['signed_fields']==['protected','payload'] and v['key_encoding']=='base64-DER-SPKI','DISCOVERY_CRYPTO')
    need(v['root_pointer']=='/root_public_key' and v['pin_pointer']=='/root_pin' and v['embedded_root_pointer']=='/payload/authority/root_public_key' and v['certificates_pointer']=='/payload/authority/certificates' and v['certificate_key_pointer']=='/payload/public_key','DISCOVERY_KEY_PATHS')
    need(x['purchase']=={'name':'WHP Standing Evaluation','url':origin+'/v1/evaluations','method':'POST','input_schema':origin+'/schemas/submission.schema.json','payment_protocol':'x402-v2','required_extension':'whp-standing','owner_authorization_required':True},'DISCOVERY_PAYMENT')
    need(x['links']==[{'rel':'service-meta','href':origin+'/.well-known/whp-standing.json'},{'rel':'service-desc','href':origin+'/v1/openapi.json'},{'rel':'profile','href':expected},{'rel':'status','href':origin+'/v1/registry/'+p['purchase_id']},{'rel':'api-catalog','href':origin+'/.well-known/api-catalog'}],'DISCOVERY_LINKS')

def verify_registry(snapshot,result,raw_result,pin,at):
    p=result['payload'];sp=snapshot['payload'];pa,keys,rev=trust(sp['trust_bundle'],pin,at)
    grant(snapshot,'WHP-REGISTRY-SNAPSHOT-v1','REGISTRY',p['submission']['bounds'],keys,rev,at)
    need(sp['observed_at']<=at+30 and at<sp['valid_until']<=sp['observed_at']+300,'REGISTRY_SNAPSHOT_STALE')
    need(sp['purchase_id']==p['purchase_id'] and sp['result_hash']==bytehash(raw_result) and sp['mark_id']==p['mark_id'],'REGISTRY_RESULT_BINDING')
    previous=None;last=None
    for i,e in enumerate(sp['events']):
        ep=e['payload'];grant(e,'WHP-REGISTRY-EVENT-v1','REGISTRY',p['submission']['bounds'],keys,rev,ep['at'])
        need(ep['sequence']==i and ep['previous_hash']==previous and ep['purchase_id']==p['purchase_id'] and ep['result_hash']==sp['result_hash'] and ep['mark_id']==p['mark_id'],'REGISTRY_CHAIN_INVALID')
        if i==0:need(ep['status']==('ACTIVE' if p['mark_id'] else 'ASSESSED_NO_MARK') and ep['command'] is None,'REGISTRY_ORIGIN_INVALID')
        else:
            cp=unseal(ep['command'],'WHP-REGISTRY-COMMAND-v1',sp['trust_bundle']['root_public_key'])
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
