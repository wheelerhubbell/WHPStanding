#!/usr/bin/env python3
"""Generic signed-artifact cold reader: the sole input is one artifact file.
No issuer names, service paths, profile IDs, keys, clock overrides or repository imports.
Protocol details and independent verification code are learned from the artifact's links.
Downloaded code executes only in a no-network read-only OCI sandbox without host secrets.
This program reaches a payment boundary. It NEVER controls a wallet or pays.
"""
import base64,hashlib,json,os,pathlib,secrets,subprocess,sys,tempfile,time,urllib.request,urllib.error,urllib.parse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,load_der_public_key


def need(value,message):
    if not value:raise ValueError(message)

def pairs(items):
    out={}
    for k,v in items:
        need(k not in out,'DUPLICATE_JSON_KEY');out[k]=v
    return out

def canon(x,depth=0):
    need(depth<=64,'JSON_DEPTH')
    if x is None:return 'null'
    if isinstance(x,bool):return 'true' if x else 'false'
    if isinstance(x,int):need(abs(x)<=9007199254740991,'INTEGER_RANGE');return str(x)
    if isinstance(x,str):
        need(not any(0xd800<=ord(c)<=0xdfff for c in x),'UNICODE');return json.dumps(x,ensure_ascii=False,separators=(',',':'))
    if isinstance(x,list):return '['+','.join(canon(v,depth+1) for v in x)+']'
    need(isinstance(x,dict),'INTEGER_JSON_REQUIRED')
    return '{'+','.join(canon(k,depth+1)+':'+canon(x[k],depth+1) for k in sorted(x,key=lambda s:s.encode('utf-16be')))+'}'

def parse(raw):
    result=json.loads(raw,object_pairs_hook=pairs,parse_float=lambda _:(_ for _ in ()).throw(ValueError('FLOAT_NOT_ALLOWED')))
    canon(result);return result

def sha(raw):return hashlib.sha256(raw).hexdigest()
def pointer(obj,p):
    need(isinstance(p,str) and (not p or p.startswith('/')),'JSON_POINTER')
    for k in p.split('/')[1:]:
        k=k.replace('~1','/').replace('~0','~');obj=obj[int(k)] if isinstance(obj,list) else obj[k]
    return obj

def signature(envelope,pub,recipe):
    need(set(envelope)=={'protected','payload','signature'},'SIGNED_ENVELOPE')
    need(envelope['protected']['algorithm']==recipe['algorithm']=='Ed25519','SIGNATURE_ALGORITHM')
    need(envelope['protected']['canonicalization']==recipe['canonicalization'],'CANONICALIZATION_CONTEXT')
    der=base64.b64decode(pub,validate=True);key=load_der_public_key(der);need(isinstance(key,Ed25519PublicKey),'KEY_ALGORITHM')
    need(sha(der)==envelope['protected']['key_id'],'SIGNING_KEY_ID')
    key.verify(base64.b64decode(envelope['signature'],validate=True),canon({k:envelope[k] for k in recipe['signed_fields']}).encode())

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('REDIRECT_NOT_ALLOWED')


def run(mark_path):
    raw=pathlib.Path(mark_path).read_bytes();need(len(raw)<=2_000_000,'ARTIFACT_SIZE');mark=parse(raw)
    carrier=mark['payload']['discovery'];need(carrier['format']=='signed-artifact-discovery-v1','DISCOVERY_CARRIER_REQUIRED')
    origin=urllib.parse.urlsplit(carrier['service_url']);need(not origin.username and not origin.password and origin.path in ['', '/'] and not origin.query and not origin.fragment,'CANONICAL_ORIGIN')
    test=carrier['environment']=='TEST';need(origin.scheme=='https' or (test and origin.scheme=='http' and origin.hostname=='127.0.0.1'),'HTTPS_REQUIRED')
    recipe=carrier['verification'];trace=[]
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def request(url,method='GET',data=None,headers={}):
        u=urllib.parse.urlsplit(url);need((u.scheme,u.netloc)==(origin.scheme,origin.netloc) and not u.username and not u.fragment,'CROSS_ORIGIN_DISCOVERY')
        req=urllib.request.Request(url,data=data,headers=headers,method=method)
        try:r=opener.open(req,timeout=20)
        except urllib.error.HTTPError as e:r=e
        with r:
            body=r.read(2_000_001);need(len(body)<=2_000_000,'RESPONSE_SIZE');trace.append({'url':url,'method':method,'status':r.status,'sha256':sha(body)});return r.status,dict(r.headers),body
    def document(url):
        status,_,body=request(url);need(status==200,'DISCOVERY_FETCH_'+str(status));return parse(body)
    # The origin pin is acquired through the artifact's published discovery route, never injected.
    service=document(carrier['discovery_url']);root=pointer(service,recipe['root_pointer']);pin=pointer(service,recipe['pin_pointer'])
    need(pin==sha(base64.b64decode(root,validate=True)),'ROOT_PIN_DIGEST')
    need(root==pointer(mark,recipe['embedded_root_pointer']),'ROOT_SUBSTITUTION')
    certificates=pointer(mark,recipe['certificates_pointer']);matched=[]
    for cert in certificates:
        signature(cert,root,recipe)
        if sha(base64.b64decode(pointer(cert,recipe['certificate_key_pointer']),validate=True))==mark['protected']['key_id']:matched.append(pointer(cert,recipe['certificate_key_pointer']))
    need(len(matched)==1,'ISSUER_CERTIFICATE');signature(mark,matched[0],recipe)
    need(carrier['meaning']['establishes'] and carrier['meaning']['does_not_establish'],'MEANING_BOUNDS_REQUIRED')
    # Resolve all concrete meaning pointers; an absent limitation/authority is not knowledge.
    for k in ['scope_pointer','authority_pointer','provenance_pointer','limitations_pointer']:pointer(mark,carrier['meaning'][k])
    verification=document(recipe['url']);need(verification['source']['sha256']==recipe['source_sha256'] and verification['source']['url']==recipe['source_url'],'VERIFIER_MANIFEST_BINDING')
    status,_,code=request(recipe['source_url']);need(status==200 and sha(code)==recipe['source_sha256'],'VERIFIER_SOURCE_HASH')
    profile=document(carrier['profile']['url']);need(sha(canon(profile['profile']).encode())==carrier['profile']['sha256']==profile['sha256'],'PROFILE_HASH')
    need(profile['profile']['id']==carrier['profile']['id'] and profile['profile']['version']==carrier['profile']['version'],'PROFILE_VERSION')
    status,_,registry_bytes=request(carrier['registry_url']);need(status==200,'REGISTRY_UNAVAILABLE')
    # Only public downloaded artifacts enter the sandbox; no producer source or configuration is mounted.
    with tempfile.TemporaryDirectory(prefix='cold-public-') as directory:
        d=pathlib.Path(directory);(d/'artifact.json').write_bytes(raw);(d/'registry.json').write_bytes(registry_bytes);(d/'verifier.py').write_bytes(code)
        d.chmod(0o755)
        for path in d.iterdir():path.chmod(0o444)
        replacements={'{mark}':'/input/artifact.json','{registry}':'/input/registry.json','{root_pin}':pin}
        args=[replacements.get(arg,arg) for arg in verification['invocation']['arguments']]
        if test:args+=verification['invocation']['test_arguments']
        # The pre-built image contains Python and generic crypto libraries ONLY, no protocol source.
        image='cold-python-crypto:1'
        inspected=subprocess.run(['docker','image','inspect',image,'--format','{{.Id}}'],capture_output=True,text=True,timeout=30)
        need(inspected.returncode==0,'GENERIC_SANDBOX_RUNTIME_REQUIRED')
        cmd=['docker','run','--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=32','--memory=256m','--cpus=1','--user=65534:65534','--tmpfs=/tmp:rw,noexec,nosuid,size=16m','--mount','type=bind,src='+str(d)+',dst=/input,readonly',image,'python3','-I','/input/verifier.py',*args]
        executed=subprocess.run(cmd,capture_output=True,text=True,timeout=45)
        need(executed.returncode==0,'INDEPENDENT_VERIFICATION_FAILED:'+executed.stdout[:1000]);report=parse(executed.stdout)
        need(report['verified'] is True and report['current_standing']=='ACTIVE','CURRENT_STANDING_NOT_ACTIVE')
    purchase=document(carrier['contract_url']);need(purchase['service']==carrier['service'] and purchase['profile']['sha256']==carrier['profile']['sha256'],'CONTRACT_IDENTITY')
    offer=purchase['purchase'];need(offer['url']==carrier['purchase']['url'] and offer['method']==carrier['purchase']['method'],'PURCHASE_BINDING')
    schema=document(offer['input_schema']);need(offer['input_schema']==carrier['purchase']['input_schema'],'SCHEMA_LOCATION')
    probe=purchase['cold_probe'];need(probe['wallet_signing'] is False,'PROBE_MUST_NOT_PAY')
    submission=json.loads(json.dumps(pointer(mark,probe['base_document_pointer'])))
    key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
    for field,source in probe['replacements'].items():
        need(source in ['generated-Ed25519-SPKI','random-32-byte-hex'],'UNSUPPORTED_PROBE_SOURCE');submission[field]=base64.b64encode(pub).decode() if source=='generated-Ed25519-SPKI' else secrets.token_hex(32)
    from jsonschema import Draft202012Validator
    Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(submission)
    body=canon(submission).encode();auth=purchase['authentication'];now=int(time.time());url=urllib.parse.urlsplit(offer['url']);path=url.path+('?' + url.query if url.query else '')
    need(auth['key_algorithm']=='Ed25519' and auth['key_id']=='SHA256-SPKI-DER','AUTHENTICATION_RECIPE')
    values={'HTTP-method':offer['method'],'URL-path-and-query':path,'SHA256-exact-request-bytes':sha(body),'Unix-seconds':now,'Unix-seconds-plus-120':now+120,'random-16-byte-hex':secrets.token_hex(16)}
    protected={**auth['protected'],'key_id':sha(pub)};payload={k:values[v] for k,v in auth['payload_fields'].items()}
    signed={'protected':protected,'payload':payload};proof={**signed,'signature':base64.b64encode(key.sign(canon({k:signed[k] for k in auth['signed_fields']}).encode())).decode()}
    proof_header=base64.b64encode(canon(proof).encode()).decode()
    status,response_headers,terms_bytes=request(offer['url'],offer['method'],body,{'Content-Type':offer['content_type'],auth['header']:proof_header})
    need(status==402,'PAYMENT_BOUNDARY_NOT_REACHED:'+str(status));terms=parse(terms_bytes)
    headers={k.lower():v for k,v in response_headers.items()};payment=purchase['payment'];header=parse(base64.b64decode(headers[payment['required_header'].lower()],validate=True));need(header==terms,'PAYMENT_HEADER_BINDING')
    quote=pointer(terms,payment['quote_pointer']);signature(quote,matched[0],recipe)
    need(quote['payload']['request_hash']==sha(body),'QUOTE_INPUT_BINDING')
    need(pointer(terms,payment['requirements_pointer'])==offer['requirements'],'PUBLISHED_PAYMENT_REQUIREMENTS')
    return {'verified':True,'environment':carrier['environment'],'completed_path':['Mark','meaning','independent cryptographic verification and replay','discovery','applicable profile','purchase contract','payment boundary'],
      'input_files':1,'prior_issuer_configuration':False,'repository_imports':False,'root_pin_source':carrier['discovery_url'],
      'meaning':carrier['meaning'],'independent_verifier':report,'sandbox_image':inspected.stdout.strip(),'sandbox_network':'none','sandbox_host_mounts':'only public downloaded artifacts, read-only',
      'payment_status':status,'payment_authorizations_created':0,'wallet_keys_available':False,'payment_terms':terms,
      'trace':trace,'trust_limit':'The discovered root is bound to the authenticated HTTPS origin. Legal institutional attribution requires separate issuer admission; this traversal does not create it.',
      'PROPAGATION-PROVEN':False,'production_completion_claim':False}

if __name__=='__main__':
    try:
        need(len(sys.argv)==2,'ONE_ARTIFACT_INPUT_REQUIRED');print(json.dumps(run(sys.argv[1]),indent=2,ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'verified':False,'error':str(error) or type(error).__name__}));sys.exit(1)
