#!/usr/bin/env python3
"""Generic cold reader. One declared input; no product configuration or producer imports.
An artifact carries its bootstrap. A need carries a vendor-neutral directory interface.
Downloaded replay code runs in a read-only, networkless, least-privilege OCI sandbox.
This program creates HTTP authentication keys only. It never has a wallet or pays.
"""
import base64, hashlib, ipaddress, json, pathlib, secrets, socket, subprocess, sys, tempfile, time
import urllib.request, urllib.error, urllib.parse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from jsonschema import Draft202012Validator


def need(value, message):
    if not value: raise ValueError(message)


def exact(obj, fields):
    need(isinstance(obj, dict) and set(obj) == set(fields), 'CLOSED_FIELDS:' + ','.join(fields))


def pairs(items):
    obj = {}
    for key, value in items:
        need(key not in obj, 'DUPLICATE_KEY'); obj[key] = value
    return obj


def integer(text):
    need(text != '-0', 'NEGATIVE_ZERO'); number = int(text)
    need(abs(number) <= 9007199254740991, 'UNSAFE_INTEGER'); return number


def noninteger(_): raise ValueError('INTEGER_LEXEME_REQUIRED')


def parse(raw):
    if isinstance(raw, bytes): raw = raw.decode('utf-8', 'strict')
    obj = json.loads(raw, object_pairs_hook=pairs, parse_int=integer, parse_float=noninteger, parse_constant=noninteger)
    canon(obj); return obj


def canon(value, depth=0):
    need(depth <= 64, 'DEPTH_LIMIT')
    if value is None: return 'null'
    if value is True: return 'true'
    if value is False: return 'false'
    if isinstance(value, int):
        need(abs(value) <= 9007199254740991, 'UNSAFE_INTEGER'); return str(value)
    if isinstance(value, str):
        value.encode('utf-8', 'strict'); return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if isinstance(value, list): return '[' + ','.join(canon(x, depth+1) for x in value) + ']'
    need(isinstance(value, dict), 'JSON_TYPE')
    keys = sorted(value, key=lambda x: x.encode('utf-16-be', 'strict'))
    return '{' + ','.join(canon(k, depth+1)+':'+canon(value[k], depth+1) for k in keys) + '}'


def sha(raw): return hashlib.sha256(raw).hexdigest()
def digest(obj): return sha(canon(obj).encode('utf-8'))


def b64(text):
    need(isinstance(text, str), 'BASE64_TYPE'); raw = base64.b64decode(text, validate=True)
    need(base64.b64encode(raw).decode() == text, 'BASE64_CANONICAL'); return raw


def public(text):
    der = b64(text); key = load_der_public_key(der)
    need(isinstance(key, Ed25519PublicKey), 'ED25519_REQUIRED')
    need(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == der, 'CANONICAL_SPKI')
    return key, sha(der)


def signature(e, pub, recipe=None, typ=None):
    exact(e, ['protected', 'payload', 'signature'])
    p = e['protected']; exact(p, ['type', 'algorithm', 'canonicalization', 'key_id'])
    need(p['algorithm'] == 'Ed25519', 'ALGORITHM')
    need(isinstance(p['type'], str) and 0 < len(p['type']) < 128, 'SIGNATURE_CONTEXT')
    if typ is not None: need(p['type'] == typ, 'SIGNATURE_TYPE')
    if recipe is not None:
        need(p['algorithm'] == recipe['algorithm'] and p['canonicalization'] == recipe['canonicalization'], 'SIGNATURE_RECIPE')
        need(recipe['signed_fields'] == ['protected', 'payload'], 'SIGNATURE_INPUT')
    key, pin = public(pub); need(pin == p['key_id'], 'SIGNING_KEY_ID')
    sig = b64(e['signature']); need(len(sig) == 64, 'SIGNATURE_SIZE')
    key.verify(sig, canon({'protected': p, 'payload': e['payload']}).encode('utf-8'))
    return e['payload']


def pointer(obj, path):
    need(isinstance(path, str) and (not path or path.startswith('/')), 'JSON_POINTER')
    for key in path.split('/')[1:]:
        key = key.replace('~1', '/').replace('~0', '~')
        obj = obj[int(key)] if isinstance(obj, list) else obj[key]
    return obj


def interval(p, now):
    need(type(p['valid_from']) is int and type(p['valid_until']) is int, 'TIME_TYPE')
    need(p['valid_from'] <= now < p['valid_until'], 'AUTHORITY_NOT_CURRENT')


TRUST_EPOCHS = {}
RESOLUTION_STATES = {}


def root_bundle(bundle, pin, now, recipe, remember=True):
    exact(bundle, ['root_public_key', 'profile_authorization', 'certificates', 'revocations', 'status_snapshot'])
    root = bundle['root_public_key']; need(public(root)[1] == pin, 'ROOT_SUBSTITUTION')
    pa = signature(bundle['profile_authorization'], root, recipe)
    exact(pa, ['profile_hash', 'ratified', 'issuer', 'environment', 'valid_from', 'valid_until'])
    need(pa['ratified'] is True and pa['environment'] in ['TEST', 'LIVE'], 'PROFILE_AUTHORITY'); interval(pa, now)
    status = signature(bundle['status_snapshot'], root, recipe)
    exact(status, ['sequence', 'previous_hash', 'profile_authorization_hash', 'certificates_hash', 'revocations_hash', 'valid_from', 'valid_until'])
    interval(status, now); need(type(status['sequence']) is int and status['sequence'] >= 0, 'TRUST_SEQUENCE')
    need(status['profile_authorization_hash'] == digest(bundle['profile_authorization']) and status['certificates_hash'] == digest(bundle['certificates']) and status['revocations_hash'] == digest(bundle['revocations']), 'TRUST_MANIFEST')
    need(isinstance(bundle['certificates'], list) and len(bundle['certificates']) <= 128 and isinstance(bundle['revocations'], list) and len(bundle['revocations']) <= 128, 'AUTHORITY_SIZE')
    revoked = []
    for envelope in bundle['revocations']:
        r = signature(envelope, root, recipe); exact(r, ['key_id', 'effective_at', 'reason'])
        need(type(r['effective_at']) is int, 'REVOCATION_TIME'); revoked.append(r)
    certificates = {}
    for envelope in bundle['certificates']:
        c = signature(envelope, root, recipe)
        exact(c, ['public_key', 'subject', 'roles', 'scopes', 'jurisdictions', 'operations', 'profile_hash', 'valid_from', 'valid_until'])
        kid = public(c['public_key'])[1]; need(kid not in certificates, 'DUPLICATE_AUTHORITY')
        need(c['profile_hash'] == pa['profile_hash'], 'CERTIFICATE_PROFILE')
        for name in ['roles', 'scopes', 'jurisdictions', 'operations']:
            need(isinstance(c[name], list) and len(c[name]) <= 64 and all(isinstance(x, str) for x in c[name]), 'CERTIFICATE_SET')
        certificates[kid] = c
    if remember:
        context=(pin,pa['profile_hash']);state=(status['sequence'],digest(bundle['status_snapshot']))
        prior=TRUST_EPOCHS.get(context)
        need(prior is None or (state[0]>=prior[0] and (state[0]!=prior[0] or state[1]==prior[1])), 'TRUST_ROLLBACK_OR_EQUIVOCATION')
        TRUST_EPOCHS[context]=state
    return {'pin': pin, 'root': root, 'profile': pa, 'status': status, 'certificates': certificates, 'revocations': revoked}


def authority(trust, key, role, at):
    c = trust['certificates'][key]; need(role in c['roles'], 'ROLE_NOT_AUTHORIZED'); interval(c, at)
    need(not any(r['key_id'] == key and r['effective_at'] <= at for r in trust['revocations']), 'AUTHORITY_REVOKED')
    return c


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): raise ValueError('REDIRECT_NOT_ALLOWED')


class Network:
    def __init__(self):
        self.origins = set(); self.trace = []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def admit(self, url, test):
        u = urllib.parse.urlsplit(url)
        need(not u.username and not u.password and not u.fragment and not u.query and u.hostname, 'URL_SHAPE')
        if u.scheme == 'http': need(test and u.hostname == '127.0.0.1', 'LOOPBACK_TEST_ONLY')
        else:
            need(u.scheme == 'https', 'HTTPS_REQUIRED')
            for address in socket.getaddrinfo(u.hostname, u.port or 443, type=socket.SOCK_STREAM):
                need(ipaddress.ip_address(address[4][0]).is_global, 'PRIVATE_NETWORK_FORBIDDEN')
        self.origins.add((u.scheme, u.netloc))

    def request(self, url, method='GET', data=None, headers=None):
        u = urllib.parse.urlsplit(url)
        need((u.scheme, u.netloc) in self.origins and not u.username and not u.password and not u.fragment, 'UNRESOLVED_ORIGIN')
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try: response = self.opener.open(req, timeout=15)
        except urllib.error.HTTPError as error: response = error
        with response:
            raw = response.read(2_000_001); need(len(raw) <= 2_000_000, 'RESPONSE_SIZE')
            self.trace.append({'url': url, 'method': method, 'status': response.status, 'sha256': sha(raw)})
            return response.status, dict(response.headers), raw

    def document(self, url, commitment=None):
        status, _, raw = self.request(url); need(status == 200, 'FETCH_FAILED:' + str(status))
        obj = parse(raw)
        if commitment: need(digest(obj) == commitment, 'DOCUMENT_HASH')
        return obj


def resolve(net, descriptor, pin, environment, capability_id, recipe):
    now = int(time.time()); net.admit(descriptor['id'], environment == 'TEST')
    e = net.document(descriptor['id']); p = e['payload']
    exact(p, ['version', 'resolution_id', 'capability_id', 'environment', 'issuer_key_id', 'sequence', 'previous_hash', 'observed_at', 'valid_until', 'authority', 'provider'])
    need(e['protected']['type'] == p['version'] == descriptor['format'], 'RESOLUTION_CONTRACT')
    need(p['resolution_id'] == descriptor['id'] and p['capability_id'] == capability_id and p['environment'] == environment, 'RESOLUTION_IDENTITY')
    need(type(p['observed_at']) is int and type(p['valid_until']) is int and now-300 <= p['observed_at'] <= now+30 and now < p['valid_until'] <= p['observed_at']+descriptor['max_age_seconds'], 'STALE_RESOLUTION')
    need(type(p['sequence']) is int and p['sequence'] >= 0, 'RESOLUTION_SEQUENCE')
    need(p['previous_hash'] is None or (isinstance(p['previous_hash'], str) and len(bytes.fromhex(p['previous_hash'])) == 32), 'RESOLUTION_PREVIOUS_HASH')
    trust = root_bundle(p['authority'], pin, now, recipe)
    need(trust['profile']['environment'] == environment, 'RESOLUTION_ENVIRONMENT')
    cert = authority(trust, p['issuer_key_id'], descriptor['authority_role'], now)
    need(p['valid_until'] <= min(cert['valid_until'], trust['status']['valid_until'], trust['profile']['valid_until']), 'RESOLUTION_AUTHORITY_EXPIRY')
    signature(e, cert['public_key'], recipe, descriptor['format'])
    provider = p['provider']
    exact(provider, ['id', 'name', 'publisher', 'service_origin', 'compatible_requirements', 'contract', 'openapi', 'profile', 'material_url_template', 'registry_url_template', 'discovery_url'])
    need(provider['id'] == capability_id and provider['publisher'] == trust['profile']['issuer'], 'PROVIDER_IDENTITY')
    for key in ['contract', 'openapi']: exact(provider[key], ['url', 'sha256'])
    exact(provider['profile'], ['id', 'version', 'sha256', 'url'])
    need(provider['profile']['sha256'] == trust['profile']['profile_hash'], 'OFFER_PROFILE_AUTHORITY')
    o = urllib.parse.urlsplit(provider['service_origin']); need(o.path in ['', '/'] and not o.query, 'SERVICE_ORIGIN')
    net.admit(provider['service_origin'], environment == 'TEST')
    for url in [provider['contract']['url'], provider['openapi']['url'], provider['profile']['url'], provider['material_url_template'], provider['registry_url_template'], provider['discovery_url']]:
        u = urllib.parse.urlsplit(url); need((u.scheme, u.netloc) == (o.scheme, o.netloc), 'UNAUTHORIZED_SERVICE_LINK')
    context=(capability_id,descriptor['id']);state=(p['sequence'],digest(provider));prior=RESOLUTION_STATES.get(context)
    need(prior is None or (state[0]>=prior[0] and (state[0]!=prior[0] or state[1]==prior[1])), 'RESOLUTION_ROLLBACK_OR_EQUIVOCATION')
    need((p['sequence']==0)==(p['previous_hash'] is None), 'RESOLUTION_PREDECESSOR')
    if prior is not None and state[0]==prior[0]+1: need(p['previous_hash']==prior[1], 'RESOLUTION_PREDECESSOR_BINDING')
    RESOLUTION_STATES[context]=state
    return p, trust


def current_offer(net, resolution, requirement):
    provider = resolution['provider']
    need(requirement in provider['compatible_requirements'], 'PROVIDER_INCOMPATIBLE')
    c = net.document(provider['contract']['url'], provider['contract']['sha256'])
    need(c['capability_id'] == provider['id'] and c['environment'] == resolution['environment'] and requirement in c['compatible_requirements'], 'CONTRACT_IDENTITY')
    api = net.document(provider['openapi']['url'], provider['openapi']['sha256'])
    need(provider['service_origin'] in [s['url'] for s in api['servers']], 'OPENAPI_SERVER')
    profile = net.document(provider['profile']['url'], provider['profile']['sha256'])
    need(c['profile']['sha256'] == provider['profile']['sha256'] and c['profile']['id'] == profile['id'] and c['profile']['version'] == profile['version'], 'CURRENT_PROFILE_BINDING')
    offer = c['purchase']; u = urllib.parse.urlsplit(offer['url']); o = urllib.parse.urlsplit(provider['service_origin'])
    need((u.scheme, u.netloc) == (o.scheme, o.netloc) and not u.query and offer['method'].lower() in api['paths'][u.path], 'PURCHASE_OPENAPI')
    schema = net.document(offer['input_schema'], offer['input_schema_sha256'])
    Draft202012Validator.check_schema(schema)
    # Never allow a remotely fetched schema to initiate an uncommitted second fetch.
    def refs(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == '$ref': need(v.startswith('#/'), 'EXTERNAL_SCHEMA_REFERENCE')
                refs(v)
        elif isinstance(x, list):
            for v in x: refs(v)
    refs(schema)
    return c, schema


def authenticate_and_probe(net, contract, schema, submission, key, trust, recipe):
    Draft202012Validator(schema).validate(submission)
    offer = contract['purchase']; body = canon(submission).encode(); auth = contract['authentication']; now = int(time.time())
    need(auth['key_algorithm'] == 'Ed25519' and auth['key_id'] == 'SHA256-SPKI-DER' and auth['signed_fields'] == ['protected', 'payload'], 'HTTP_AUTHENTICATION_RECIPE')
    pub = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    url = urllib.parse.urlsplit(offer['url']); path = url.path + ('?' + url.query if url.query else '')
    values = {'HTTP-method': offer['method'], 'URL-path-and-query': path, 'SHA256-exact-request-bytes': sha(body), 'Unix-seconds': now, 'Unix-seconds-plus-120': now+120, 'random-16-byte-hex': secrets.token_hex(16)}
    proof = {'protected': {**auth['protected'], 'key_id': sha(pub)}, 'payload': {k: values[v] for k, v in auth['payload_fields'].items()}}
    proof['signature'] = base64.b64encode(key.sign(canon(proof).encode())).decode()
    status, headers, raw = net.request(offer['url'], offer['method'], body, {'Content-Type': offer['content_type'], auth['header']: base64.b64encode(canon(proof).encode()).decode()})
    need(status == 402, 'PAYMENT_BOUNDARY_NOT_REACHED:' + str(status) + ':' + raw[:400].decode(errors='replace'))
    terms = parse(raw); headers = {k.lower(): v for k, v in headers.items()}; payment = contract['payment']
    need(parse(b64(headers[payment['required_header'].lower()])) == terms, 'PAYMENT_HEADER_BINDING')
    need(terms['x402Version'] == 2 and len(terms['accepts']) == 1, 'PAYMENT_PROTOCOL')
    quote = pointer(terms, payment['quote_pointer']); q = quote['payload']
    cert = authority(trust, quote['protected']['key_id'], 'ISSUER', now); signature(quote, cert['public_key'], recipe)
    exact(q, ['purchase_id', 'request_hash', 'buyer_key', 'profile_hash', 'issuer', 'environment', 'issued_at', 'expires_at', 'resource', 'payment_requirements', 'charge_policy'])
    need(q['request_hash'] == sha(body) and q['buyer_key'] == base64.b64encode(pub).decode(), 'QUOTE_INPUT_BINDING')
    need(q['profile_hash'] == contract['profile']['sha256'] and q['issuer'] == trust['profile']['issuer'] and q['environment'] == contract['environment'], 'QUOTE_AUTHORITY_BINDING')
    need(now-30 <= q['issued_at'] <= now+30 and q['issued_at'] < q['expires_at'] and now < q['expires_at'], 'QUOTE_FRESHNESS')
    need(q['resource'] == terms['resource'] and q['resource']['url'] == offer['url'], 'QUOTE_RESOURCE_BINDING')
    need(q['payment_requirements'] == pointer(terms, payment['requirements_pointer']) == offer['requirements'], 'PAYMENT_TERMS_BINDING')
    return {'payment_status': status, 'purchase_url': offer['url'], 'payment_terms': terms, 'submitted_object': submission['object'], 'submitted_operation': submission['requested_operation'], 'submission_sha256': sha(body), 'payment_authorizations_created': 0, 'wallet_keys_available': False}


def independently_verify(raw, registry_raw, code, carrier, pin, environment):
    need(sha(code) == carrier['verification']['source_sha256'], 'VERIFIER_SOURCE_HASH')
    need(carrier['verification']['source_id'] == 'urn:sha256:' + sha(code), 'VERIFIER_SOURCE_ID')
    with tempfile.TemporaryDirectory(prefix='cold-public-') as directory:
        d = pathlib.Path(directory); d.chmod(0o755)
        for name, content in [('artifact.json', raw), ('registry.json', registry_raw), ('verifier.py', code)]:
            path = d/name; path.write_bytes(content); path.chmod(0o444)
        replacements = {'{mark}': '/input/artifact.json', '{registry}': '/input/registry.json', '{root_pin}': pin}
        invocation = carrier['verification']['invocation']
        args = [replacements.get(arg, arg) for arg in invocation['arguments']]
        if environment == 'TEST': args += invocation['test_arguments']
        need(len(args) <= 16 and all(isinstance(arg, str) and len(arg) < 512 for arg in args), 'VERIFIER_INVOCATION_BOUNDS')
        image = 'cold-python-crypto:1'
        inspected = subprocess.run(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], capture_output=True, text=True, timeout=20)
        need(inspected.returncode == 0, 'GENERIC_SANDBOX_RUNTIME_REQUIRED')
        command = ['docker', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=32', '--memory=256m', '--cpus=1', '--user=65534:65534', '--tmpfs=/tmp:rw,noexec,nosuid,size=16m', '--mount', 'type=bind,src='+str(d)+',dst=/input,readonly', image, 'python3', '-I', '/input/verifier.py', *args]
        result = subprocess.run(command, capture_output=True, text=True, timeout=50)
        need(result.returncode == 0, 'INDEPENDENT_VERIFICATION_FAILED:' + result.stdout[:1000] + result.stderr[:400])
        report = parse(result.stdout)
        need(report['verified'] is True and report['evaluation_replay'] == 'VERIFIED', 'INDEPENDENT_REPLAY_REQUIRED')
        need(report['current_standing'] == 'ACTIVE', 'CURRENT_STANDING_NOT_ACTIVE')
        return report, inspected.stdout.strip()


def read_artifact(raw):
    mark = parse(raw); p = mark['payload']; carrier = p['discovery']; recipe = carrier['verification']
    need(carrier['format'] == 'signed-artifact-discovery-v1' and carrier['artifact']['historical'] is True, 'ARTIFACT_DISCOVERY_REQUIRED')
    root = pointer(mark, recipe['embedded_root_pointer']); pin = public(root)[1]
    need(carrier['issuer']['root_pin'] == pin and carrier['issuer']['id'] == 'urn:sha256:'+pin, 'SELF_CERTIFYING_IDENTITY')
    historical = root_bundle(p['authority'], pin, p['issued_at'], recipe, remember=False)
    issuer = authority(historical, mark['protected']['key_id'], 'ISSUER', p['issued_at'])
    signature(mark, issuer['public_key'], recipe)
    need(carrier['issuer']['name'] == p['issuer'] == historical['profile']['issuer'], 'ISSUER_LABEL')
    for name, value in carrier['meaning'].items():
        if name.endswith('_pointer'): pointer(mark, value)
    profile = pointer(mark, carrier['profile']['embedded_pointer'])
    need(digest(profile) == carrier['profile']['sha256'] == historical['profile']['profile_hash'], 'HISTORICAL_PROFILE')
    need(profile['id'] == carrier['profile']['id'] and profile['version'] == carrier['profile']['version'], 'HISTORICAL_PROFILE_VERSION')
    net = Network()
    resolution, current = resolve(net, carrier['resolution'], pin, p['environment'], carrier['capability']['id'], recipe)
    provider = resolution['provider']
    historical_material = provider['material_url_template'].replace('{sha256}', carrier['profile']['sha256'])
    need(net.document(historical_material, carrier['profile']['sha256']) == profile, 'IMMUTABLE_PROFILE_MATERIAL')
    code_url = provider['material_url_template'].replace('{sha256}', recipe['source_sha256'])
    status, _, code = net.request(code_url); need(status == 200, 'VERIFIER_UNAVAILABLE')
    registry_url = provider['registry_url_template'].replace('{purchase_id}', p['purchase_id'])
    status, _, registry_raw = net.request(registry_url); need(status == 200, 'REGISTRY_UNAVAILABLE')
    registry = parse(registry_raw); need(registry['protected']['type'] == carrier['status']['type'], 'REGISTRY_TYPE')
    need(int(time.time())-carrier['status']['max_age_seconds'] <= registry['payload']['observed_at'], 'REGISTRY_MAX_AGE')
    report, image = independently_verify(raw, registry_raw, code, carrier, pin, p['environment'])
    c, schema = current_offer(net, resolution, carrier['capability']['requirement_id'])
    probe = c['cold_probe']; need(probe['wallet_signing'] is False, 'NO_WALLET_AUTHORITY')
    submission = parse(canon(pointer(mark, probe['base_document_pointer'])))
    key = Ed25519PrivateKey.generate(); pub = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    for field, source in probe['replacements'].items():
        need(source in ['generated-Ed25519-SPKI', 'random-32-byte-hex'], 'PROBE_RECIPE')
        submission[field] = base64.b64encode(pub).decode() if source == 'generated-Ed25519-SPKI' else secrets.token_hex(32)
    payment = authenticate_and_probe(net, c, schema, submission, key, current, recipe)
    return {'verified': True, 'kind': 'MARK_ONLY', 'environment': p['environment'], 'PROPAGATION-PROVEN': p['environment'], 'input_files': 1, 'prior_issuer_configuration': False, 'repository_imports': False, 'institutional_authority_admission': 'NOT_ESTABLISHED', 'root_pin_source': 'artifact self-certifying key identity; not externally admitted institutional authority', 'completed_path': ['Mark', 'artifact and issuer identity', 'exact meaning and limitations', 'independent verification and replay', 'issuance profile', 'current registry status', 'canonical capability', 'current provider resolution', 'purchase contract', 'x402 payment boundary'], 'meaning': carrier['meaning'], 'historical_profile_sha256': digest(profile), 'current_profile_sha256': c['profile']['sha256'], 'capability_id': carrier['capability']['id'], 'resolution_sequence': resolution['sequence'], 'independent_verifier': report, 'sandbox_image': image, 'sandbox_network': 'none', 'sandbox_host_mounts': 'public artifact, fresh registry and hash-checked verifier only; read-only', 'mark_sha256': sha(raw), 'trace': net.trace, 'production_completion_claim': False, **payment}


def recognize(external, action, interface):
    need(interface['vendor_neutral'] is True, 'NEUTRAL_INTERFACE_REQUIRED')
    observed = external.get('standing_evidence') if isinstance(external, dict) else None
    # Self-asserted flags in an external object never constitute an independent verification.
    reason = 'NO_STANDING_EVIDENCE' if observed is None else 'INDEPENDENTLY_VERIFIABLE_WARRANT_REQUIRED'
    if isinstance(observed, dict):
        for key, missing in [('authority_established','INSUFFICIENT_AUTHORITY'), ('provenance_sufficient','PROVENANCE_INSUFFICIENT'), ('transformation_warrant_established','TRANSFORMATION_WARRANT_MISSING'), ('qualifications_preserved','QUALIFICATION_PRESERVATION_UNESTABLISHED')]:
            if observed.get(key) is not True: reason = missing; break
        if observed.get('blocking_unknowns') is not False: reason = 'BLOCKING_UNKNOWN'
    need(reason in interface['vocabulary'], 'NEED_VOCABULARY')
    return {'version': interface['version'], 'result': reason, 'capability_required': interface['capability'], 'object_sha256': digest(external), 'contemplated_action': action, 'action_sha256': digest(action)}


def interpolate(template, inputs, computed):
    if isinstance(template, dict):
        if set(template) == {'$input'}: return inputs[template['$input']]
        if set(template) == {'$computed'}: return computed[template['$computed']]
        return {k: interpolate(v, inputs, computed) for k,v in template.items()}
    if isinstance(template, list): return [interpolate(v, inputs, computed) for v in template]
    return template


def read_need(document):
    exact(document, ['external_object', 'contemplated_action', 'interface'])
    external = document['external_object']; action = document['contemplated_action']; interface = document['interface']
    requirement = recognize(external, action, interface); net = Network(); directory = interface['directory']
    net.admit(directory['url'], directory['environment'] == 'TEST'); catalog = net.document(directory['url'])
    need(catalog['interface'] == interface['directory']['interface'], 'DIRECTORY_INTERFACE')
    candidates = catalog['providers']; need(isinstance(candidates, list) and 1 <= len(candidates) <= 64, 'DIRECTORY_SIZE')
    compatible = [c for c in candidates if requirement['capability_required']['id'] in c.get('compatible_requirements', [])]
    need(compatible, 'NO_COMPATIBLE_PROVIDER'); failures = []
    for candidate in compatible:
        try:
            bootstrap = candidate['resolution']; need(bootstrap['authority_role']==interface['provider_authority_role'], 'DIRECTORY_ROLE_CONTEXT'); pin = candidate['root_pin']; recipe = candidate['verification']
            resolution, trust = resolve(net, bootstrap, pin, candidate['environment'], candidate['capability_id'], recipe)
            c, schema = current_offer(net, resolution, requirement['capability_required']['id'])
            probe = c['boundary_probe']; need(probe['format'] == 'external-json-boundary-probe-v1' and probe['wallet_signing'] is False and probe['authority_claim'] == 'NOT_ESTABLISHED', 'UNESTABLISHED_AUTHORITY_MUST_REMAIN_UNKNOWN')
            now = int(time.time()); bounds = probe['supported_bounds']; key = Ed25519PrivateKey.generate()
            pub = base64.b64encode(key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()
            inputs = {'object_id': 'external-' + digest(external), 'object_version': '1', 'object_content': external, 'object_locator': 'urn:sha256:' + digest(external), 'client_reference': secrets.token_hex(32), 'public_key': pub, 'operation': action['operation'], 'scope': bounds['scope'], 'jurisdiction': bounds['jurisdiction'], 'valid_from': max(now-5, bounds['valid_from']), 'valid_until': min(now+120, bounds['valid_until'])}
            node = interpolate(probe['node_template'], inputs, {})
            need(node['content'] == external and node['epistemic_status'] == 'UNKNOWN', 'EXTERNAL_OBJECT_PRESERVATION')
            source = {'protected': {**probe['source_protected'], 'key_id': public(pub)[1]}, 'payload': node}
            source['signature'] = base64.b64encode(key.sign(canon(source).encode())).decode()
            submission = interpolate(probe['submission_template'], inputs, {'source_envelope': source, 'object_reference': {'id': node['id'], 'version': node['version'], 'root': digest(node)}})
            need(submission['nodes'][0]['payload']['content'] == external and submission['requested_operation'] == action['operation'], 'OBJECT_ACTION_JOIN')
            payment = authenticate_and_probe(net, c, schema, submission, key, trust, recipe)
            return {'verified': True, 'kind': 'NEED_ONLY', 'environment': candidate['environment'], 'PROPAGATION-PROVEN': candidate['environment'], 'input_files': 1, 'prior_issuer_configuration': False, 'repository_imports': False, 'institutional_authority_admission': 'NOT_ESTABLISHED', 'source_authority': 'NOT_ESTABLISHED', 'requirement': requirement, 'directory_candidates_inspected': len(candidates), 'compatible_candidates_inspected': len(failures)+1, 'selected_capability_id': resolution['capability_id'], 'provider_selection': 'requirement compatibility and verified current contract; not provider name or fixed URL', 'completed_path': ['external object and contemplated action', 'vendor-neutral missing-warrant requirement', 'multi-provider discovery', 'verified current provider resolution', 'purchase contract', 'x402 payment boundary'], 'external_object_sha256': digest(external), 'submitted_content_sha256': digest(submission['nodes'][0]['payload']['content']), 'provider_attempt_failures': failures, 'trace': net.trace, 'production_completion_claim': False, **payment}
        except Exception as error:
            failures.append({'candidate': candidate.get('capability_id'), 'error': str(error)})
    raise ValueError('NO_VALID_COMPATIBLE_PROVIDER:' + json.dumps(failures))


def main(path):
    raw = pathlib.Path(path).read_bytes(); need(len(raw) <= 2_000_000, 'INPUT_SIZE'); obj = parse(raw)
    report = read_artifact(raw) if 'payload' in obj and 'discovery' in obj.get('payload', {}) else read_need(obj)
    print(json.dumps(report, ensure_ascii=False), flush=True)
    # A later object is a new input event, not injected knowledge at first contact.
    later = sys.stdin.buffer.readline(2_000_001)
    if later:
        need(report['kind'] == 'MARK_ONLY', 'RECURSIVE_JOIN_REQUIRES_FIRST_ARTIFACT')
        second = read_need(parse(later))
        need(second['environment'] == report['environment'] == 'TEST', 'BOUNDED_TEST_JOIN')
        print(json.dumps({'verified': True, 'kind': 'RECURSIVE_JOIN', 'PROPAGATION-PROVEN': 'TEST', 'environment': 'TEST', 'first_mark_sha256': report['mark_sha256'], 'first_verification': report['independent_verifier'], 'later_requirement': second['requirement'], 'first_capability_id': report['capability_id'], 'rediscovered_capability_id': second['selected_capability_id'], 'second_boundary': second, 'payment_authorizations_created': 0, 'wallet_keys_available': False, 'production_completion_claim': False}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    try:
        need(len(sys.argv)==2, 'ONE_DECLARED_INPUT_REQUIRED'); main(sys.argv[1])
    except Exception as error:
        print(json.dumps({'verified': False, 'error': str(error) or type(error).__name__}), flush=True); sys.exit(1)
