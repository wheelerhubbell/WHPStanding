import base64,hashlib,json,lzma,os,pathlib,subprocess,urllib.request
R=pathlib.Path.cwd()
def digest(b):return hashlib.sha256(b).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
def blob(sha):
    assert len(sha)==40 and all(c in '0123456789abcdef' for c in sha)
    return git('cat-file','blob',sha)
def safe(path):
    p=pathlib.PurePosixPath(path)
    assert not p.is_absolute() and '..' not in p.parts and not any(x in ['.git','node_modules','.runtime','.env'] for x in p.parts)
    return R/path
if os.environ.get('STAGE_ACTION')!='publish':
    parts=sorted((R/'build-input/public-v1-source').glob('part-*.b64'));assert len(parts)==9
    packed=base64.b64decode(''.join(p.read_text() for p in parts),validate=True)
    assert digest(packed)=='6a629a03dfef501a2986051a85bd29d0874a8360ce70aa498efcbaca0f938f42'
    raw=lzma.decompress(packed);assert digest(raw)=='a9112a2099bdf5caf1cb22775dd96f2684c7c7cc457796c5255635d35e568c2f'
    payload=json.loads(raw);assert payload['format']=='sha256-bound-complete-source-transition-v1'
    for w in payload['workflow_files']:
        assert digest(safe(w['path']).read_bytes())==w['sha256'],w['path']
    for f in payload['files']:
        path=safe(f['path']);assert not f['path'].startswith('.github/')
        if 'reuse_sha' in f:b=blob(f['reuse_sha'])
        elif 'delta' in f:
            old=blob(f['delta']['base_blob']);b=b''.join(old[x['copy'][0]:sum(x['copy'])] if 'copy' in x else x['insert'].encode() for x in f['delta']['pieces'])
        elif 'text' in f:b=f['text'].encode()
        else:b=base64.b64decode(f['base64'],validate=True)
        assert digest(b)==f['sha256'],f['path']
        assert hashlib.sha1(('blob '+str(len(b))+'\0').encode()+b).hexdigest()==f['git_sha']
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b);path.chmod(int(f['mode'],8)&0o777)
    for name in payload['remove']:safe(name).unlink()
    assert digest((R/'WHP-Standing-v1-candidate-1.zip').read_bytes())=='37f38a3799baafcbdd149aa29e9994fa6ae39230d108ef35f93b842bcdea2056'
    print('102 source files reconstructed byte-identically; original candidate archive unchanged; current v1 workflow installed.')
else:
    proof=json.loads((R/'evidence/public-v1/verification.json').read_text());assert proof['complete_thread_proof'] is True
    assert proof['evidence_states']['PROPAGATION-PROVEN']=='TEST' and proof['test_counts']['fail']==0
    repository=os.environ['GITHUB_REPOSITORY'];token=os.environ['GH_TREE_TOKEN']
    def post(path,obj):
        req=urllib.request.Request('https://api.github.com/repos/'+repository+path,data=json.dumps(obj).encode(),headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=120) as resp:return json.load(resp)
    tracked=git('ls-files','-z').decode().split('\0');untracked=git('ls-files','--others','--exclude-standard','-z').decode().split('\0')
    allowed=('src/','verify/','scripts/','schemas/','profiles/','contracts/','public/','test/','netlify/','docs/','examples/','evidence/','migrations/','discovery/')
    allowed_root={'AGENTS.md','package-lock.json'}
    entries=[]
    for name in sorted(set(tracked+untracked)-{''}):
        if '__pycache__' in pathlib.PurePosixPath(name).parts or name.endswith('.pyc'):continue
        if name not in tracked:assert name.startswith(allowed) or name in allowed_root,name
        p=safe(name)
        if not p.exists():
            if name in tracked:entries.append({'path':name,'mode':'100644','type':'blob','sha':None})
            continue
        assert p.is_file() and not p.is_symlink(),name
        b=p.read_bytes();sha=hashlib.sha1(('blob '+str(len(b))+'\0').encode()+b).hexdigest()
        old=subprocess.run(['git','rev-parse','HEAD:'+name],capture_output=True,text=True)
        if old.returncode==0 and old.stdout.strip()==sha:continue
        assert not name.startswith('.github/'),'Workflow changes require connected writes'
        e={'path':name,'mode':'100755' if p.stat().st_mode&0o111 else '100644','type':'blob'}
        try:e['content']=b.decode('utf-8')
        except UnicodeDecodeError:
            e['sha']=post('/git/blobs',{'encoding':'base64','content':base64.b64encode(b).decode()})['sha']
        entries.append(e)
    tree=post('/git/trees',{'base_tree':git('rev-parse','HEAD^{tree}').decode().strip(),'tree':entries})
    report={'verified_tree_sha':tree['sha'],'parent_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'source_manifest_sha256':proof['source_manifest_sha256'],'test_counts':proof['test_counts'],'complete_thread_proof':True,'ref_updated':False,'commit_created':False,'production_deployed':False,'tree_entries':len(entries)}
    (R/'publication').mkdir(exist_ok=True);(R/'publication/verified-tree.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
