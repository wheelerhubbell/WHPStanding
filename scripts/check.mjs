import {readdir,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';import {spawnSync} from 'node:child_process';import {createHash} from 'node:crypto';
const root=resolve(new URL('..',import.meta.url).pathname);process.chdir(root);
const evidence='evidence/public-v1',started=new Date().toISOString();await mkdir(evidence,{recursive:true});
await rm(evidence+'/verification.json',{force:true});await rm(evidence+'/failure.json',{force:true});
const sha=b=>createHash('sha256').update(b).digest('hex');
async function walk(dir){const out=[];for(const e of await readdir(dir,{withFileTypes:true})){if(['node_modules','.git','.runtime','__pycache__'].includes(e.name))continue;const p=join(dir,e.name);if(e.isDirectory())out.push(...await walk(p));else out.push(p);}return out;}
function run(command,args,options={}){const r=spawnSync(command,args,{encoding:'utf8',maxBuffer:33554432,timeout:180000,...options});if(r.error||r.status!==0)throw Error((r.error?.message??'COMMAND_FAILED')+' '+command+' '+args.join(' ')+'\n'+r.stdout+'\n'+r.stderr);return r;}
async function checkedRun(label,command,args,options={}){const r=spawnSync(command,args,{encoding:'utf8',maxBuffer:33554432,timeout:180000,...options});await writeFile(evidence+'/'+label,r.stdout+r.stderr);if(r.error||r.status!==0)throw Error((r.error?.message??'COMMAND_FAILED')+' '+label+'\n'+r.stdout+'\n'+r.stderr);return r;}
try{
 const files=await walk('.'),js=files.filter(p=>p.endsWith('.mjs')),py=files.filter(p=>p.endsWith('.py'));
 const lock=JSON.parse(await readFile('contracts/public-v1-lock.json','utf8'));
 for(const [p,h] of Object.entries(lock.files))if(sha(await readFile(p))!==h)throw Error('FROZEN_CONTRACT_CHANGED:'+p);
 const transition=JSON.parse(await readFile(evidence+'/transition.json','utf8'));
 for(const [p,h] of Object.entries(transition.candidate_evidence_files))if(sha(await readFile(p))!==h)throw Error('CANDIDATE_PROVENANCE_CHANGED:'+p);
 for(const p of js)run(process.execPath,['--check',p]);
 run('python3',['-c','import pathlib,sys;[(compile(pathlib.Path(p).read_text(),p,"exec")) for p in sys.argv[1:]]',...py]);
 const sandbox=run('docker',['image','inspect','cold-python-crypto:1','--format','{{.Id}}']).stdout.trim();
 // Save each file's output even on failure. No stale success report can stand in for this run.
 await mkdir(evidence+'/test-files',{recursive:true});const counts={tests:0,pass:0,fail:0,cancelled:0,skipped:0,todo:0};let tap='';const perFile=[];
 for(const path of files.filter(p=>p.startsWith('test/')&&p.endsWith('.test.mjs')).sort()){
  console.log('VERIFY_TEST_FILE',path);
  const r=await checkedRun('test-files/'+path.split('/').at(-1)+'.tap',process.execPath,['--test',path],{timeout:600000});
  const c=Object.fromEntries([...r.stdout.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)].map(m=>[m[1],Number(m[2])]));
  if(!c.tests||c.pass!==c.tests||c.fail||c.cancelled||c.skipped||c.todo)throw Error('TEST_COVERAGE_INCOMPLETE:'+path);
  for(const key of Object.keys(counts))counts[key]+=c[key];perFile.push({file:path,...c});tap+='\n# FILE '+path+'\n'+r.stdout+r.stderr;await writeFile(evidence+'/tests.tap',tap);
 }
 if(counts.tests<=83)throw Error('PUBLIC_V1_MUST_EXTEND_INHERITED_PROOF');
 const cold={};for(const [name,kind] of [['A','MARK_ONLY'],['B','NEED_ONLY'],['C','RECURSIVE_JOIN']]){
  const report=JSON.parse(await readFile(evidence+'/cold/'+name+'.json','utf8'));
  if(report.verified!==true||report.kind!==kind||report['PROPAGATION-PROVEN']!=='TEST'||report.production_completion_claim!==false||report.payment_authorizations_created!==0)throw Error('COLD_PROOF_INCOMPLETE:'+name);
  cold[name]={kind,verified:true,level:'TEST',report:'cold/'+name+'.json',sha256:sha(await readFile(evidence+'/cold/'+name+'.json'))};
 }
 const demo=await checkedRun('demonstration-run.txt',process.execPath,['scripts/demonstrate.mjs',evidence+'/demonstration']);
 const execution=JSON.parse(await readFile(evidence+'/demonstration/execution-record.json','utf8'));
 await checkedRun('schemas.txt','python3',['scripts/check-schemas.py','schemas/submission.schema.json',evidence+'/demonstration/TEST-submission.json','schemas/result.schema.json',evidence+'/demonstration/TEST-standing-mark.json','schemas/registry.schema.json',evidence+'/demonstration/TEST-registry-snapshot.json']);
 const refused=spawnSync('python3',['verify/verify_mark.py',evidence+'/demonstration/TEST-standing-mark.json','--root-pin',execution.root_pin],{encoding:'utf8',timeout:60000});
 await writeFile(evidence+'/test-not-live-refusal.json',refused.stdout);
 if(refused.status!==1||!refused.stdout.includes('TEST_ARTIFACT_NOT_LIVE'))throw Error('TEST_MARK_WAS_NOT_REFUSED_AS_LIVE');
 const sourceFiles=(await walk('.')).filter(p=>!p.startsWith('evidence/')&&!p.startsWith('build-input/')&&!p.endsWith('.zip')).sort();
 const inventory={};for(const p of sourceFiles)inventory[p]=sha(await readFile(p));
 await writeFile(evidence+'/source-inventory.json',JSON.stringify(inventory,null,2)+'\n');
 const report={contract:'WHP Standing v1',mark:'WHP Standing Mark v1',version:'1.0.0',started_at:started,completed_at:new Date().toISOString(),environment:'TEST',
  states:{DESIGNED:true,IMPLEMENTED:true,VERIFIED:true,'PROPAGATION-PROVEN':'TEST',DEPLOYED:false,LIVE:false,SOLD:false,ISSUED:false},
  source_commit_under_test:process.env.GITHUB_SHA??null,source_commit_note:'During isolated materialization this names the staging commit. source_inventory_sha256 binds every executed source byte; the promotion record identifies the final authoritative commit.',
  source_inventory_sha256:sha(await readFile(evidence+'/source-inventory.json')),contract_lock_sha256:sha(await readFile('contracts/public-v1-lock.json')),
  node:process.version,python:run('python3',['--version']).stdout.trim(),python_packages:JSON.parse(run('python3',['-c','import importlib.metadata,json;print(json.dumps({k:importlib.metadata.version(k) for k in ["cryptography","jsonschema"]}))']).stdout),
  javascript_syntax_files:js.length,python_syntax_files:py.length,test_counts:counts,test_files:perFile,inherited_test_count:83,inherited_provenance_preserved:true,
  schemas_validated:true,real_local_http_transaction_executed:true,separate_process_retrieval_executed:true,independent_python_verifier_executed:true,independent_replay_executed:true,test_artifact_refused_as_live:true,
  generic_sandbox_image:sandbox,cold_proofs:cold,
  demonstration:{purchase_id:execution.purchase_id,mark_id:execution.mark_id,mark_sha256:execution.mark_sha256,root_pin:execution.root_pin,wallet_signing_calls:execution.signer_invocations,settlement_calls:execution.settlement_calls,simulated_transfers:execution.simulated_transfers},
  institutional_authority_admission:'NOT_ESTABLISHED by a Mark alone; external root policy remains required.',
  production_deployment_performed:false,live_payment_executed:false,actual_funds_moved:'0',public_directory_registration_proven:false,postgresql_evidence:'Separate optional TEST proof: evidence/postgresql/report.json',external_security_audit_performed:false,
  completion_boundary:'First-public-v1 cryptographic contract and TEST propagation. Production authority, deployment and genuine outside sale/issuance require separate evidence.'};
 await writeFile(evidence+'/verification.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
}catch(error){await writeFile(evidence+'/failure.json',JSON.stringify({started_at:started,failed_at:new Date().toISOString(),environment:'TEST',verified:false,error:error.stack},null,2)+'\n');console.error(error.stack);process.exitCode=1;}
