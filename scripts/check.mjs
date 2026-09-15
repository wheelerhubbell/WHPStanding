import {readdir,mkdir,writeFile,readFile} from 'node:fs/promises';import {join,resolve} from 'node:path';import {spawnSync} from 'node:child_process';
const root=resolve(new URL('..',import.meta.url).pathname);process.chdir(root);await mkdir('evidence',{recursive:true});
const started=new Date().toISOString();
async function walk(dir){const out=[];for(const e of await readdir(dir,{withFileTypes:true})){if(['node_modules','.git','.runtime','__pycache__'].includes(e.name))continue;const p=join(dir,e.name);if(e.isDirectory())out.push(...await walk(p));else out.push(p);}return out;}
function run(command,args,options={}){const result=spawnSync(command,args,{encoding:'utf8',maxBuffer:16777216,timeout:120000,...options});if(result.error||result.status!==0)throw Error((result.error?.message??'COMMAND_FAILED')+'\n'+result.stdout+'\n'+result.stderr);return result;}
try{
  const files=await walk('.'),js=files.filter(p=>p.endsWith('.mjs')),py=files.filter(p=>p.endsWith('.py'));
  for(const path of js)run(process.execPath,['--check',path]);
  run('python3',['-c','import pathlib,sys;[(compile(pathlib.Path(p).read_text(),p,"exec")) for p in sys.argv[1:]]',...py]);
  const tests=run(process.execPath,['--test',...files.filter(p=>p.startsWith('test/')&&p.endsWith('.test.mjs')).sort()]);
  await writeFile('evidence/tests.tap',tests.stdout+tests.stderr);
  const counts=Object.fromEntries([...tests.stdout.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)].map(m=>[m[1],Number(m[2])]));
  if(!counts.tests||counts.pass!==counts.tests||counts.fail||counts.skipped||counts.todo)throw Error('TEST_COVERAGE_INCOMPLETE');
  const demonstration=run(process.execPath,['scripts/demonstrate.mjs','evidence/demonstration']);
  await writeFile('evidence/demonstration-run.json',demonstration.stdout);await writeFile('evidence/demonstration-stderr.txt',demonstration.stderr);
  const execution=JSON.parse(await readFile('evidence/demonstration/execution-record.json','utf8'));
  const schema=run('python3',['scripts/check-schemas.py','schemas/submission.schema.json','evidence/demonstration/TEST-submission.json','schemas/result.schema.json','evidence/demonstration/TEST-standing-mark.json']);await writeFile('evidence/schemas.txt',schema.stdout);
  const refused=spawnSync('python3',['verify/verify_mark.py','evidence/demonstration/TEST-standing-mark.json','--root-pin',execution.root_pin],{encoding:'utf8'});
  if(refused.status!==1||!refused.stdout.includes('TEST_ARTIFACT_NOT_LIVE'))throw Error('TEST_MARK_WAS_NOT_REFUSED_AS_LIVE');
  await writeFile('evidence/test-not-live-refusal.json',refused.stdout);
  const report={build:'WHP Standing v1',version:'1.0.0-candidate.1',started_at:started,completed_at:new Date().toISOString(),
    node:process.version,python:run('python3',['--version']).stdout.trim(),python_packages:JSON.parse(run('python3',['-c','import importlib.metadata,json;print(json.dumps({k:importlib.metadata.version(k) for k in ["cryptography","jsonschema"]}))']).stdout),
    javascript_syntax_files:js.length,python_syntax_files:py.length,test_counts:counts,schemas_validated:true,real_local_http_transaction_executed:true,
    separate_process_retrieval_executed:true,independent_python_verifier_executed:true,test_artifact_refused_as_live:true,
    demonstration:{purchase_id:execution.purchase_id,mark_id:execution.mark_id,mark_sha256:execution.mark_sha256,root_pin:execution.root_pin,wallet_signing_calls:execution.signer_invocations,settlement_calls:execution.settlement_calls,simulated_transfers:execution.simulated_transfers},
    exact_completion_boundary:'OPEN — no real buyer payment or institutional WHP Standing Mark was issued.',
    live_completion:false,production_deployment_performed:false,postgresql_integration_tested:false,live_facilitator_integration_tested:false,external_security_audit_performed:false};
  await writeFile('evidence/verification.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
}catch(error){console.error(error.stack);process.exitCode=1;}
