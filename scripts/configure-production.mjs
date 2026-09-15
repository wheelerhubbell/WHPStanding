// Authorized deployment configuration; no wallet or payment execution.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {canonical,parseStrict,demand,hash,keyId,publicDer} from '../src/canonical.mjs';
import {verifyAuthority,ORIGIN} from './authority-core.mjs';
import {postgresStore} from '../src/store.mjs';
import {EvmRail} from '../src/payment.mjs';
import {livePaymentDestination} from '../src/discovery.mjs';
const SITE='914e2d6d-ec82-4b03-aa58-785fcf3b453b',ACCOUNT='6aa6fb2da06f6afa962eee67';
const PREFIX='/accounts/'+ACCOUNT+'/env',token=process.env.NETLIFY_AUTH_TOKEN;
const report={checked_at:new Date().toISOString(),source_commit:process.env.GITHUB_SHA,payment_executed:false,paid_plan_enabled:false};
const value=(e,c='production')=>e?.values?.find(v=>v.context===c)?.value;
async function api(path,method='GET',body){
 const r=await fetch('https://api.netlify.com/api/v1'+path,{method,headers:{Authorization:'Bearer '+token,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(60000)});
 demand(r.ok,'NETLIFY_'+method+'_'+r.status,503);return r.status===204?null:r.json();
}
async function put(key,data){
 const vars=await api(PREFIX+'?site_id='+SITE),body={key,values:[{context:'production',value:data}]};
 await api(PREFIX+(vars.some(e=>e.key===key)?'/'+key:'')+'?site_id='+SITE,vars.some(e=>e.key===key)?'PUT':'POST',vars.some(e=>e.key===key)?body:[body]);
}
try{
 demand(token,'NETLIFY_TOKEN_REQUIRED');
 const account=await api('/accounts/'+ACCOUNT);demand(account.type_name==='Free','NO_PAID_ACCOUNT_OPERATION_AUTHORIZED');report.account_plan=account.type_name;
 const vars=await api(PREFIX+'?site_id='+SITE),pub=parseStrict(await readFile('public/authority/root.json','utf8'));
 const issuer=value(vars.find(e=>e.key==='WHP_ISSUER_PRIVATE_KEY')),bundle=parseStrict(value(vars.find(e=>e.key==='WHP_TRUST_BUNDLE_JSON')));
 verifyAuthority(bundle,pub.root_pin,issuer,Math.floor(Date.now()/1000));demand(value(vars.find(e=>e.key==='WHP_ROOT_PIN'))===pub.root_pin,'ROOT_PIN_CONFIGURATION_MISMATCH');
 report.authority_verified=true;
 const requirements={scheme:'exact',network:'eip155:8453',amount:'1000000',asset:'0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',payTo:'0x1050eddd8282623b0c263ed6bdbd42370bbc28d3',maxTimeoutSeconds:300,extra:{assetTransferMethod:'eip3009',paymentFlow:'authorization',name:'USD Coin',version:'2'}};
 livePaymentDestination(requirements);report.payment_requirements=requirements;report.price_basis='Launch configuration: 1 USDC per evaluation; no buyer payment authorized by deployment.';
 const facilitator='https://facilitator.payai.network',rpc='https://base-rpc.publicnode.com';
 const supported=await fetch(facilitator+'/supported',{signal:AbortSignal.timeout(20000)});demand(supported.ok,'FACILITATOR_UNAVAILABLE');const kinds=await supported.json();
 demand(kinds.kinds.some(k=>k.x402Version===2&&k.scheme==='exact'&&k.network===requirements.network),'FACILITATOR_NOT_COMPATIBLE');
 report.facilitator={url:facilitator,supported:true,free_tier:true,settlement_execution_verified:false};
 const rail=new EvmRail({facilitator_url:facilitator,rpc_url:rpc,network:requirements.network});
 const head=await rail.startBlock(),finalized=await rail.rpc('eth_getBlockByNumber',['finalized',false]);
 demand(finalized&&BigInt(finalized.number)<=BigInt(head),'FINALITY_READ_FAILED');
 const code=await rail.rpc('eth_getCode',[requirements.asset,'latest']);demand(code&&code!=='0x','USDC_CONTRACT_MISSING');
 const logs=await rail.rpc('eth_getLogs',[{address:requirements.asset,fromBlock:finalized.number,toBlock:finalized.number}]);demand(Array.isArray(logs),'LOG_QUERY_FAILED');
 const check=await fetch('https://mainnet.base.org',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_getBlockByNumber',params:[finalized.number,false]}),signal:AbortSignal.timeout(20000)});
 const other=await check.json();demand(other.result?.hash===finalized.hash,'INDEPENDENT_FINALIZED_BLOCK_MISMATCH');
 report.rpc={url:rpc,chain_id:8453,finalized_number:finalized.number,finalized_hash:finalized.hash,independent_base_rpc_agrees:true,usdc_code_present:true,logs_readable:true};
 // Official idempotent create endpoint; existing Free plan only, no upgrades/top-ups.
 await api('/sites/'+SITE+'/database','POST',{});const db=await api('/sites/'+SITE+'/database?role=netlifydb_owner');demand(typeof db.connection_string==='string','DATABASE_CONNECTION_REQUIRED');
 const store=await postgresStore(db.connection_string);try{
 const role=(await store.driver.query('SELECT current_user AS role'))[0].role;
 report.database={provider:'Netlify managed PostgreSQL',api_role:role,migration_verified:false,production_runtime_connection:'Netlify getConnectionString',migration_path:'netlify/database/migrations/0001_whp_standing.sql'};
 }finally{await store.close();}
 for(const [k,v] of Object.entries({WHP_USE_NETLIFY_DATABASE:'true',WHP_ORIGIN:ORIGIN,WHP_FACILITATOR_URL:facilitator,WHP_RPC_URL:rpc,WHP_PAYMENT_REQUIREMENTS_JSON:canonical(requirements)}))await put(k,v);
 const back=await api(PREFIX+'?site_id='+SITE);for(const k of ['WHP_USE_NETLIFY_DATABASE','WHP_PAYMENT_REQUIREMENTS_JSON','WHP_RPC_URL','WHP_FACILITATOR_URL'])demand(value(back.find(e=>e.key===k)),'CONFIG_READBACK_FAILED');
 demand(hash(parseStrict(value(back.find(e=>e.key==='WHP_PAYMENT_REQUIREMENTS_JSON'))))===hash(requirements),'PAYMENT_CONFIG_MISMATCH');
 report.configuration_ready_for_deployment=true;report.configuration_verified=false;
}catch(e){report.failure=e.code??e.name;if(e.code==='42501')report.permission_error=e.message;process.exitCode=1;}
await mkdir('evidence/production',{recursive:true});await writeFile('evidence/production/configuration.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
