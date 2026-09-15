import {readFile} from 'node:fs/promises';
import {createPrivateKey} from 'node:crypto';
import {parseStrict,demand} from './canonical.mjs';
import {postgresStore} from './store.mjs';
import {EvmRail} from './payment.mjs';
import {StandingService} from './service.mjs';
export async function runtimeFromEnvironment(env=process.env){
  for(const name of ['WHP_ORIGIN','WHP_ROOT_PIN','WHP_TRUST_BUNDLE_FILE','WHP_ISSUER_PRIVATE_KEY','WHP_PAYMENT_REQUIREMENTS_FILE','WHP_FACILITATOR_URL','WHP_RPC_URL','DATABASE_URL'])demand(env[name],'CONFIG_'+name+'_REQUIRED',503);
  const trustBundle=parseStrict(await readFile(env.WHP_TRUST_BUNDLE_FILE,'utf8'),1048576),requirements=parseStrict(await readFile(env.WHP_PAYMENT_REQUIREMENTS_FILE,'utf8'));
  demand(trustBundle.profile_authorization.payload.environment==='LIVE','PRODUCTION_REQUIRES_LIVE_AUTHORITY',503);
  const privateKey=createPrivateKey(env.WHP_ISSUER_PRIVATE_KEY),rail=new EvmRail({facilitator_url:env.WHP_FACILITATOR_URL,rpc_url:env.WHP_RPC_URL,network:requirements.network});
  const store=await postgresStore(env.DATABASE_URL);
  try{return new StandingService({store,rail,privateKey,trustBundle,rootPin:env.WHP_ROOT_PIN,origin:env.WHP_ORIGIN,requirements});}catch(e){await store.close();throw e;}
}
