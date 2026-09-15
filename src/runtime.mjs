import {readFile} from 'node:fs/promises';
import {createPrivateKey} from 'node:crypto';
import {parseStrict,demand} from './canonical.mjs';
import {postgresStore} from './store.mjs';
import {EvmRail} from './payment.mjs';
import {StandingService} from './service.mjs';
import {validateTrust,issuerAuthority} from './authority.mjs';
import {keyId,publicDer} from './canonical.mjs';
import {livePaymentDestination,bazaar} from './discovery.mjs';
export async function runtimeFromEnvironment(env=process.env){
  for(const name of ['WHP_ORIGIN','WHP_ROOT_PIN','WHP_ISSUER_PRIVATE_KEY','WHP_FACILITATOR_URL','WHP_RPC_URL'])demand(env[name],'CONFIG_'+name+'_REQUIRED',503);
  demand(env.WHP_TRUST_BUNDLE_JSON||env.WHP_TRUST_BUNDLE_FILE,'CONFIG_WHP_TRUST_BUNDLE_REQUIRED',503);
  demand(env.WHP_PAYMENT_REQUIREMENTS_JSON||env.WHP_PAYMENT_REQUIREMENTS_FILE,'CONFIG_WHP_PAYMENT_REQUIREMENTS_REQUIRED',503);
  const trustBundle=parseStrict(env.WHP_TRUST_BUNDLE_JSON??await readFile(env.WHP_TRUST_BUNDLE_FILE,'utf8'),1048576),requirements=parseStrict(env.WHP_PAYMENT_REQUIREMENTS_JSON??await readFile(env.WHP_PAYMENT_REQUIREMENTS_FILE,'utf8'));
  validateTrust(trustBundle,env.WHP_ROOT_PIN,Math.floor(Date.now()/1000));livePaymentDestination(requirements);
  demand(trustBundle.profile_authorization.payload.environment==='LIVE','PRODUCTION_REQUIRES_LIVE_AUTHORITY',503);
  const privateKey=createPrivateKey(env.WHP_ISSUER_PRIVATE_KEY),rail=new EvmRail({facilitator_url:env.WHP_FACILITATOR_URL,rpc_url:env.WHP_RPC_URL,network:requirements.network,discovery_extensions:{bazaar:bazaar({origin:env.WHP_ORIGIN})}});
  const store=await postgresStore(env.DATABASE_URL??env.NETLIFY_DB_URL);
  try{return new StandingService({store,rail,privateKey,trustBundle,rootPin:env.WHP_ROOT_PIN,origin:env.WHP_ORIGIN,resolutionUrl:env.WHP_RESOLUTION_URL??null,catalogUrl:env.WHP_CAPABILITY_CATALOG_URL??null,requirements});}catch(e){await store.close();throw e;}
}
