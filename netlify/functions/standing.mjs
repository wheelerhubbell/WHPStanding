import {runtimeFromEnvironment} from '../../src/runtime.mjs';
let service;
export default async function handler(request){
  try{service??=runtimeFromEnvironment().catch(e=>{service=null;throw e;});return (await service).handle(request);}
  catch{return new Response('{"error":{"code":"SERVICE_UNAVAILABLE"}}',{status:503,headers:{'content-type':'application/json','cache-control':'no-store'}});}
}
export const config={path:['/','/v1/*','/.well-known/whp-standing.json','/.well-known/standing-capability.json','/discovery/*','/verification/*','/examples/*','/.well-known/api-catalog','/healthz','/schemas/*','/mcp','/server.json','/robots.txt','/sitemap.xml','/llms.txt']};
