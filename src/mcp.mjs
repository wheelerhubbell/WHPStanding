// Stateless Streamable HTTP. Tools use the same authenticated, fail-closed service routes.
import {canonical,parseStrict,exact,demand} from './canonical.mjs';
import {contract,profilePath,SERVICE,CAPABILITY} from './discovery.mjs';
const VERSIONS=['2025-11-25','2025-06-18','2025-03-26'];
const object=(properties={},required=Object.keys(properties))=>({type:'object',properties,required,additionalProperties:false});
const string=maxLength=>({type:'string',maxLength});
const tools=[
  {name:'whp_standing_contract',description:'Discover WHP Standing: '+CAPABILITY+' Includes exact profile, schema, authority prerequisites and owner-authorized payment contract.',inputSchema:object(),annotations:{readOnlyHint:true,idempotentHint:true,openWorldHint:false}},
  {name:'whp_standing_evaluation',description:'Request a WHP Standing Evaluation. First call returns the exact HTTP 402 payment terms. Supply only the buyer’s own pre-authorized payment signature on retry. Paying does not establish standing; a failed assessment has no Mark.',inputSchema:object({submission_raw:string(262144),client_proof:string(6000),payment_signature:string(24000)},['submission_raw','client_proof']),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:true}},
  {name:'whp_standing_result',description:'Retrieve the exact original WHP Standing Mark or negative assessment bytes with buyer authentication, without another charge.',inputSchema:object({purchase_id:{type:'string',pattern:'^[0-9a-f]{64}$'},client_proof:string(6000)}),annotations:{readOnlyHint:true,idempotentHint:true,openWorldHint:false}}
];
const json=(status,body)=>new Response(canonical(body)+'\n',{status,headers:{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'}});
export async function mcpRoute(service,req){
  if(req.headers.has('origin')&&req.headers.get('origin')!==service.origin)return json(403,{jsonrpc:'2.0',error:{code:-32600,message:'Origin not allowed'}});
  if(req.method!=='POST')return new Response(null,{status:405,headers:{allow:'POST'}});
  if(!(req.headers.get('content-type')??'').startsWith('application/json'))return json(415,{jsonrpc:'2.0',error:{code:-32600,message:'JSON required'}});
  const accept=req.headers.get('accept')??'';if(!accept.includes('application/json')||!accept.includes('text/event-stream'))return json(406,{jsonrpc:'2.0',error:{code:-32600,message:'Accept application/json and text/event-stream'}});
  const proto=req.headers.get('mcp-protocol-version');if(proto&&!VERSIONS.includes(proto))return json(400,{jsonrpc:'2.0',error:{code:-32600,message:'Unsupported protocol version'}});
  let msg;try{const reader=req.body?.getReader();let size=0,parts=[];if(reader)for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>300000){await reader.cancel();return json(413,{error:'Request too large'});}parts.push(Buffer.from(value));}msg=parseStrict(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)),300000);}catch{return json(400,{jsonrpc:'2.0',id:null,error:{code:-32700,message:'Invalid JSON'}});}
  if(!msg||typeof msg!=='object'||Array.isArray(msg)||msg.jsonrpc!=='2.0')return json(400,{jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid request'}});
  if(!Object.hasOwn(msg,'id'))return new Response(null,{status:202});
  if(!['string','number'].includes(typeof msg.id)||!msg.method)return json(400,{jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid request'}});
  const reply=result=>json(200,{jsonrpc:'2.0',id:msg.id,result});
  const error=(code,message)=>json(200,{jsonrpc:'2.0',id:msg.id,error:{code,message}});
  try{
    if(msg.method==='initialize')return reply({protocolVersion:VERSIONS.includes(msg.params?.protocolVersion)?msg.params.protocolVersion:VERSIONS[0],capabilities:{tools:{listChanged:false},resources:{subscribe:false,listChanged:false}},serverInfo:{name:SERVICE,version:'1.0.0'},instructions:'Read the WHP Standing contract before any evaluation. This server never holds buyer wallet keys or grants spending authority.'});
    if(msg.method==='ping')return reply({});
    if(msg.method==='tools/list')return reply({tools});
    const resources=[['/v1/contract','WHP Standing Evaluation contract'],[profilePath,'WHP Standing Profile'],['/v1/verification','WHP Standing Mark independent verification']].map(([p,name])=>({uri:service.origin+p,name,mimeType:'application/json'}));
    if(msg.method==='resources/list')return reply({resources});
    if(msg.method==='resources/read'){
      const uri=msg.params?.uri;if(!resources.some(r=>r.uri===uri))return error(-32002,'Resource not found');
      const response=await service.handle(new Request(uri));return reply({contents:[{uri,mimeType:'application/json',text:await response.text()}]});
    }
    if(msg.method!=='tools/call')return error(-32601,'Method not found');
    const name=msg.params?.name,a=msg.params?.arguments??{};
    if(name==='whp_standing_contract'){exact(a,[]);const data=contract(service);return reply({content:[{type:'text',text:canonical(data)}],structuredContent:data});}
    let response;
    if(name==='whp_standing_evaluation'){
      exact(a,Object.hasOwn(a,'payment_signature')?['submission_raw','client_proof','payment_signature']:['submission_raw','client_proof']);
      demand(typeof a.submission_raw==='string'&&Buffer.byteLength(a.submission_raw)<=262144&&typeof a.client_proof==='string'&&a.client_proof.length<=6000,'INPUT_INVALID');
      const headers={'content-type':'application/json','whp-client-proof':a.client_proof};if(a.payment_signature!==undefined){demand(typeof a.payment_signature==='string'&&a.payment_signature.length<=24000,'PAYMENT_HEADER_INVALID');headers['payment-signature']=a.payment_signature;}
      response=await service.handle(new Request(service.origin+'/v1/evaluations',{method:'POST',headers,body:a.submission_raw}));
    }else if(name==='whp_standing_result'){
      exact(a,['purchase_id','client_proof']);demand(/^[0-9a-f]{64}$/.test(a.purchase_id)&&typeof a.client_proof==='string'&&a.client_proof.length<=6000,'INPUT_INVALID');
      response=await service.handle(new Request(service.origin+'/v1/purchases/'+a.purchase_id+'/result',{headers:{'whp-client-proof':a.client_proof}}));
    }else return error(-32602,'Unknown tool');
    const raw=await response.text();const data={http_status:response.status,headers:Object.fromEntries([...response.headers].filter(([k])=>['payment-required','payment-response','retry-after'].includes(k))),body_bytes:raw};
    return reply({content:[{type:'text',text:canonical(data)}],structuredContent:data,isError:response.status>=400&&response.status!==402});
  }catch{return error(-32602,'Invalid tool arguments');}
}
