// Fail-closed interpreter for the vocabulary used by the frozen, local v1 schemas.
// It performs no network resolution and is not a general-purpose JSON Schema engine.
import {canonical,demand} from './canonical.mjs';
const annotations=new Set(['$schema','$id','$defs','title','description','x-whp-canonicalization','x-whp-cross-field-constraints']);
const supported=new Set([...annotations,'$ref','const','enum','oneOf','anyOf','type','properties','required','additionalProperties','items','minItems','maxItems','uniqueItems','minLength','maxLength','pattern','minimum','maximum','x-whp-unique-key','x-whp-uint256']);
export function validateContract(value,schema){
  function test(v,s,depth=0){
    demand(depth<192,'SCHEMA_DEPTH',503);
    for(const key of Object.keys(s))demand(supported.has(key),'UNSUPPORTED_CONTRACT_SCHEMA_KEYWORD:'+key,503);
    if(s.$ref){demand(s.$ref.startsWith('#/'),'EXTERNAL_SCHEMA_FORBIDDEN',503);let x=schema;for(const k of s.$ref.slice(2).split('/'))x=x[k.replace(/~1/g,'/').replace(/~0/g,'~')];return test(v,x,depth+1);}
    if('const' in s&&canonical(v)!==canonical(s.const))return false;
    if(s.enum&&!s.enum.some(x=>canonical(v)===canonical(x)))return false;
    if(s.oneOf&&s.oneOf.filter(x=>test(v,x,depth+1)).length!==1)return false;
    if(s.anyOf&&!s.anyOf.some(x=>test(v,x,depth+1)))return false;
    if(s.type){const valid={null:v===null,boolean:typeof v==='boolean',integer:Number.isSafeInteger(v)&&!Object.is(v,-0),string:typeof v==='string',array:Array.isArray(v),object:v!==null&&typeof v==='object'&&!Array.isArray(v)}[s.type];if(!valid)return false;}
    if(typeof v==='string'){const n=[...v].length;if(!v.isWellFormed()||('minLength'in s&&n<s.minLength)||('maxLength'in s&&n>s.maxLength)||(s.pattern&&!new RegExp(s.pattern,'u').test(v)))return false;}
    if(s['x-whp-uint256']){try{if(typeof v!=='string'||BigInt(v)<0n||BigInt(v)>((1n<<256n)-1n))return false;}catch{return false;}}
    if(typeof v==='number'&&(('minimum'in s&&v<s.minimum)||('maximum'in s&&v>s.maximum)))return false;
    if(Array.isArray(v)){
      if(('minItems'in s&&v.length<s.minItems)||('maxItems'in s&&v.length>s.maxItems))return false;
      if(s.uniqueItems&&new Set(v.map(x=>canonical(x))).size!==v.length)return false;
      if(s['x-whp-unique-key']&&new Set(v.map(x=>canonical(x[s['x-whp-unique-key']]))).size!==v.length)return false;
      if(s.items&&!v.every(x=>test(x,s.items,depth+1)))return false;
    }else if(v!==null&&typeof v==='object'){
      if(s.required&&!s.required.every(k=>Object.hasOwn(v,k)))return false;
      for(const [k,x] of Object.entries(v)){
        if(s.properties&&Object.hasOwn(s.properties,k)){if(!test(x,s.properties[k],depth+1))return false;}
        else if(s.additionalProperties===false)return false;
        else if(s.additionalProperties&&typeof s.additionalProperties==='object'&&!test(x,s.additionalProperties,depth+1))return false;
      }
    }
    return true;
  }
  canonical(value);demand(test(value,schema),'PUBLIC_V1_SCHEMA_VIOLATION',503);return value;
}
