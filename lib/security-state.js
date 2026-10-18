'use strict';

// Call only after the original logical database/egress permit was consumed.
// PostgreSQL, not process memory, remains the authority for every replay claim.
const TABLE='/rest/v1/dirac_s2s_security', RPC='/rest/v1/rpc/dirac_s2s_state_v539';
const CLAIM='/rest/v1/rpc/dirac_central_atomic_claim_record_v230';
const CONSUME='/rest/v1/rpc/dirac_central_atomic_consume_v230';
const OWNER='__dirac_storage_owner_v539', KEY=/^[A-Za-z0-9:._-]{1,500}$/;
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const FIELDS=new Set(['security_key','record_json','blocked_until_ms','updated_at','expires_at','created_at','revision']);
const QUERY=new Set(['select','security_key','limit','offset','order','on_conflict','expires_at','updated_at','blocked_until_ms']);
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const invalid=()=>Object.assign(new Error('S2S_STORAGE_CONTRACT_INVALID'),{code:'S2S_STORAGE_CONTRACT_INVALID',status:503});

function owner(body,verifiedCustomerId='') {
  const input=Array.isArray(body)&&body.length===1?body[0]:body;
  const row=object(input)?input:{};
  const record=object(row.p_record_json)?row.p_record_json:object(row.record_json)?row.record_json:{};
  const customer=String(verifiedCustomerId||record.customer_id||'').toLowerCase();
  if(UUID.test(customer))return 'customer:'+customer;
  return /^s2s-admin-v(?:405|410|411):/.test(String(row.p_security_key||row.security_key||''))?'admin':'shared';
}
function request(path,method,body,prefer='',ownerHint='') {
  const resource=String(path||'').split('?',1)[0];
  if(resource===CLAIM||resource===CONSUME) {
    if(resource===CLAIM&&(!object(body)||body.p_table_name!=='dirac_s2s_security'))return null;
    if(method!=='POST'||!object(body)||!object(body.p_record_json)||Object.prototype.hasOwnProperty.call(body.p_record_json,OWNER))throw invalid();
    return {path,method,body:{...body,p_record_json:{...body.p_record_json,[OWNER]:ownerHint||owner(body)}}};
  }
  if(resource!==TABLE)return null;
  if(!['GET','HEAD','POST','PATCH','DELETE'].includes(method))throw invalid();
  const params=new URLSearchParams(String(path).slice(TABLE.length+1)),pairs=Array.from(params);
  if(pairs.length>12||pairs.some(([key])=>!QUERY.has(key)||params.getAll(key).length!==1))throw invalid();
  const query=Object.fromEntries(pairs),selector=query.security_key||'';
  const keys=selector.startsWith('eq.')?[selector.slice(3)]:selector.startsWith('in.(')&&selector.endsWith(')')?selector.slice(4,-1).split(','):[];
  if(selector&&!keys.length&&!/^like\.s2s-report-queue:[A-Za-z0-9:._-]*\*$/.test(selector))throw invalid();
  if(keys.length>1000||keys.some(key=>!KEY.test(key)))throw invalid();
  if(method!=='POST'&&!selector)throw invalid();
  if(['PATCH','DELETE'].includes(method)&&keys.length!==1)throw invalid();
  if(query.select&&query.select!=='*'&&query.select.split(',').some(key=>!FIELDS.has(key)))throw invalid();
  if(query.on_conflict&&query.on_conflict!=='security_key')throw invalid();
  if(query.order&&!/^(?:security_key|expires_at|updated_at|created_at)(?:\.(?:asc|desc))?$/.test(query.order))throw invalid();
  if(['limit','offset'].some(key=>query[key]!==undefined&&!/^(?:0|[1-9][0-9]{0,3})$/.test(query[key])))throw invalid();
  if(['expires_at','updated_at','blocked_until_ms'].some(key=>query[key]&&!/^(?:eq|lte|lt|gte|gt|is)\.[^\x00-\x1f\x7f]{1,80}$/.test(query[key])))throw invalid();
  const row=Array.isArray(body)&&body.length===1?body[0]:body;
  if(['POST','PATCH'].includes(method)&&(!object(row)||Object.keys(row).some(key=>!FIELDS.has(key))))throw invalid();
  if(['GET','HEAD','DELETE'].includes(method)&&body!==undefined)throw invalid();
  return {path:RPC,method:'POST',body:{p_method:method,p_query:query,p_body:row===undefined?null:row,p_prefer:String(prefer||''),p_owner:ownerHint||owner(body)}};
}
module.exports=Object.freeze({owner,request});
