'use strict';
const service=loadfile('/usr/libexec/cm2012-proxy-native.uc')();
function call(method,request) {
 try {return service[method](request?.args || {});}catch(e){return {error:'代理操作失败，未输出订阅或凭据。'};}
}
return {cm2012_proxy:{
 status:{call:function(){return call('status',null);}},
 save_subscription:{args:{subscription_url:'',expected_revision:''},call:function(r){return call('save_subscription',r);}},
 apply:{args:{enabled:'',subscription_url:'',expected_revision:''},call:function(r){return call('apply',r);}},
 confirm:{args:{token:''},call:function(r){return call('confirm',r);}},
 rollback:{args:{token:''},call:function(r){return call('rollback',r);}},
 disable:{args:{expected_revision:''},call:function(r){return call('disable',r);}},
 update_subscription:{args:{expected_revision:''},call:function(r){return call('update_subscription',r);}}
}};
