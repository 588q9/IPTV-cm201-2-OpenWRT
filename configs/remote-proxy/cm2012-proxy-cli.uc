'use strict';
const service=loadfile('/usr/libexec/cm2012-proxy-native.uc')();
const actions=['transaction','update','guard','recover','suspend','reconcile'];
let action=ARGV[0];if(!(action in actions))exit(2);
try {let result=service[action](ARGV[1]);if(result?.error)exit(1);}catch(e){exit(1);}
