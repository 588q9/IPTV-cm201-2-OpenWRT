/* Regression for the captured 3.18 validate_nla bridge-creation crash. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
size_t cm2012_filter_bridge(void *, size_t);
static const unsigned char message[64] = {
 64,0,0,0,16,0,5,6, 1,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
 32,0,18,128, 11,0,1,0,'b','r','i','d','g','e',0,0,
 16,0,2,128, 12,0,5,0, 0,0,0,0,0,0,0,0
};
int main(void) {
 unsigned char buffer[128], expected[64];
 memcpy(buffer,message,64); memcpy(expected,message,64);
 expected[50]=expected[51]=0;
 assert(cm2012_filter_bridge(buffer,64)==1);
 assert(!memcmp(buffer,expected,64));
 assert(cm2012_filter_bridge(buffer,64)==0);
 memcpy(buffer,message,64);buffer[40]='v';
 assert(cm2012_filter_bridge(buffer,64)==0);
 assert(buffer[50]==2);
 memcpy(buffer,message,64);
 assert(cm2012_filter_bridge(buffer,63)==0 && buffer[50]==2);
 buffer[32]=255;
 assert(cm2012_filter_bridge(buffer,64)==0 && buffer[50]==2);
 memcpy(buffer,message,64);memcpy(buffer+64,message,64);
 assert(cm2012_filter_bridge(buffer,128)==2);
 puts("NETLINK_BRIDGE_COMPAT_OK");
 return 0;
}
