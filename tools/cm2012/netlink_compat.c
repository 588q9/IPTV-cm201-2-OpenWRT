/* The vendor 3.18 bridge policy crashes on modern IFLA_INFO_DATA attributes.
 * Preserve kind/name/ports and let the kernel use its bridge defaults.
 * Buffers use Linux little-endian netlink wire format on this fixed target. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
static uint16_t u16(const unsigned char *p) { return p[0] | (uint16_t)p[1] << 8; }
static uint32_t u32(const unsigned char *p) { return u16(p) | (uint32_t)u16(p+2) << 16; }
static size_t align4(size_t n) { return (n+3) & ~(size_t)3; }
size_t cm2012_filter_bridge(void *data, size_t length) {
 unsigned char *buffer=data; size_t changed=0;
 for (size_t offset=0; offset+16<=length;) {
  unsigned char *message=buffer+offset;
  size_t size=u32(message); unsigned type=u16(message+4);
  if (size<16 || size>length-offset) break;
  if ((type==16 || type==19) && size>=32) {
   for (size_t pos=32; pos+4<=size;) {
    unsigned char *outer=message+pos;size_t bytes=u16(outer);
    if (bytes<4 || bytes>size-pos) break;
    if ((u16(outer+2)&0x3fff)==18) {
     int bridge=0;unsigned char *options=NULL;
     for (size_t inner=4;inner+4<=bytes;) {
      unsigned char *attr=outer+inner;size_t n=u16(attr);unsigned kind=u16(attr+2)&0x3fff;
      if (n<4 || n>bytes-inner) { bridge=0;options=NULL;break; }
      if (kind==1 && n==11 && !memcmp(attr+4,"bridge\0",7)) bridge=1;
      if (kind==2) options=attr;
      inner+=align4(n);
     }
     if (bridge && options) {
      // NLA type 0 is ignored; keep alignment and all message lengths intact.
      options[2]=options[3]=0;changed++;
     }
    }
    pos+=align4(bytes);
   }
  }
  offset+=align4(size);
 }
 return changed;
}
