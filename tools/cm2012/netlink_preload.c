#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
size_t cm2012_filter_bridge(void *,size_t);
ssize_t sendmsg(int fd,const struct msghdr *msg,int flags) {
 static ssize_t (*original)(int,const struct msghdr *,int);
 if (!original) original=dlsym(RTLD_NEXT,"sendmsg");
 if (!original) { errno=ENOSYS;return -1; }
 struct sockaddr_storage address;socklen_t addrlen=sizeof(address);
 if (!msg || getsockname(fd,(void *)&address,&addrlen) || address.ss_family!=AF_NETLINK)
  return original(fd,msg,flags);
 size_t size=0;
 for (size_t i=0;i<msg->msg_iovlen;i++) {
  if (msg->msg_iov[i].iov_len>1048576-size) { errno=EMSGSIZE;return -1; }
  size+=msg->msg_iov[i].iov_len;
 }
 if (!size) return original(fd,msg,flags);
 unsigned char *copy=malloc(size);
 if (!copy) { errno=ENOMEM;return -1; }
 size_t offset=0;
 for (size_t i=0;i<msg->msg_iovlen;i++) {
  memcpy(copy+offset,msg->msg_iov[i].iov_base,msg->msg_iov[i].iov_len);offset+=msg->msg_iov[i].iov_len;
 }
 cm2012_filter_bridge(copy,size);
 struct iovec iov={copy,size};struct msghdr replacement=*msg;
 replacement.msg_iov=&iov;replacement.msg_iovlen=1;
 ssize_t result=original(fd,&replacement,flags);int saved=errno;
 free(copy);errno=saved;return result;
}
