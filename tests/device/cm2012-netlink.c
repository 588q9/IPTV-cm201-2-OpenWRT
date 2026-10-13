/* Real netlink bridge creation using the attributes that crashed 3.18. */
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
int main(void) {
 unsigned char message[96]={0};
 struct nlmsghdr *h=(void *)message; h->nlmsg_type=RTM_NEWLINK;
 h->nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL;h->nlmsg_seq=1;
 struct rtattr *name=(void *)(message+32);name->rta_len=16;name->rta_type=IFLA_IFNAME;
 memcpy(message+36,"cm2012probe",12);
 struct rtattr *info=(void *)(message+48);info->rta_len=36;info->rta_type=IFLA_LINKINFO;
 struct rtattr *kind=(void *)(message+52);kind->rta_len=11;kind->rta_type=IFLA_INFO_KIND;
 memcpy(message+56,"bridge",7);
 struct rtattr *data=(void *)(message+64);data->rta_len=20;data->rta_type=IFLA_INFO_DATA;
 struct rtattr *attr=(void *)(message+68);attr->rta_len=8;attr->rta_type=5;
 *(unsigned *)(message+72)=300;
 attr=(void *)(message+76);attr->rta_len=5;attr->rta_type=23;message[80]=0;
 h->nlmsg_len=84;
 int fd=socket(AF_NETLINK,SOCK_RAW,NETLINK_ROUTE);
 struct sockaddr_nl local={.nl_family=AF_NETLINK},kernel={.nl_family=AF_NETLINK};
 if(fd<0||bind(fd,(void *)&local,sizeof(local)))return 1;
 struct iovec iov={message,84};struct msghdr m={.msg_name=&kernel,.msg_namelen=sizeof(kernel),.msg_iov=&iov,.msg_iovlen=1};
 if(sendmsg(fd,&m,0)<0){perror("sendmsg");return 2;}
 unsigned char reply[4096];ssize_t n=recv(fd,reply,sizeof(reply),0);close(fd);
 if(n<36||((struct nlmsghdr *)reply)->nlmsg_type!=NLMSG_ERROR)return 3;
 struct nlmsgerr *error=(void *)(reply+16);
 if(error->error){errno=-error->error;perror("netlink ACK");return 4;}
 puts("NATIVE_NETLINK_BRIDGE_CREATE_OK");return 0;
}
