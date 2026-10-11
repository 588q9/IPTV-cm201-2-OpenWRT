/* SPDX-License-Identifier: MIT
 * 只读写专属 /tmp 作业文件；帧 CRC、确认重试和有界等待。 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int io(int fd, void *buf, size_t n, int writing) {
    unsigned char *p = buf;
    while (n) {
        if (!writing) {
            struct pollfd f = {fd, POLLIN, 0};
            if (poll(&f, 1, 10000) <= 0) return -1;
        }
        ssize_t k = writing ? write(fd,p,n) : read(fd,p,n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return -1;
        p += k; n -= k;
    }
    return 0;
}
static int ack(int fd, char wanted) {
    struct pollfd p={fd,POLLIN,0};
    int available=poll(&p,1,2000);
    if(available==0) return 1;
    if(available<0) return -1;
    char ch;
    if (io(fd,&ch,1,0)) return -1;
    return ch == wanted ? 0 : ch == 'Q' ? -1 : 1;
}
static long long now_ms(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC,&value);
    return (long long)value.tv_sec*1000 + value.tv_nsec/1000000;
}
static int send_ack(int fd, char kind, uint32_t index) {
    unsigned char packet[8]={'C','M','3',(unsigned char)kind};
    memcpy(packet+4,&index,4); return io(fd,packet,8,1);
}
static int frame_ack(int fd, uint32_t expected) {
    long long deadline=now_ms()+2000; unsigned char mark[4]={0}; int used=0;
    while(now_ms()<deadline) {
        struct pollfd p={fd,POLLIN,0};
        int available=poll(&p,1,(int)(deadline-now_ms()));
        if(available==0) return 1;
        if(available<0) {if(errno==EINTR)continue; return -1;}
        unsigned char ch; if(io(fd,&ch,1,0))return -1;
        if(ch=='Q')return -1;
        if(used==4){memmove(mark,mark+1,3);used=3;} mark[used++]=ch;
        if(used==4 && (!memcmp(mark,"CM3A",4)||!memcmp(mark,"CM3N",4))) {
            uint32_t index; if(io(fd,&index,4,0))return -1;
            if(index==expected)return mark[3]=='A' ? 0 : 1;
            used=0; /* 丢失确认后迟到的旧序号不得确认新帧。 */
        }
    }
    return 1;
}
static uint32_t crc(const unsigned char *p, size_t n) {
    uint32_t v=0xffffffff;
    while(n--) {v^=*p++; for(int i=0;i<8;i++) v=(v>>1)^(0xedb88320u & (0u-(v&1)));}
    return ~v;
}
int main(int argc, char **argv) {
    const char prefix[]="/tmp/cm2012-build-";
    if (argc<3 || strncmp(argv[2],prefix,sizeof(prefix)-1) || strstr(argv[2],"..") || strlen(argv[2])>240) return 2;
    int receiving=!strcmp(argv[1],"rx");
    if ((!receiving && strcmp(argv[1],"tx")) || (receiving && argc!=4)) return 2;
    char partial[256]; snprintf(partial,sizeof(partial),"%s.partial",argv[2]);
    int file=receiving ? open(partial,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600) : open(argv[2],O_RDONLY|O_NOFOLLOW);
    if (file<0) return 2;
    struct stat st; if(fstat(file,&st) || !S_ISREG(st.st_mode)) {close(file);return 2;}
    long long total=receiving ? strtoll(argv[3],NULL,10) : st.st_size;
    if(total<=0 || total>64*1024*1024) {close(file);return 2;}
    int tty=open("/dev/ttyAMA0",O_RDWR|O_NOCTTY), result=1, changed=0;
    struct termios old,next;
    if(tty<0 || tcgetattr(tty,&old)) goto out;
    char message[]="CM3_SWITCH\r\n";
    if(io(tty,message,sizeof(message)-1,1)) goto out;
    tcdrain(tty); next=old; cfmakeraw(&next);
    next.c_cflag &= ~(CRTSCTS|PARENB|CSTOPB|CSIZE); next.c_cflag |= CLOCAL|CREAD|CS8;
    cfsetispeed(&next,B460800); cfsetospeed(&next,B460800);
    if(tcsetattr(tty,TCSADRAIN,&next)) goto out;
    changed=1; if(ack(tty,'G')) goto out;
    unsigned char buffer[1024], previous[1024];
    uint32_t seq=0; long long done=0; int finished=0;
    while(!finished) {
        if(receiving) {
            unsigned char mark[4]; uint32_t fields[3];
            if(io(tty,mark,4,0)) goto out;
            if(!memcmp(mark,"CM3E",4)) {
                if(done!=total) goto out;
                if(send_ack(tty,'A',seq)) goto out;
                finished=1; continue;
            }
            if(memcmp(mark,"CM3F",4) || io(tty,fields,12,0)) goto out;
            uint32_t idx=fields[0], size=fields[1];
            if(idx>=(total+1023)/1024 || size!=(uint32_t)((total-(long long)idx*1024)>1024 ? 1024 : total-(long long)idx*1024)) goto out;
            if(io(tty,buffer,size,0)) goto out;
            char a='A';
            if(crc(buffer,size)!=fields[2]) a='N';
            else if(idx==seq) {
                if(io(file,buffer,size,1)) goto out;
                memcpy(previous,buffer,size); seq++; done+=size;
            } else if(idx+1!=seq || memcmp(previous,buffer,size)) goto out;
            if(send_ack(tty,a,idx)) goto out;
        } else {
            if(done==total) {
                char end[]="CM3E"; if(io(tty,end,4,1) || frame_ack(tty,seq)) goto out;
                finished=1; continue;
            }
            size_t size=total-done>1024 ? 1024 : total-done;
            if(io(file,buffer,size,0)) goto out;
            unsigned char mark[]="CM3F"; uint32_t fields[3]={seq,size,crc(buffer,size)};
            int accepted=0;
            for(int retry=0;retry<5;retry++) {
                if(io(tty,mark,4,1)||io(tty,fields,12,1)||io(tty,buffer,size,1)) goto out;
                int a=frame_ack(tty,seq); if(a<0) goto out; if(a==0){accepted=1;break;}
            }
            if(!accepted) goto out; seq++; done+=size;
        }
    }
    if(ack(tty,'R')) goto out;
    if(receiving && (fsync(file) || rename(partial,argv[2]))) goto out;
    result=0;
out:
    if(changed) {
        tcdrain(tty); usleep(200000); tcsetattr(tty,TCSADRAIN,&old);
        char restored[]="CM3_RESTORED\r\n"; io(tty,restored,sizeof(restored)-1,1);tcdrain(tty);
    }
    if(tty>=0)close(tty);close(file);return result;
}
