/* Opt-in device fixture: loopback only, one request, no header/body logging. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char **argv)
{
    alarm(15);
    if (argc != 2) return 2;
    int server=socket(AF_INET,SOCK_STREAM,0),one=1;
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(9090),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if (server<0 || setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one)) ||
        bind(server,(struct sockaddr*)&address,sizeof(address)) || listen(server,1)) return 3;
    int client=accept(server,NULL,NULL);close(server);
    if (client<0) return 4;
    char request[1024]={0};size_t used=0;
    while (used<sizeof(request)-1 && !strstr(request,"\r\n\r\n")) {
        ssize_t n=read(client,request+used,sizeof(request)-used-1);if(n<=0)return 5;used+=(size_t)n;
    }
    /* The real key stays in process memory and never appears in test output. */
    if (strncmp(request,"GET /version HTTP/1.1\r\n",23) || !strstr(request,"Authorization: Bearer ")) return 6;
    if (!strcmp(argv[1],"stall")) {sleep(4);close(client);return 0;}
    const char *response=!strcmp(argv[1],"ok")?"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}":
        !strcmp(argv[1],"unauthorized")?"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n":
        !strcmp(argv[1],"redirect")?"HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\nContent-Length: 0\r\n\r\n":
        !strcmp(argv[1],"partial")?"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial":
        !strcmp(argv[1],"badstatus")?"HTTP/1.1 2000 Invalid\r\nContent-Length: 0\r\n\r\n":
        "HTTP/1.1 200 OK\r\nContent-Length: 4097\r\nConnection: close\r\n\r\n";
    (void)write(client,response,strlen(response));
    if (!strcmp(argv[1],"large")) {char body[4097];memset(body,'x',sizeof(body));(void)write(client,body,sizeof(body));}
    close(client);return 0;
}
