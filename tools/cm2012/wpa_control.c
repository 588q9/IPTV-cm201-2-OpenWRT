#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 固定接口控制工具；密码只写入 0600 配置文件，不放在命令参数。 */
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "STATUS") && strcmp(argv[1], "SCAN") &&
                     strcmp(argv[1], "SCAN_RESULTS") && strcmp(argv[1], "DISCONNECT"))) return 2;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_un local = {.sun_family=AF_UNIX}, remote = {.sun_family=AF_UNIX};
    snprintf(local.sun_path, sizeof(local.sun_path), "/tmp/cm2012-wpa-ctrl-%ld", (long)getpid());
    strcpy(remote.sun_path, "/var/run/wpa_supplicant/wlan0");
    unlink(local.sun_path);
    if (bind(fd, (void *)&local, sizeof(local)) || connect(fd, (void *)&remote, sizeof(remote))) {
        perror("wpa control"); close(fd); unlink(local.sun_path); return 1;
    }
    int status = 1;
    if (send(fd, argv[1], strlen(argv[1]), 0) >= 0) {
        struct pollfd p = {.fd=fd, .events=POLLIN};
        if (poll(&p, 1, 5000) > 0) {
            char buffer[32768];
            ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
            if (count > 0) {
                fwrite(buffer, 1, count, stdout);
                status = count >= 4 && !memcmp(buffer, "FAIL", 4) ? 1 : 0;
            }
        }
    }
    close(fd); unlink(local.sun_path); return status;
}
