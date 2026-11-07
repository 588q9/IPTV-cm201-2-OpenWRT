#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 64;
    if (unshare(CLONE_NEWNET | CLONE_NEWNS) != 0) {
        perror("unshare(CLONE_NEWNET|CLONE_NEWNS)");
        return 77;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        perror("private mount namespace");
        return 78;
    }
    if (mount("/etc", "/etc", NULL, MS_BIND | MS_REC, NULL) != 0 ||
        mount(NULL, "/etc", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) != 0) {
        perror("read-only /etc in private namespace");
        return 79;
    }
    if (mount("sysfs", "/sys", "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) {
        perror("private network sysfs");
        return 80;
    }
    execvp(argv[1], argv + 1);
    perror("execvp");
    return 126;
}
