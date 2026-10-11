#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>

/* 保留最小 RAM 文件及其根目录引用，失败时恢复原 shell 的依赖。 */
static void maintenance(int old_root, const char *reason)
{
    int saved_errno = errno;
    fprintf(stderr, "CM2012 切根失败：%s：%s；保持 PID %ld\n",
            reason, strerror(saved_errno), (long)getpid());
    if (old_root >= 0 && fchdir(old_root) == 0 && chroot(".") == 0 && chdir("/") == 0) {
        fprintf(stderr, "CM2012 已恢复原 RAM 维护根，未删除原维护文件\n");
        struct statfs current;
        if (statfs("/proc", &current) < 0 || (unsigned long)current.f_type != 0x9fa0UL)
            mount("proc", "/proc", "proc", 0, NULL);
        if (statfs("/sys", &current) < 0 || (unsigned long)current.f_type != 0x62656572UL)
            mount("sysfs", "/sys", "sysfs", 0, NULL);
    } else {
        fprintf(stderr, "CM2012 无法恢复原 RAM 根，仍保持维护进程\n");
    }
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
    for (;;) {
        pid_t child = fork();
        if (child == 0) {
            setsid();
            ioctl(STDIN_FILENO, TIOCSCTTY, 0);
            execl("/bin/sh", "/bin/sh", (char *)NULL);
            perror("CM2012 维护 shell");
            _exit(127);
        }
        if (child > 0) {
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        }
        sleep(1);
    }
}

int main(int argc, char **argv)
{
    int old_root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (old_root < 0) maintenance(-1, "打开原根");
    if (getpid() != 1) { errno = EPERM; maintenance(old_root, "切根程序必须是 PID1"); }
    int test_failure = argc == 2 && !strcmp(argv[1], "--test-exec-failure");
    if (argc != 1 && !test_failure) { errno = EINVAL; maintenance(old_root, "未知参数"); }

    struct stat original, target;
    struct statfs filesystem;
    if (fstat(old_root, &original) < 0 || stat("/newroot", &target) < 0 ||
        statfs("/newroot", &filesystem) < 0)
        maintenance(old_root, "检查内部根挂载");
    if (!S_ISDIR(target.st_mode) || original.st_dev == target.st_dev ||
        (unsigned long)filesystem.f_type != 0x24051905UL) {
        errno = EINVAL;
        maintenance(old_root, "目标不是独立 UBIFS 根");
    }
    if (chdir("/newroot") < 0) maintenance(old_root, "进入内部根");
    if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) maintenance(old_root, "移动根挂载");
    if (chroot(".") < 0 || chdir("/") < 0) maintenance(old_root, "更换进程根");
    setenv("INITRAMFS", "1", 1);
    const char *init = test_failure ? "/cm2012-intentionally-missing-init" : "/sbin/init";
    char *const init_arguments[] = {(char *)init, NULL};
    execv(init, init_arguments);
    maintenance(old_root, test_failure ? "注入 init 执行失败" : "执行内部 init");
}
