/* 此 RAM 探针直接使用目标 OpenWrt 的动态 musl，避免静态 PIE 自重定位入口。 */
extern int main(int, char **);
extern int __libc_start_main(int (*)(int, char **), int, char **,
                           void (*)(void), void (*)(void), void (*)(void));
__attribute__((used, visibility("hidden"))) void cm2012_start_c(long *stack)
{
    __libc_start_main(main, (int)stack[0], (char **)(stack + 1), 0, 0, 0);
    __builtin_trap();
}
__attribute__((naked, used)) void _start(void)
{
    __asm__ volatile("mov r0, sp\n"
                     "bic sp, sp, #7\n"
                     "bl cm2012_start_c\n");
}
