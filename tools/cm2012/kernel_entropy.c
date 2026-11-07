/* Linux 3.18 /dev/random can block after its entropy accounting drains.
 * getrandom with flags=0 obtains kernel CRNG bytes after initialization, while
 * curl retains its DRBG and prediction resistance; this downloader obtains
 * its entropy directly from the initialized kernel CSPRNG. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "kernel_entropy.h"
#include <errno.h>

/* Tests replace only the syscall boundary, including on a Windows host. */
#ifndef CM2012_GETRANDOM
#include <sys/syscall.h>
#include <unistd.h>
#define CM2012_GETRANDOM(output, length, flags) \
    syscall(SYS_getrandom, (output), (length), (flags))
#endif

#define CM2012_ENTROPY_SOURCE_FAILED (-0x003c)

/* This source is linked only into the single-threaded dedicated downloader. */
static size_t entropy_calls;

size_t cm2012_entropy_calls(void)
{
    return entropy_calls;
}

int mbedtls_platform_entropy_poll(void *data, unsigned char *output,
                                  size_t len, size_t *olen)
{
    size_t done = 0;

    (void) data;
    ++entropy_calls;
    *olen = 0;
    while (done < len) {
        size_t chunk = len - done;
        long count;

        if (chunk > 256)
            chunk = 256;
        count = CM2012_GETRANDOM(output + done, chunk, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0 || (size_t) count > chunk) {
            volatile unsigned char *wipe = output;

            while (done)
                wipe[--done] = 0;
            return CM2012_ENTROPY_SOURCE_FAILED;
        }
        done += (size_t) count;
    }
    *olen = done;
    return 0;
}

/* libmbedcrypto locally binds its platform source. curl's externally bound
 * callback is the effective boundary for this dedicated executable. */
int mbedtls_entropy_func(void *data, unsigned char *output, size_t len)
{
    size_t produced = 0;
    int code = mbedtls_platform_entropy_poll(data, output, len, &produced);
    return code == 0 && produced == len ? 0 : CM2012_ENTROPY_SOURCE_FAILED;
}
