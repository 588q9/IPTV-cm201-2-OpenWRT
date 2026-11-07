#ifndef CM2012_KERNEL_ENTROPY_H
#define CM2012_KERNEL_ENTROPY_H

#include <stddef.h>

/* Internal kernel reader, with the same shape as a platform source. */
int mbedtls_platform_entropy_poll(void *data, unsigned char *output,
                                  size_t len, size_t *olen);
/* Exported for curl: full DRBG entropy comes from the initialized kernel CRNG. */
int mbedtls_entropy_func(void *data, unsigned char *output, size_t len);

/* Callback entries in this single-threaded downloader, for runtime proof. */
size_t cm2012_entropy_calls(void);

#endif
