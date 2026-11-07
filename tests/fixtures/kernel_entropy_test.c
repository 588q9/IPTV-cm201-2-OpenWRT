/* Exercise the production entropy callback with deterministic syscall results. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

struct result {
    long length;
    int error;
};

static const struct result *results;
static const size_t *requests;
static size_t result_count, used, produced;

static long mock_getrandom(void *output, size_t length, unsigned int flags)
{
    struct result result;
    unsigned char *bytes = output;
    size_t i;

    assert(used < result_count);
    assert(length == requests[used]);
    assert(length <= 256);
    assert(flags == 0);
    result = results[used++];
    if (result.length < 0) {
        errno = result.error;
        return -1;
    }
    assert((size_t) result.length <= length);
    for (i = 0; i < (size_t) result.length; ++i)
        bytes[i] = (unsigned char) (++produced);
    return result.length;
}

#define CM2012_GETRANDOM mock_getrandom
#include "../../tools/cm2012/kernel_entropy.c"

static void prepare(const struct result *steps, const size_t *sizes, size_t count)
{
    results = steps;
    requests = sizes;
    result_count = count;
    used = produced = 0;
}

static void check_bytes(const unsigned char *output, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i)
        assert(output[i] == (unsigned char) (i + 1));
}

static void test_chunks(void)
{
    const struct result steps[] = { {256, 0}, {256, 0}, {88, 0} };
    const size_t sizes[] = {256, 256, 88};
    unsigned char output[602];
    size_t olen = 123, calls = cm2012_entropy_calls();

    memset(output, 0xa5, sizeof(output));
    prepare(steps, sizes, 3);
    assert(mbedtls_platform_entropy_poll(NULL, output + 1, 600, &olen) == 0);
    assert(olen == 600 && used == 3);
    assert(cm2012_entropy_calls() == calls + 1);
    check_bytes(output + 1, 600);
    assert(output[0] == 0xa5 && output[601] == 0xa5);
}

static void test_interrupted_short_reads(void)
{
    const struct result steps[] = {
        {-1, EINTR}, {17, 0}, {-1, EINTR}, {239, 0}, {1, 0}, {43, 0}
    };
    const size_t sizes[] = {256, 256, 256, 256, 44, 43};
    unsigned char output[300];
    size_t olen = 0;

    prepare(steps, sizes, 6);
    assert(mbedtls_platform_entropy_poll(NULL, output, sizeof(output), &olen) == 0);
    assert(olen == 300 && used == 6);
    check_bytes(output, sizeof(output));
}

static void test_failure(long result, int error, size_t prefix)
{
    const struct result steps[] = { {5, 0}, {result, error} };
    const size_t sizes[] = {16, 11};
    unsigned char output[18];
    size_t olen = 123, i, calls = cm2012_entropy_calls();

    memset(output, 0xa5, sizeof(output));
    prepare(prefix ? steps : steps + 1, sizes, prefix ? 2 : 1);
    assert(mbedtls_platform_entropy_poll(NULL, output + 1, 16, &olen) == -0x003c);
    assert(olen == 0 && used == (prefix ? 2 : 1));
    assert(cm2012_entropy_calls() == calls + 1);
    assert(output[0] == 0xa5 && output[17] == 0xa5);
    for (i = 0; i < prefix; ++i)
        assert(output[i + 1] == 0);
    for (i = prefix; i < 16; ++i)
        assert(output[i + 1] == 0xa5);
}

static void test_empty_request(void)
{
    size_t olen = 123, calls = cm2012_entropy_calls();

    prepare(NULL, NULL, 0);
    assert(mbedtls_platform_entropy_poll(NULL, NULL, 0, &olen) == 0);
    assert(olen == 0 && used == 0);
    assert(cm2012_entropy_calls() == calls + 1);
}

extern int mbedtls_entropy_func(void *, unsigned char *, size_t);
static void test_drbg_callback(void)
{
    const struct result steps[] = {{-1,EINTR},{5,0},{11,0}};
    const size_t sizes[] = {16,16,11};
    unsigned char output[16];
    size_t calls=cm2012_entropy_calls();
    prepare(steps,sizes,3);
    assert(mbedtls_entropy_func(NULL,output,sizeof(output))==0);
    check_bytes(output,sizeof(output));
    assert(cm2012_entropy_calls()==calls+1);
    const struct result failures[] = {{5,0},{-1,ENOSYS}};
    const size_t failure_sizes[] = {16,11};
    memset(output,0xa5,sizeof(output));
    prepare(failures,failure_sizes,2);
    assert(mbedtls_entropy_func(NULL,output,sizeof(output))==-0x003c);
    for(size_t i=0;i<5;++i)assert(output[i]==0);
    for(size_t i=5;i<sizeof(output);++i)assert(output[i]==0xa5);
    const struct result zero[]={{0,0}};
    prepare(zero,failure_sizes,1);
    assert(mbedtls_entropy_func(NULL,output,sizeof(output))==-0x003c);
    const struct result error[]={{-1,EIO}};
    prepare(error,failure_sizes,1);
    assert(mbedtls_entropy_func(NULL,output,sizeof(output))==-0x003c);
}

int main(void)
{
    assert(cm2012_entropy_calls() == 0);
    test_chunks();
    test_interrupted_short_reads();
    test_failure(0, 0, 0);
    test_failure(-1, EAGAIN, 0);
    test_failure(-1, ENOSYS, 0);
    test_failure(-1, EIO, 0);
    test_failure(-1, EPERM, 0);
    test_failure(0, 0, 5);
    test_failure(-1, EAGAIN, 5);
    test_failure(-1, ENOSYS, 5);
    test_failure(-1, EIO, 5);
    test_empty_request();
    test_drbg_callback();
    puts("KERNEL_ENTROPY_OK");
    return 0;
}
