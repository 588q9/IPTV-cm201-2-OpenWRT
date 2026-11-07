/* Standalone transport harness: no curl or entropy initialization. */
#define _GNU_SOURCE
#include "proxy_api.h"

int main(int argc, char **argv)
{
    return argc == 2 ? cm2012_proxy_api(argv[1]) : 2;
}
