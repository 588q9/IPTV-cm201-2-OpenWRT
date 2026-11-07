/* Subscription HTTPS and fixed private loopback API transport. No data is logged.
 * The executable supplies kernel CRNG bytes through the entropy callback,
 * leaving curl's prediction-resistant DRBG and TLS verification in place.
 */
#define _GNU_SOURCE
#include <curl/curl.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "kernel_entropy.h"
#include "proxy_api.h"

#define BODY_LIMIT 4194304u
#define URL_LIMIT 8192u

struct curl_api {
    CURLcode (*global_init)(long);
    void (*global_cleanup)(void);
    curl_version_info_data *(*version_info)(CURLversion);
    CURL *(*easy_init)(void);
    CURLcode (*easy_setopt)(CURL *, CURLoption, ...);
    CURLcode (*easy_perform)(CURL *);
    CURLcode (*easy_getinfo)(CURL *, CURLINFO, ...);
    void (*easy_cleanup)(CURL *);
    struct curl_slist *(*slist_append)(struct curl_slist *, const char *);
    void (*slist_free_all)(struct curl_slist *);
};

struct sink { FILE *file; size_t total; int oversized; };

static size_t receive_body(char *data, size_t size, size_t count, void *context)
{
    struct sink *sink = context;
    if (size && count > (BODY_LIMIT - sink->total) / size) {
        sink->oversized = 1;
        return 0;
    }
    size_t length = size * count;
    size_t written = fwrite(data, 1, length, sink->file);
    sink->total += written;
    return written;
}

static int load_api(void *library, struct curl_api *api)
{
#define LOAD(field, symbol) do { \
    *(void **)(&api->field) = dlsym(library, symbol); \
    if (!api->field) return 0; \
} while (0)
    LOAD(global_init, "curl_global_init");
    LOAD(global_cleanup, "curl_global_cleanup");
    LOAD(version_info, "curl_version_info");
    LOAD(easy_init, "curl_easy_init");
    LOAD(easy_setopt, "curl_easy_setopt");
    LOAD(easy_perform, "curl_easy_perform");
    LOAD(easy_getinfo, "curl_easy_getinfo");
    LOAD(easy_cleanup, "curl_easy_cleanup");
    LOAD(slist_append, "curl_slist_append");
    LOAD(slist_free_all, "curl_slist_free_all");
#undef LOAD
    return 1;
}

static int read_url(const char *path, char *url)
{
    struct stat info;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    int ok = !fstat(fd, &info) && S_ISREG(info.st_mode) &&
             info.st_uid == geteuid() && !(info.st_mode & 077) &&
             info.st_size > 8 && info.st_size <= URL_LIMIT;
    size_t length = ok ? (size_t)info.st_size : 0, used = 0;
    while (used < length) {
        ssize_t n = read(fd, url + used, length - used);
        if (n <= 0) { ok = 0; break; }
        used += (size_t)n;
    }
    close(fd);
    if (!ok) return 0;
    url[length] = 0;
    if (strncmp(url, "https://", 8)) return 0;
    for (size_t i = 0; i < length; ++i)
        if ((unsigned char)url[i] <= 32 || (unsigned char)url[i] == 127) return 0;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 2) return cm2012_proxy_api(argv[1]);
    if ((argc != 4 && argc != 5) || !strcmp(argv[1], argv[2])) return CURLE_FAILED_INIT;
    int github_rule = argc == 5;
    if (github_rule && strcmp(argv[4], "github-rule")) return CURLE_FAILED_INIT;
    char url[URL_LIMIT + 1] = {0};
    if (!read_url(argv[1], url)) return CURLE_URL_MALFORMAT;
    const char github_prefix[] = "https://api.github.com/repos/";
    if (github_rule && strncmp(url, github_prefix, sizeof(github_prefix) - 1)) return CURLE_FAILED_INIT;
    /* Absolute library name prevents a user-controlled search directory. */
    void *library = dlopen("/usr/lib/libcurl.so.4", RTLD_NOW | RTLD_GLOBAL);
    struct curl_api api;
    int code = CURLE_FAILED_INIT, initialized = 0, output_created = 0;
    CURL *handle = NULL;
    struct curl_slist *headers = NULL;
    struct sink sink = {0};
    if (!library || !load_api(library, &api)) goto done;
    curl_version_info_data *version = api.version_info(CURLVERSION_FIRST);
    if (!version || version->version_num != LIBCURL_VERSION_NUM ||
        !version->ssl_version || strcmp(version->ssl_version, "mbedTLS/3.6.7")) goto done;
    if (api.global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) goto done;
    initialized = 1;
    /* Refuse to connect if a changed runtime bound the old source internally. */
    if (!cm2012_entropy_calls()) goto done;
    handle = api.easy_init();
    if (!handle) goto done;
    int fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { code = CURLE_WRITE_ERROR; goto done; }
    output_created = 1;
    if (fchmod(fd, 0600) || !(sink.file = fdopen(fd, "wb"))) {
        close(fd); code = CURLE_WRITE_ERROR; goto done;
    }
#define SET(option, value) do { \
    code = api.easy_setopt(handle, option, value); \
    if (code != CURLE_OK) goto done; \
} while (0)
    SET(CURLOPT_URL, url);
    SET(CURLOPT_PROTOCOLS_STR, "https");
    SET(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    SET(CURLOPT_FOLLOWLOCATION, 1L);
    SET(CURLOPT_MAXREDIRS, 3L);
    SET(CURLOPT_CONNECTTIMEOUT, 10L);
    SET(CURLOPT_TIMEOUT, 35L);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_FAILONERROR, 1L);
    SET(CURLOPT_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_SSL_VERIFYHOST, 2L);
    SET(CURLOPT_CAINFO, argv[3]);
    SET(CURLOPT_PROXY, "");
    SET(CURLOPT_USERAGENT, "clash.meta");
    if (github_rule) {
        headers = api.slist_append(NULL, "Accept: application/vnd.github.raw+json");
        if (!headers) { code = CURLE_OUT_OF_MEMORY; goto done; }
        SET(CURLOPT_HTTPHEADER, headers);
    }
    SET(CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)BODY_LIMIT);
    SET(CURLOPT_WRITEFUNCTION, receive_body);
    SET(CURLOPT_WRITEDATA, &sink);
#undef SET
    size_t before = cm2012_entropy_calls();
    code = api.easy_perform(handle);
    if (github_rule && code == CURLE_HTTP_RETURNED_ERROR) {
        long response = 0;
        if (api.easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response) != CURLE_OK)
            code = CURLE_FAILED_INIT;
        else if (response == 403 || response == 429)
            code = 69; /* Dedicated HTTPS transport: GitHub request/rate limit. */
    }
    if (sink.oversized) code = CURLE_FILESIZE_EXCEEDED;
    if (code == CURLE_OK && cm2012_entropy_calls() <= before) code = CURLE_FAILED_INIT;
done:
    if (sink.file && fclose(sink.file) && code == CURLE_OK) code = CURLE_WRITE_ERROR;
    if (handle) api.easy_cleanup(handle);
    if (headers) api.slist_free_all(headers);
    if (initialized) api.global_cleanup();
    if (library) dlclose(library);
    if (code && output_created) unlink(argv[2]);
    volatile char *wipe = url;
    for (size_t i = 0; i < sizeof(url); ++i) wipe[i] = 0;
    return code;
}
