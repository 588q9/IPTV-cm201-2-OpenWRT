/* Fixed private loopback API. Deliberately independent of curl/TLS and RNG. */
#ifndef CM2012_PROXY_API_H
#define CM2012_PROXY_API_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* Overrides exist only in a separately compiled test harness. */
#ifdef CM2012_PROXY_API_TEST
#define CM2012_API_SECRET_DIR CM2012_PROXY_API_TEST_SECRET_DIR
#define CM2012_API_PORT CM2012_PROXY_API_TEST_PORT
#else
#define CM2012_API_SECRET_DIR "/etc/cm2012-proxy"
#define CM2012_API_PORT 9090
#endif

static void cm2012_api_wipe(void *buffer, size_t length)
{
    volatile unsigned char *p = buffer;
    while (length--) *p++ = 0;
}

static void cm2012_api_expired(int signum)
{
    (void)signum;
    _exit(28);
}

static int cm2012_api_key(char *key)
{
    struct stat info;
    int directory = open(CM2012_API_SECRET_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return 0;
    int valid = !fstat(directory, &info) && S_ISDIR(info.st_mode) &&
                info.st_uid == geteuid() && (info.st_mode & 07777) == 0700;
    int fd = valid ? openat(directory, "secret", O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    close(directory);
    if (fd < 0) return 0;
    valid = !fstat(fd, &info) && S_ISREG(info.st_mode) &&
            info.st_uid == geteuid() && (info.st_mode & 07777) == 0600 &&
            (info.st_size == 64 || info.st_size == 65);
    size_t used = 0;
    while (valid && used < 66) {
        ssize_t n = read(fd, key + used, 66 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { valid = 0; break; }
        if (!n) break;
        used += (size_t)n;
    }
    close(fd);
    valid = valid && used == (size_t)info.st_size &&
            (used == 64 || (used == 65 && key[64] == '\n'));
    for (size_t i = 0; i < 64; ++i)
        if (!((key[i] >= '0' && key[i] <= '9') || (key[i] >= 'a' && key[i] <= 'f'))) valid = 0;
    key[64] = 0;
    return valid;
}

struct cm2012_api_json { const char *p, *end; };

static void cm2012_api_space(struct cm2012_api_json *json)
{
    while (json->p < json->end && (*json->p == ' ' || *json->p == '\t' ||
           *json->p == '\r' || *json->p == '\n')) ++json->p;
}

static int cm2012_api_hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int cm2012_api_unicode(struct cm2012_api_json *json, unsigned *value)
{
    *value = 0;
    for (int i = 0; i < 4; ++i) {
        if (json->p == json->end) return 0;
        int digit = cm2012_api_hex((unsigned char)*json->p++);
        if (digit < 0) return 0;
        *value = *value * 16 + (unsigned)digit;
    }
    return 1;
}

/* Decode ASCII object keys; validate escapes, surrogate pairs and UTF-8. */
static int cm2012_api_string(struct cm2012_api_json *json, char *out, size_t size, size_t *length)
{
    if (json->p == json->end || *json->p++ != '"') return 0;
    size_t used = 0;
    while (json->p < json->end) {
        unsigned c = (unsigned char)*json->p++;
        if (c == '"') {
            if (out && size) out[used < size ? used : size - 1] = 0;
            if (length) *length = used;
            return 1;
        }
        if (c < 32) return 0;
        if (c == '\\') {
            if (json->p == json->end) return 0;
            c = (unsigned char)*json->p++;
            if (c == 'u') {
                if (!cm2012_api_unicode(json, &c)) return 0;
                if (c >= 0xd800 && c <= 0xdbff) {
                    unsigned low;
                    if (json->end - json->p < 2 || json->p[0] != '\\' || json->p[1] != 'u') return 0;
                    json->p += 2;
                    if (!cm2012_api_unicode(json, &low) || low < 0xdc00 || low > 0xdfff) return 0;
                    c = 0x10000 + ((c - 0xd800) << 10) + low - 0xdc00;
                } else if (c >= 0xdc00 && c <= 0xdfff) return 0;
            } else if (!strchr("\"\\/bfnrt", (int)c)) return 0;
            else if (c == 'b') c = '\b';
            else if (c == 'f') c = '\f';
            else if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
        } else if (c >= 128) {
            unsigned minimum, left;
            if (c >= 0xc2 && c <= 0xdf) { c &= 31; minimum = 0x80; left = 1; }
            else if (c >= 0xe0 && c <= 0xef) { c &= 15; minimum = 0x800; left = 2; }
            else if (c >= 0xf0 && c <= 0xf4) { c &= 7; minimum = 0x10000; left = 3; }
            else return 0;
            while (left--) {
                if (json->p == json->end || ((unsigned char)*json->p & 0xc0) != 0x80) return 0;
                c = (c << 6) | ((unsigned char)*json->p++ & 63);
            }
            if (c < minimum || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return 0;
        }
        /* A NUL or non-ASCII key cannot accidentally match a fixed ASCII key. */
        if (out && used + 1 < size) out[used] = c && c < 128 ? (char)c : '?';
        ++used;
    }
    return 0;
}

static int cm2012_api_number(struct cm2012_api_json *json, int delay)
{
    const char *start = json->p;
    if (json->p < json->end && *json->p == '-') ++json->p;
    if (json->p == json->end) return 0;
    if (*json->p == '0') ++json->p;
    else {
        if (*json->p < '1' || *json->p > '9') return 0;
        while (json->p < json->end && *json->p >= '0' && *json->p <= '9') ++json->p;
    }
    if (json->p < json->end && *json->p == '.') {
        ++json->p;
        const char *digits = json->p;
        while (json->p < json->end && *json->p >= '0' && *json->p <= '9') ++json->p;
        if (digits == json->p) return 0;
    }
    if (json->p < json->end && (*json->p == 'e' || *json->p == 'E')) {
        ++json->p;
        if (json->p < json->end && (*json->p == '+' || *json->p == '-')) ++json->p;
        const char *digits = json->p;
        while (json->p < json->end && *json->p >= '0' && *json->p <= '9') ++json->p;
        if (digits == json->p) return 0;
    }
    if (delay) {
        /* strtod may underflow a negative nonzero JSON number to -0. */
        if (*start == '-')
            for (const char *p = start + 1; p < json->p && *p != 'e' && *p != 'E'; ++p)
                if (*p >= '1' && *p <= '9') return 0;
        char *end;
        double value = strtod(start, &end);
        if (end != json->p || !isfinite(value) || value < 0) return 0;
    }
    return 1;
}

static int cm2012_api_value(struct cm2012_api_json *json, unsigned depth)
{
    cm2012_api_space(json);
    if (depth > 16 || json->p == json->end) return 0;
    char c = *json->p;
    if (c == '"') return cm2012_api_string(json, NULL, 0, NULL);
    if (c == '{' || c == '[') {
        char close = c == '{' ? '}' : ']';
        ++json->p;
        cm2012_api_space(json);
        if (json->p < json->end && *json->p == close) { ++json->p; return 1; }
        for (;;) {
            if (c == '{') {
                if (!cm2012_api_string(json, NULL, 0, NULL)) return 0;
                cm2012_api_space(json);
                if (json->p == json->end || *json->p++ != ':') return 0;
            }
            if (!cm2012_api_value(json, depth + 1)) return 0;
            cm2012_api_space(json);
            if (json->p == json->end) return 0;
            if (*json->p == close) { ++json->p; return 1; }
            if (*json->p++ != ',') return 0;
            cm2012_api_space(json);
        }
    }
    const char *literal = c == 't' ? "true" : c == 'f' ? "false" : c == 'n' ? "null" : NULL;
    if (literal) {
        size_t length = strlen(literal);
        if ((size_t)(json->end - json->p) < length || memcmp(json->p, literal, length)) return 0;
        json->p += length;
        return 1;
    }
    return cm2012_api_number(json, 0);
}

static int cm2012_api_json_reply(const char *body, size_t length, int probe)
{
    struct cm2012_api_json json = {body, body + length};
    int found = 0;
    cm2012_api_space(&json);
    if (json.p == json.end || *json.p++ != '{') return 0;
    cm2012_api_space(&json);
    for (;;) {
        char key[16] = {0};
        if (!cm2012_api_string(&json, key, sizeof(key), NULL)) return 0;
        cm2012_api_space(&json);
        if (json.p == json.end || *json.p++ != ':') return 0;
        cm2012_api_space(&json);
        if (probe) {
            if (found || strcmp(key, "delay") || !cm2012_api_number(&json, 1)) return 0;
            found = 1;
        } else if (!strcmp(key, "version")) {
            size_t size = 0;
            if (found || !cm2012_api_string(&json, NULL, 0, &size) || !size) return 0;
            found = 1;
        } else if (!cm2012_api_value(&json, 1)) return 0;
        cm2012_api_space(&json);
        if (json.p == json.end) return 0;
        if (*json.p == '}') { ++json.p; break; }
        if (*json.p++ != ',') return 0;
        cm2012_api_space(&json);
    }
    cm2012_api_space(&json);
    return found && json.p == json.end;
}

static int cm2012_api_response(char *response, size_t length, int operation)
{
    if (memchr(response, 0, length)) return 8;
    response[length] = 0;
    char *line = strstr(response, "\r\n");
    if (!line || line - response < 13 ||
        (memcmp(response, "HTTP/1.1 ", 9) && memcmp(response, "HTTP/1.0 ", 9)) ||
        response[9] < '0' || response[9] > '9' || response[10] < '0' || response[10] > '9' ||
        response[11] < '0' || response[11] > '9' || response[12] != ' ') return 8;
    for (char *p = response + 13; p < line; ++p)
        if (((unsigned char)*p < 32 && *p != '\t') || (unsigned char)*p == 127) return 8;
    int status = (response[9] - '0') * 100 + (response[10] - '0') * 10 + response[11] - '0';
    if (status != (operation == 2 ? 204 : 200)) return 22;
    size_t declared = 0;
    int has_length = 0;
    for (line += 2;;) {
        char *end = strstr(line, "\r\n");
        if (!end) return 8;
        if (end == line) {
            char *body = end + 2;
            size_t body_length = length - (size_t)(body - response);
            if (has_length && declared != body_length) return 18;
            if (operation == 2) return body_length ? 8 : 0;
            return cm2012_api_json_reply(body, body_length, operation == 1) ? 0 : 8;
        }
        char *colon = memchr(line, ':', (size_t)(end - line));
        if (!colon || colon == line) return 8;
        for (char *p = line; p < colon; ++p)
            if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                  (*p >= '0' && *p <= '9') || strchr("!#$%&'*+-.^_`|~", *p))) return 8;
        for (char *p = colon + 1; p < end; ++p)
            if (((unsigned char)*p < 32 && *p != '\t') || (unsigned char)*p == 127) return 8;
        if (colon - line == 17 && !strncasecmp(line, "Transfer-Encoding", 17)) return 8;
        if (colon - line == 14 && !strncasecmp(line, "Content-Length", 14)) {
            if (has_length) return 8;
            has_length = 1;
            char *p = colon + 1;
            while (p < end && (*p == ' ' || *p == '\t')) ++p;
            char *digits = p;
            while (p < end && *p >= '0' && *p <= '9') {
                if (declared > (4096u - (unsigned)(*p - '0')) / 10) return 18;
                declared = declared * 10 + (unsigned)(*p++ - '0');
            }
            if (p == digits) return 18;
            while (p < end && (*p == ' ' || *p == '\t')) ++p;
            if (p != end) return 18;
        }
        line = end + 2;
    }
}

/* 0 means this one fixed operation succeeded. Nothing is emitted on failure. */
static int cm2012_proxy_api(const char *command)
{
    int operation;
    if (!strcmp(command, "health")) operation = 0;
    else if (!strcmp(command, "dns-probe")) operation = 1;
    else if (!strcmp(command, "dns-flush")) operation = 2;
    else return 2;
    char key[66] = {0}, request[384] = {0}, response[4097] = {0};
    int connection = -1, code = 2;
    signal(SIGALRM, cm2012_api_expired);
    alarm(operation == 1 ? 4 : 2);
    if (!cm2012_api_key(key)) goto done;
    connection = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(CM2012_API_PORT),
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (connection < 0 || connect(connection, (struct sockaddr *)&address, sizeof(address))) {
        code = 7; goto done;
    }
    const char *path = operation == 0 ? "/version" : operation == 1 ?
        "/proxies/CM2012-DNS/delay?url=https%3A%2F%2F1.1.1.1%2Fcdn-cgi%2Ftrace&timeout=3000&expected=200" :
        "/cache/dns/flush";
    int length = snprintf(request, sizeof(request),
        "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nAuthorization: Bearer %s\r\nConnection: close\r\n%s\r\n",
        operation == 2 ? "POST" : "GET", path, (unsigned)CM2012_API_PORT, key,
        operation == 2 ? "Content-Length: 0\r\n" : "");
    if (length <= 0 || (size_t)length >= sizeof(request)) goto done;
    size_t used = 0;
    while (used < (size_t)length) {
        ssize_t n = send(connection, request + used, (size_t)length - used, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { code = 55; goto done; }
        used += (size_t)n;
    }
    used = 0;
    for (;;) {
        ssize_t n = read(connection, response + used, sizeof(response) - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { code = 56; goto done; }
        if (!n) break;
        used += (size_t)n;
        if (used > 4096) { code = 23; goto done; }
    }
    code = cm2012_api_response(response, used, operation);
done:
    alarm(0);
    if (connection >= 0) close(connection);
    cm2012_api_wipe(key, sizeof(key));
    cm2012_api_wipe(request, sizeof(request));
    cm2012_api_wipe(response, sizeof(response));
    return code;
}

#endif
