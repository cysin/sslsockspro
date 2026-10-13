/* Android socket protection for packaged native TLS clients.
 * Copyright (c) 2026 SSLSocks Pro contributors. SPDX-License-Identifier: MIT
 * A failed broker request must never fall back to an unprotected connection.
 */
/* Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>

int __real_connect(int, const struct sockaddr *, socklen_t);

/* Close private listeners when the Android worker exits. Recheck the parent
 * after prctl to close the fork/prctl race. */
__attribute__((constructor)) static void monitor_parent(void) {
    const char *expected = getenv("SSP_PARENT_PID");
    if (!expected) return;
    char *end = NULL;
    long parent = strtol(expected, &end, 10);
    if (!end || *end || parent <= 1 ||
        prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() != parent)
        _exit(126);
}

static int peer_allowed(const struct sockaddr *address) {
    const char *peers = getenv("SSP_ALLOWED_PEERS");
    if (!peers || strlen(peers) > 8192) return 0;
    char *copy = strdup(peers), *save = NULL;
    if (!copy) return 0;
    int allowed = 0;
    for (char *entry = strtok_r(copy, ",", &save); entry; entry = strtok_r(NULL, ",", &save)) {
        char *delimiter = strrchr(entry, '|');
        if (!delimiter) continue;
        *delimiter++ = 0;
        char *end = NULL;
        long port = strtol(delimiter, &end, 10);
        if (!end || *end || port < 1 || port > 65535) continue;
        unsigned char expected[16];
        if (address->sa_family == AF_INET && inet_pton(AF_INET, entry, expected) == 1) {
            const struct sockaddr_in *peer = (const struct sockaddr_in *)address;
            allowed = peer->sin_port == htons((unsigned short)port) && !memcmp(expected, &peer->sin_addr, 4);
        } else if (address->sa_family == AF_INET6 && inet_pton(AF_INET6, entry, expected) == 1) {
            const struct sockaddr_in6 *peer = (const struct sockaddr_in6 *)address;
            allowed = peer->sin6_port == htons((unsigned short)port) && !memcmp(expected, &peer->sin6_addr, 16);
        }
        if (allowed) break;
    }
    free(copy);
    return allowed;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (!address || (address->sa_family != AF_INET && address->sa_family != AF_INET6))
        return __real_connect(fd, address, length);
    if ((address->sa_family == AF_INET && length < sizeof(struct sockaddr_in)) ||
        (address->sa_family == AF_INET6 && length < sizeof(struct sockaddr_in6))) {
        errno = EINVAL; return -1;
    }
    int loopback = 0;
    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in))
        loopback = (ntohl(((const struct sockaddr_in *)address)->sin_addr.s_addr) >> 24) == 127;
    else if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6))
        loopback = IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)address)->sin6_addr);
    if (loopback) return __real_connect(fd, address, length);
    if (!peer_allowed(address)) { errno = EACCES; return -1; }
    const char *broker = getenv("SSP_PROTECT_SOCKET");
    if (!broker || !*broker || strlen(broker) >= sizeof(((struct sockaddr_un *)0)->sun_path) - 1) {
        errno = EACCES; return -1;
    }
    int channel = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (channel < 0) return -1;
    struct timeval timeout = {5, 0};
    setsockopt(channel, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(channel, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_un target;
    memset(&target, 0, sizeof(target));
    target.sun_family = AF_UNIX;
    memcpy(target.sun_path + 1, broker, strlen(broker));
    if (__real_connect(channel, (const struct sockaddr *)&target, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(broker))) < 0) {
        close(channel); errno = EACCES; return -1;
    }
    char command = 'P';
    struct iovec part = {&command, 1};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &part; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    char response = 0;
    int success = sendmsg(channel, &message, MSG_NOSIGNAL) == 1 && recv(channel, &response, 1, 0) == 1 && response == 'Y';
    close(channel);
    if (!success) { errno = EACCES; return -1; }
    return __real_connect(fd, address, length);
}
