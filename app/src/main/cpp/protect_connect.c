/* Android socket protection for packaged native TLS clients.
 * Copyright (c) 2026 SSLSocks Pro contributors. SPDX-License-Identifier: MIT
 * A failed broker request must never fall back to an unprotected connection,
 * and an unverified client of a guarded internal listener is always closed.
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
int __real_accept(int, struct sockaddr *, socklen_t *);
int __real_accept4(int, struct sockaddr *, socklen_t *, int);

/* Close private listeners when the Android worker exits. Recheck the parent
 * after prctl to close the fork/prctl race. */
__attribute__((constructor)) static void monitor_parent(void) {
    /* These processes hold private keys and session secrets: other processes
     * of the same app user may not attach to them or read their memory. */
    prctl(PR_SET_DUMPABLE, 0);
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

/* One request to the app's broker; returns 1 only for an explicit 'Y'.
 * A descriptor (or -1) travels as SCM_RIGHTS. Every failure answers no. */
static int ask_broker(char command, const void *payload, size_t length, int descriptor) {
    const char *broker = getenv("SSP_PROTECT_SOCKET");
    if (!broker || !*broker || strlen(broker) >= sizeof(((struct sockaddr_un *)0)->sun_path) - 1) return 0;
    int channel = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (channel < 0) return 0;
    struct timeval timeout = {5, 0};
    setsockopt(channel, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(channel, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_un target;
    memset(&target, 0, sizeof(target));
    target.sun_family = AF_UNIX;
    memcpy(target.sun_path + 1, broker, strlen(broker));
    if (__real_connect(channel, (const struct sockaddr *)&target, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(broker))) < 0) {
        close(channel); return 0;
    }
    unsigned char request[64];
    if (length > sizeof(request) - 1) { close(channel); return 0; }
    request[0] = (unsigned char)command;
    if (length) memcpy(request + 1, payload, length);
    struct iovec part = {request, length + 1};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &part; message.msg_iovlen = 1;
    if (descriptor >= 0) {
        message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    }
    char response = 0;
    int success = sendmsg(channel, &message, MSG_NOSIGNAL) == (ssize_t)(length + 1) &&
        recv(channel, &response, 1, 0) == 1 && response == 'Y';
    close(channel);
    return success;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (!address || (address->sa_family != AF_INET && address->sa_family != AF_INET6))
        return __real_connect(fd, address, length);
    if ((address->sa_family == AF_INET && length < sizeof(struct sockaddr_in)) ||
        (address->sa_family == AF_INET6 && length < sizeof(struct sockaddr_in6))) {
        errno = EINVAL; return -1;
    }
    int loopback = 0;
    if (address->sa_family == AF_INET)
        loopback = (ntohl(((const struct sockaddr_in *)address)->sin_addr.s_addr) >> 24) == 127;
    else
        loopback = IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)address)->sin6_addr);
    if (loopback) return __real_connect(fd, address, length);
    if (!peer_allowed(address) || !ask_broker('P', NULL, 0, fd)) { errno = EACCES; return -1; }
    return __real_connect(fd, address, length);
}

/* Loopback listeners named in SSP_GUARDED_PORTS are internal to the app. */
static int guarded_listener(int listener) {
    const char *ports = getenv("SSP_GUARDED_PORTS");
    if (!ports || !*ports || strlen(ports) > 256) return 0;
    struct sockaddr_storage local;
    socklen_t length = sizeof(local);
    if (getsockname(listener, (struct sockaddr *)&local, &length) != 0) return 1;
    unsigned short port;
    if (local.ss_family == AF_INET) port = ntohs(((struct sockaddr_in *)&local)->sin_port);
    else if (local.ss_family == AF_INET6) port = ntohs(((struct sockaddr_in6 *)&local)->sin6_port);
    else return 0;
    char copy[257], *save = NULL;
    strcpy(copy, ports);
    for (char *entry = strtok_r(copy, ",", &save); entry; entry = strtok_r(NULL, ",", &save)) {
        char *end = NULL;
        long value = strtol(entry, &end, 10);
        if (end && !*end && value == port) return 1;
    }
    return 0;
}

/* Ask whether the accepted client belongs to this app. Payload: family,
 * peer address(16), peer port(2), local address(16), local port(2). */
static int owner_allowed(int client) {
    struct sockaddr_storage peer, local;
    socklen_t peer_length = sizeof(peer), local_length = sizeof(local);
    if (getpeername(client, (struct sockaddr *)&peer, &peer_length) != 0 ||
        getsockname(client, (struct sockaddr *)&local, &local_length) != 0 || peer.ss_family != local.ss_family) return 0;
    unsigned char payload[37];
    memset(payload, 0, sizeof(payload));
    if (peer.ss_family == AF_INET) {
        const struct sockaddr_in *from = (const struct sockaddr_in *)&peer, *to = (const struct sockaddr_in *)&local;
        payload[0] = 4;
        memcpy(payload + 1, &from->sin_addr, 4); memcpy(payload + 17, &from->sin_port, 2);
        memcpy(payload + 19, &to->sin_addr, 4); memcpy(payload + 35, &to->sin_port, 2);
    } else if (peer.ss_family == AF_INET6) {
        const struct sockaddr_in6 *from = (const struct sockaddr_in6 *)&peer, *to = (const struct sockaddr_in6 *)&local;
        payload[0] = 6;
        memcpy(payload + 1, &from->sin6_addr, 16); memcpy(payload + 17, &from->sin6_port, 2);
        memcpy(payload + 19, &to->sin6_addr, 16); memcpy(payload + 35, &to->sin6_port, 2);
    } else return 0;
    return ask_broker('U', payload, sizeof(payload), -1);
}

static int guard_accepted(int listener, int client) {
    if (client < 0 || !guarded_listener(listener) || owner_allowed(client)) return client;
    close(client);
    errno = ECONNABORTED;
    return -1;
}

int __wrap_accept(int fd, struct sockaddr *address, socklen_t *length) {
    return guard_accepted(fd, __real_accept(fd, address, length));
}

int __wrap_accept4(int fd, struct sockaddr *address, socklen_t *length, int flags) {
    return guard_accepted(fd, __real_accept4(fd, address, length, flags));
}
