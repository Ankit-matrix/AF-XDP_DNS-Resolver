/*
 * socket_resolver.c — Baseline front-end: client I/O over a UDP socket
 *
 * Control arm of the benchmark.  All DNS work (validation, --local zone,
 * cache, iterative resolution) lives in resolver.c and is identical to
 * afxdp_resolver; the only difference is how client packets arrive and
 * leave:  recvfrom()/sendto() through the normal Linux network stack.
 *
 * Build:
 *   gcc -O3 -Wall -Wextra -o socket_resolver socket_resolver.c resolver.c dns.c
 *
 * Usage:
 *   sudo ./socket_resolver              # recursive resolver, port 53
 *   sudo ./socket_resolver --local      # built-in zone only (benchmark)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "resolver.h"

#define LISTEN_PORT 53
#define MAX_EVENTS  64

/* Client context: where to send the reply. */
struct sock_ctx {
    struct sockaddr_in addr;
    socklen_t          len;
};

static int client_fd;

static void sock_reply(const void *ctx, int ctx_len,
                       const uint8_t *dns, int dns_len) {
    const struct sock_ctx *c = ctx;
    (void)ctx_len;
    sendto(client_fd, dns, dns_len, 0, (const struct sockaddr *)&c->addr, c->len);
}

int main(int argc, char *argv[]) {
    int local_mode = 0;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--local") == 0)
            local_mode = 1;

    client_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (client_fd < 0) { perror("socket(client)"); return 1; }

    int yes = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(LISTEN_PORT);
    if (bind(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    int upstream_fd = resolver_init(local_mode, sock_reply);

    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); return 1; }

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = client_fd };
    epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);
    if (upstream_fd >= 0) {
        ev.data.fd = upstream_fd;
        epoll_ctl(epfd, EPOLL_CTL_ADD, upstream_fd, &ev);
    }

    fprintf(stderr, "socket_resolver listening on port %d (%s mode)\n",
            LISTEN_PORT, local_mode ? "LOCAL" : "recursive");

    struct epoll_event events[MAX_EVENTS];
    for (;;) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, local_mode ? -1 : 100);

        for (int n = 0; n < nfds; n++) {
            if (events[n].data.fd == client_fd) {
                uint8_t buf[DNS_BUF_SIZE];
                struct sock_ctx c = { .len = sizeof(c.addr) };
                ssize_t len = recvfrom(client_fd, buf, sizeof(buf), 0,
                                       (struct sockaddr *)&c.addr, &c.len);
                if (len > 0)
                    resolver_handle_query(buf, (int)len, &c, sizeof(c));
            } else if (events[n].data.fd == upstream_fd) {
                resolver_handle_upstream();
            }
        }
        if (!local_mode)
            resolver_tick();
    }
}
