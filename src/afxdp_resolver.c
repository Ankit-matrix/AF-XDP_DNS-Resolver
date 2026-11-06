/*
 * afxdp_resolver.c — AF_XDP front-end: client I/O over XSK rings
 *
 * The AF_XDP counterpart to socket_resolver.c.  Both binaries link the
 * same resolver.c (validation, --local zone, cache, iterative resolution)
 * and dns.c, so the ONLY difference between them is the client-facing
 * packet path:
 *
 *   socket_resolver   — recvfrom/sendto over a normal UDP socket
 *   afxdp_resolver    — RX/TX rings on an AF_XDP socket
 *
 * Data path:
 *   client query  : NIC -> XDP (xdp_kern.o, UDP dst 53) -> XSKMAP -> RX ring
 *                   -> resolver_handle_query()
 *   upstream      : ordinary UDP socket owned by resolver.c (root/TLD/auth);
 *                   replies arrive on an ephemeral port, so XDP passes them
 *                   to the kernel stack
 *   client answer : reply callback -> free UMEM frame -> Eth/IPv4/UDP built
 *                   from the query's saved headers -> TX ring
 *
 * The query's Ethernet+IPv4+UDP headers are the "client context": the
 * engine stores them with an in-flight query and hands them back with
 * the answer, which may come many round trips later.
 *
 * Known limitations:
 *   - The reply's MACs are the query's MACs swapped, so the client must
 *     be on the same L2 segment (valid on the veth testbed and a LAN).
 *   - Copy mode (XDP_COPY), single queue (queue 0), IPv4 only.
 *
 * Build:
 *   clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
 *         -c xdp_kern.c -o xdp_kern.o
 *   gcc -O3 -Wall -Wextra -o afxdp_resolver afxdp_resolver.c resolver.c dns.c \
 *       -lxdp -lbpf
 *
 * Usage:
 *   sudo ./afxdp_resolver <interface> [--local] [--skb|--drv]
 *     (no --local: recursive resolver; --local: built-in zone, benchmark)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <stdint.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_link.h>     /* XDP_FLAGS_SKB_MODE / XDP_FLAGS_DRV_MODE */

#include <xdp/xsk.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "resolver.h"

/* ================================================================
 * CONFIGURATION
 * ================================================================ */
#define NUM_FRAMES       4096
#define FRAME_SIZE       XSK_UMEM__DEFAULT_FRAME_SIZE   /* 4096 */
#define RX_BATCH_SIZE    64
#define TX_BATCH_SIZE    64

#define RESOLVER_PORT    53

/* ================================================================
 * GLOBAL STATE
 * ================================================================ */
static volatile int running = 1;

static void                *umem_area;
static struct xsk_ring_prod tx_ring;
static int                  xsk_fd;

/* Free-frame pool — stack of UMEM offsets available for TX.
 * RX side manages its own frames via the FILL ring; TX frames are
 * allocated from this pool and returned via the COMPLETION ring. */
static uint64_t free_tx_frames[NUM_FRAMES];
static int      free_tx_count = 0;

/* Replies built but not yet on the TX ring (flushed in batches). */
static struct { uint64_t addr; uint32_t len; } tx_batch[TX_BATCH_SIZE];
static unsigned int tx_batch_n;

static unsigned long rx_pkts, tx_pkts, tx_dropped;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

/* ================================================================
 * TX FRAME POOL
 * ================================================================ */
static uint64_t frame_pool_alloc(void) {
    if (free_tx_count == 0) return UINT64_MAX;
    return free_tx_frames[--free_tx_count];
}

static void frame_pool_free(uint64_t addr) {
    if (free_tx_count < NUM_FRAMES)
        free_tx_frames[free_tx_count++] = addr;
}

/* ================================================================
 * PACKET CRAFTING: query headers -> response frame
 *
 * Takes the query's headers (Ethernet + IPv4 + UDP), swaps the
 * addresses and ports, appends the DNS response payload, and fixes
 * all the lengths and checksums.
 * ================================================================ */

/* IPv4 header checksum — RFC 1071 one's complement.
 * Reads the header byte by byte: the fields were just written through
 * struct iphdr, and reading them back through a uint16_t pointer breaks
 * C's strict-aliasing rule — at -O3 GCC reordered a store past the read
 * and produced an off-by-one checksum.  uint8_t access is always legal. */
static uint16_t ip_checksum(const void *data, int len) {
    const uint8_t *p = data;
    uint32_t sum = 0;
    for (int i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (len & 1)
        sum += (uint32_t)p[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)~sum);
}

/*
 * Build a reply packet in place.
 *
 * pkt:          start of the frame, holding a copy of the query's headers
 * pkt_len:      length of those headers
 * frame_cap:    maximum bytes we can write in this frame
 * dns_payload:  the DNS response bytes to put in
 * dns_len:      length of the DNS response
 *
 * Returns the total length of the response frame (eth+ip+udp+dns),
 * or -1 on error.
 */
static int build_reply_frame(uint8_t *pkt, int pkt_len, int frame_cap,
                             const uint8_t *dns_payload, int dns_len) {
    if (pkt_len < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr) +
                        sizeof(struct udphdr)))
        return -1;

    struct ethhdr *eth = (struct ethhdr *)pkt;
    struct iphdr  *ip  = (struct iphdr  *)(pkt + sizeof(struct ethhdr));
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20) return -1;

    struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip_hdr_len);

    int total_len = sizeof(struct ethhdr) + ip_hdr_len +
                    sizeof(struct udphdr) + dns_len;
    if (total_len > frame_cap) return -1;

    /* --- Ethernet: swap MAC addresses --- */
    uint8_t tmp_mac[ETH_ALEN];
    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    /* --- IPv4: swap src/dst, fix tot_len, zero checksum, recompute --- */
    uint32_t tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ip->tot_len = htons(ip_hdr_len + sizeof(struct udphdr) + dns_len);
    ip->ttl = 64;
    ip->check = 0;
    ip->check = ip_checksum(ip, ip_hdr_len);

    /* --- UDP: swap ports, fix length, zero checksum (allowed on IPv4) --- */
    uint16_t tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest   = tmp_port;
    udp->len    = htons(sizeof(struct udphdr) + dns_len);
    udp->check  = 0;

    /* --- DNS payload --- */
    uint8_t *dns_dst = (uint8_t *)udp + sizeof(struct udphdr);
    memcpy(dns_dst, dns_payload, dns_len);

    return total_len;
}

/* ================================================================
 * TX PATH
 * ================================================================ */

/* Put every batched reply on the TX ring and kick the kernel. */
static void tx_flush(void) {
    if (tx_batch_n == 0) return;

    __u32 tx_idx = 0;
    if (xsk_ring_prod__reserve(&tx_ring, tx_batch_n, &tx_idx) == tx_batch_n) {
        for (unsigned int i = 0; i < tx_batch_n; i++) {
            struct xdp_desc *td = xsk_ring_prod__tx_desc(&tx_ring, tx_idx + i);
            td->addr    = tx_batch[i].addr;
            td->len     = tx_batch[i].len;
            td->options = 0;
        }
        xsk_ring_prod__submit(&tx_ring, tx_batch_n);
        tx_pkts += tx_batch_n;

        if (xsk_ring_prod__needs_wakeup(&tx_ring))
            sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    } else {
        /* TX ring full — drop these replies, return frames */
        for (unsigned int i = 0; i < tx_batch_n; i++)
            frame_pool_free(tx_batch[i].addr);
        tx_dropped += tx_batch_n;
    }
    tx_batch_n = 0;
}

/* Reply callback for resolver.c: ctx is the query's Eth+IPv4+UDP headers. */
static void xsk_reply(const void *ctx, int ctx_len,
                      const uint8_t *dns, int dns_len) {
    uint64_t addr = frame_pool_alloc();
    if (addr == UINT64_MAX) { tx_dropped++; return; }   /* pool exhausted */

    uint8_t *frame = (uint8_t *)umem_area + addr;
    memcpy(frame, ctx, ctx_len);
    int len = build_reply_frame(frame, ctx_len, FRAME_SIZE, dns, dns_len);
    if (len < 0) {
        frame_pool_free(addr);
        return;
    }

    tx_batch[tx_batch_n].addr = addr;
    tx_batch[tx_batch_n].len  = (uint32_t)len;
    if (++tx_batch_n == TX_BATCH_SIZE)
        tx_flush();
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(int argc, char *argv[]) {
    const char *ifname = NULL;
    int local_mode = 0;
    __u32 xdp_mode = 0;    /* 0 = kernel picks (native if supported) */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--local") == 0)
            local_mode = 1;
        else if (strcmp(argv[i], "--skb") == 0)
            xdp_mode = XDP_FLAGS_SKB_MODE;     /* force generic XDP */
        else if (strcmp(argv[i], "--drv") == 0)
            xdp_mode = XDP_FLAGS_DRV_MODE;     /* force native XDP */
        else
            ifname = argv[i];
    }

    if (!ifname) {
        fprintf(stderr,
                "Usage: %s <interface> [--local] [--skb|--drv]\n"
                "  default: recursive resolver;  --local: built-in zone only\n",
                argv[0]);
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", ifname);
        return 1;
    }

    /* Raise memlock limit — required for libxdp UMEM allocation */
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
        perror("setrlimit(MEMLOCK)");
        return 1;
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* ============================================================
     * 1. Allocate UMEM
     *
     * Half of the frames go to RX (pre-filled into the FILL ring);
     * the other half form the TX free-frame pool.
     * ============================================================ */
    size_t umem_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&umem_area, getpagesize(), umem_size)) {
        perror("posix_memalign");
        return 1;
    }
    memset(umem_area, 0, umem_size);

    struct xsk_umem *umem = NULL;
    struct xsk_ring_prod fill_ring = {0};   /* patch fix: zero-init */
    struct xsk_ring_cons comp_ring = {0};

    struct xsk_umem_config umem_cfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = 0,
        .flags          = 0,    /* aligned mode */
    };

    int ret = xsk_umem__create(&umem, umem_area, umem_size,
                               &fill_ring, &comp_ring, &umem_cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create: %s\n", strerror(-ret));
        free(umem_area);
        return 1;
    }

    /* ============================================================
     * 2. Create XSK socket
     * ============================================================ */
    struct xsk_socket *xsk = NULL;
    struct xsk_ring_cons rx_ring = {0};     /* patch fix: zero-init */

    struct xsk_socket_config xsk_cfg = {
        .rx_size        = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size        = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags   = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags      = 0,    /* program attached below with xdp_mode */
        .bind_flags     = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };

    ret = xsk_socket__create(&xsk, ifname, 0 /* queue */,
                             umem, &rx_ring, &tx_ring, &xsk_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create: %s\n", strerror(-ret));
        xsk_umem__delete(umem);
        free(umem_area);
        return 1;
    }

    xsk_fd = xsk_socket__fd(xsk);

    /* ============================================================
     * 3. Load XDP program and populate XSKMAP
     * ============================================================ */
    struct bpf_object *bpf_obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "bpf_object__open_file xdp_kern.o: %s\n",
                strerror((int)libbpf_get_error(bpf_obj)));
        goto cleanup;
    }

    ret = bpf_object__load(bpf_obj);
    if (ret) {
        fprintf(stderr, "bpf_object__load: %s\n", strerror(-ret));
        goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(
        bpf_obj, "xdp_dns_redirect");
    if (!prog) {
        fprintf(stderr, "Cannot find xdp_dns_redirect program\n");
        goto cleanup;
    }

    int prog_fd = bpf_program__fd(prog);
    ret = bpf_xdp_attach(ifindex, prog_fd, xdp_mode, NULL);
    if (ret) {
        fprintf(stderr, "bpf_xdp_attach: %s\n", strerror(-ret));
        goto cleanup;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    if (!map) {
        fprintf(stderr, "Cannot find xsks_map\n");
        goto detach;
    }

    int map_fd = bpf_map__fd(map);
    __u32 key = 0;
    ret = bpf_map_update_elem(map_fd, &key, &xsk_fd, 0);
    if (ret) {
        fprintf(stderr, "bpf_map_update_elem(xsks_map): %s\n", strerror(-ret));
        goto detach;
    }

    /* ============================================================
     * 4. Pre-fill the FILL ring and set up the TX frame pool
     *
     * Frames 0..fill_size-1  →  FILL ring (RX use)
     * Frames fill_size..NUM_FRAMES-1  →  TX free-frame pool
     * (patch fix: reserve fill_size, not NUM_FRAMES)
     * ============================================================ */
    __u32 idx = 0;
    ret = xsk_ring_prod__reserve(&fill_ring, umem_cfg.fill_size, &idx);
    if (ret != (int)umem_cfg.fill_size) {
        fprintf(stderr, "Could not reserve FILL ring entries\n");
        goto detach;
    }
    for (__u32 i = 0; i < umem_cfg.fill_size; i++)
        *xsk_ring_prod__fill_addr(&fill_ring, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&fill_ring, umem_cfg.fill_size);

    if (xsk_ring_prod__needs_wakeup(&fill_ring))
        recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);

    /* The rest of the UMEM is available for TX */
    for (__u32 i = umem_cfg.fill_size; i < NUM_FRAMES; i++)
        frame_pool_free((uint64_t)i * FRAME_SIZE);

    /* ============================================================
     * 5. Resolution engine (shared with socket_resolver)
     * ============================================================ */
    int upstream_fd = resolver_init(local_mode, xsk_reply);

    fprintf(stderr,
            "afxdp_resolver on %s (%s mode, copy mode, XDP mode: %s)\n"
            "  UMEM: %u frames x %u bytes  (RX pre-fill: %u, TX pool: %d)\n",
            ifname, local_mode ? "local" : "recursive",
            xdp_mode == XDP_FLAGS_SKB_MODE ? "generic (forced)" :
            xdp_mode == XDP_FLAGS_DRV_MODE ? "native (forced)"  : "auto",
            NUM_FRAMES, FRAME_SIZE,
            umem_cfg.fill_size, free_tx_count);

    /* ============================================================
     * 6. Event loop:  poll → completions → upstream replies/timeouts
     *                      → RX → engine → TX → FILL refill
     * ============================================================ */
    while (running) {
        struct pollfd pfd[2] = {
            { .fd = xsk_fd,      .events = POLLIN },
            { .fd = upstream_fd, .events = POLLIN },
        };
        int poll_ret = poll(pfd, upstream_fd >= 0 ? 2 : 1,
                            local_mode ? 1000 : 100);
        if (poll_ret < 0 && errno != EINTR) {
            perror("poll");
            break;
        }

        /* --- Reclaim TX completions back to the frame pool --- */
        __u32 comp_idx = 0;
        unsigned int completed = xsk_ring_cons__peek(&comp_ring,
                                                      TX_BATCH_SIZE,
                                                      &comp_idx);
        if (completed) {
            for (unsigned int i = 0; i < completed; i++) {
                uint64_t addr = *xsk_ring_cons__comp_addr(&comp_ring,
                                                           comp_idx + i);
                frame_pool_free(addr);
            }
            xsk_ring_cons__release(&comp_ring, completed);
        }

        /* --- Upstream replies and timeouts (recursive mode) --- */
        if (upstream_fd >= 0) {
            if (poll_ret > 0 && (pfd[1].revents & POLLIN))
                resolver_handle_upstream();
            resolver_tick();
            tx_flush();
        }

        /* --- Receive a batch of client queries --- */
        __u32 rx_idx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&rx_ring, RX_BATCH_SIZE,
                                                 &rx_idx);
        if (rcvd == 0) {
            if (xsk_ring_prod__needs_wakeup(&fill_ring))
                recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
            continue;
        }

        for (unsigned int i = 0; i < rcvd; i++) {
            const struct xdp_desc *rx_desc =
                xsk_ring_cons__rx_desc(&rx_ring, rx_idx + i);
            uint8_t *rx_pkt = (uint8_t *)umem_area + rx_desc->addr;
            uint32_t rx_len = rx_desc->len;

            rx_pkts++;

            /* Locate DNS payload inside the frame */
            if (rx_len < sizeof(struct ethhdr) + sizeof(struct iphdr) +
                         sizeof(struct udphdr))
                continue;

            struct ethhdr *eth = (struct ethhdr *)rx_pkt;
            if (eth->h_proto != htons(ETH_P_IP)) continue;

            struct iphdr *ip = (struct iphdr *)(rx_pkt + sizeof(struct ethhdr));
            int ip_hdr_len = ip->ihl * 4;
            if (ip_hdr_len < 20) continue;
            if (ip->protocol != IPPROTO_UDP) continue;

            /* IP options can push the UDP header past the frame end */
            if (sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr) > rx_len)
                continue;

            struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip_hdr_len);
            if (ntohs(udp->dest) != RESOLVER_PORT) continue;

            int udp_data_off = sizeof(struct ethhdr) + ip_hdr_len +
                               sizeof(struct udphdr);
            int udp_data_len = (int)rx_len - udp_data_off;
            if (udp_data_len <= 0) continue;

            /* Hand the DNS payload to the shared engine; the frame's
             * headers are the client context for the reply. */
            resolver_handle_query(rx_pkt + udp_data_off, udp_data_len,
                                  rx_pkt, udp_data_off);
        }
        tx_flush();

        /* --- Release the RX batch and recycle its frames into FILL --- */
        __u32 fill_idx = 0;
        if (xsk_ring_prod__reserve(&fill_ring, rcvd, &fill_idx) == rcvd) {
            for (unsigned int i = 0; i < rcvd; i++) {
                const struct xdp_desc *rx_desc =
                    xsk_ring_cons__rx_desc(&rx_ring, rx_idx + i);
                *xsk_ring_prod__fill_addr(&fill_ring, fill_idx + i) =
                    rx_desc->addr;
            }
            xsk_ring_prod__submit(&fill_ring, rcvd);
        }
        xsk_ring_cons__release(&rx_ring, rcvd);

        if (xsk_ring_prod__needs_wakeup(&fill_ring))
            recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    }

    fprintf(stderr, "\nafxdp_resolver: RX=%lu TX=%lu TX_dropped=%lu\n",
            rx_pkts, tx_pkts, tx_dropped);

    /* Kernel-side AF_XDP drop counters: non-zero rx_ring_full / fill_empty
     * means the 2048-entry rings (or the loop draining them) were too slow. */
    struct xdp_statistics st;
    socklen_t sl = sizeof(st);
    if (getsockopt(xsk_fd, SOL_XDP, XDP_STATISTICS, &st, &sl) == 0)
        fprintf(stderr, "xsk stats: rx_dropped=%llu rx_ring_full=%llu "
                        "fill_empty=%llu tx_invalid=%llu tx_ring_empty=%llu\n",
                (unsigned long long)st.rx_dropped,
                (unsigned long long)st.rx_ring_full,
                (unsigned long long)st.rx_fill_ring_empty_descs,
                (unsigned long long)st.tx_invalid_descs,
                (unsigned long long)st.tx_ring_empty_descs);

detach:
    bpf_xdp_detach(ifindex, xdp_mode, NULL);
cleanup:
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    free(umem_area);
    if (bpf_obj) bpf_object__close(bpf_obj);

    return 0;
}
