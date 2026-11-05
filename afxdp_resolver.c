/*
 * afxdp_resolver.c — DNS resolver using AF_XDP
 *
 * The AF_XDP counterpart to socket_resolver.c.  Both binaries share
 * dns.c, so the ONLY difference in the benchmark is how packets enter
 * and leave the process:
 *
 *   socket_resolver   — recvfrom/sendto over a normal UDP socket
 *   afxdp_resolver    — RX/TX rings on an AF_XDP socket
 *
 * Shared contract:
 *   Receive UDP payload  →  dns_validate_query()
 *                        →  dns_local_lookup()  (--local mode)
 *                        →  dns_build_response()
 *                        →  Send UDP payload
 *
 * What's different here:
 *   - UMEM + XSKMAP setup (lifted from xsk_rx_test.c, with the three
 *     fixes from setup-fixes.patch baked in from line one)
 *   - A free-frame pool so each TX reply uses a separate UMEM frame,
 *     independent of the RX frame the query arrived in
 *   - rx_to_tx(): header swap (MAC/IP/port) + length fix + IP checksum
 *     recompute + UDP checksum=0, so the reply reaches the client
 *
 * Known limitations (v1, intentional):
 *   - --local mode only (apples-to-apples with socket_resolver --local)
 *   - MAC swap trick assumes the client is on the same L2 segment
 *     (the source MAC of the query is the correct next hop for the
 *     reply).  Valid on the veth testbed and any LAN client; NOT
 *     valid if a router sits between client and server.
 *   - Copy mode (XDP_COPY).  Zero-copy would need an i40e/ice/ixgbe/
 *     mlx5 NIC, not the e1000e this is tested on.
 *   - XDP attach mode (--skb / --drv) must be passed explicitly: the
 *     driver decides what "default" (flags=0) means, and on veth that
 *     is native (XDP_FLAGS_DRV_MODE-equivalent), NOT generic, so the
 *     comment "generic XDP" in earlier versions of this file was wrong
 *     for veth.  See configs A/B/C in the benchmark plan.
 *
 * Build:
 *   clang -O2 -g -target bpf \
 *       -I/usr/include/$(uname -m)-linux-gnu \
 *       -c xdp_kern.c -o xdp_kern.o
 *   gcc -O3 -Wall -Wextra -o afxdp_resolver afxdp_resolver.c dns.c \
 *       -lxdp -lbpf
 *   (ASan build: add -fno-sanitize=alignment — UBSan otherwise flags
 *    the IP header at byte offset 14 as misaligned, which is normal
 *    for raw packet buffers and harmless on x86.)
 *
 * Usage:
 *   sudo ./afxdp_resolver --local --skb <interface>   # generic/SKB mode
 *   sudo ./afxdp_resolver --local --drv <interface>   # native/driver mode
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
#include <linux/if_link.h>     /* XDP_FLAGS_SKB_MODE / XDP_FLAGS_DRV_MODE */
#include <linux/ip.h>
#include <linux/udp.h>

#include <xdp/xsk.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dns.h"

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

/* Free-frame pool — stack of UMEM offsets available for TX.
 * RX side manages its own frames via the FILL ring; TX frames are
 * allocated from this pool and returned via the COMPLETION ring. */
static uint64_t free_tx_frames[NUM_FRAMES];
static int      free_tx_count = 0;

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
 * PACKET CRAFTING: query frame -> response frame
 *
 * Takes the incoming packet (Ethernet + IPv4 + UDP + DNS query),
 * swaps the addresses and ports, replaces the DNS payload with the
 * response payload, and fixes all the lengths and checksums.
 *
 * Returns the new total packet length, or -1 on error.
 * ================================================================ */

/* IPv4 header checksum — RFC 1071 one's complement */
static uint16_t ip_checksum(const void *data, int len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/*
 * Build a reply packet in place.
 *
 * pkt:          start of the frame (Ethernet header)
 * pkt_len:      length of the incoming packet
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
 * DNS PROCESSING (shared with socket_resolver via dns.c)
 *
 * Given the DNS query payload, produce the DNS response payload.
 * Returns response length, or -1 if the query should be dropped.
 * ================================================================ */
static int process_dns(const uint8_t *query, int query_len,
                       uint8_t *response, int response_cap) {
    char qname[256];
    uint16_t qtype, ctxid;

    if (!dns_validate_query(query, query_len, qname, sizeof(qname),
                            &qtype, &ctxid))
        return -1;

    /* Only A and AAAA — NOTIMP for the rest */
    if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
        return dns_build_error(response, response_cap, ctxid, qname,
                               qtype, DNS_RCODE_NOTIMP);
    }

    /* Local mode: answer from the shared local zone */
    struct cached_rr ans[MAX_CACHED_RRS];
    int an_count = 0;
    uint8_t rcode = DNS_RCODE_NOERROR;

    if (dns_local_lookup(qname, qtype, ans, &an_count) < 0) {
        rcode = DNS_RCODE_NXDOMAIN;
        an_count = 0;
    }

    return dns_build_response(response, response_cap, ctxid, qname,
                              qtype, rcode, ans, an_count);
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(int argc, char *argv[]) {
    const char *ifname = NULL;
    int local_mode = 0;
    int xdp_mode_flag = 0;      /* XDP_FLAGS_SKB_MODE or XDP_FLAGS_DRV_MODE */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--local") == 0)
            local_mode = 1;
        else if (strcmp(argv[i], "--skb") == 0)
            xdp_mode_flag = XDP_FLAGS_SKB_MODE;
        else if (strcmp(argv[i], "--drv") == 0)
            xdp_mode_flag = XDP_FLAGS_DRV_MODE;
        else
            ifname = argv[i];
    }

    if (!ifname || xdp_mode_flag == 0) {
        fprintf(stderr,
                "Usage: %s --local (--skb | --drv) <interface>\n"
                "  --skb  generic (SKB) mode — works on any NIC/veth\n"
                "  --drv  native (driver) mode — needs driver XDP support\n"
                "  (v1 supports --local mode only; mode and interface "
                "are required)\n",
                argv[0]);
        return 1;
    }

    if (!local_mode) {
        fprintf(stderr,
                "This build only supports --local mode.  Pass --local.\n");
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
    signal(SIGTERM, sigint_handler);   /* `kill`/`timeout` must also
                                         * reach the cleanup path, or
                                         * the XDP program stays attached
                                         * and the next run fails to bind. */

    /* ============================================================
     * 1. Allocate UMEM
     *
     * Half of the frames go to RX (pre-filled into the FILL ring);
     * the other half form the TX free-frame pool.
     * ============================================================ */
    void *umem_area = NULL;
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
    struct xsk_ring_prod tx_ring = {0};

    /* xdp_flags here is cosmetic: XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
     * means libxdp does NOT load/attach a program on our behalf, so the
     * actual attach mode (SKB vs DRV) is set below via bpf_xdp_attach(),
     * using xdp_mode_flag from the command line. */
    struct xsk_socket_config xsk_cfg = {
        .rx_size        = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size        = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags   = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags      = 0,
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

    int xsk_fd = xsk_socket__fd(xsk);

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
    ret = bpf_xdp_attach(ifindex, prog_fd, xdp_mode_flag, NULL);
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

    fprintf(stderr,
            "afxdp_resolver on %s (local mode, copy mode, %s XDP)\n"
            "  UMEM: %u frames x %u bytes  (RX pre-fill: %u, TX pool: %d)\n",
            ifname,
            xdp_mode_flag == XDP_FLAGS_DRV_MODE ? "native/drv" : "generic/skb",
            NUM_FRAMES, FRAME_SIZE,
            umem_cfg.fill_size, free_tx_count);

    /* ============================================================
     * 5. Event loop:  poll → RX → process → TX → wakeup
     *                      → completions → FILL refill
     * ============================================================ */
    unsigned long rx_pkts = 0, tx_pkts = 0;

    while (running) {
        struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
        int poll_ret = poll(&pfd, 1, 1000);
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

        /* --- Receive a batch --- */
        __u32 rx_idx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&rx_ring, RX_BATCH_SIZE,
                                                 &rx_idx);
        if (rcvd == 0) {
            if (xsk_ring_prod__needs_wakeup(&fill_ring))
                recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
            continue;
        }

        /* --- First pass: build the response payloads, remember which
         * RX frames need to be transmitted (and with what length).
         * Reserve TX slots only after we know the exact count — libxdp
         * requires submit==reserve. --- */
        struct tx_plan {
            uint64_t addr;
            uint32_t len;
        } plan[RX_BATCH_SIZE];
        unsigned int planned = 0;

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

            /* ip_hdr_len can exceed 20 when the IP header carries
             * options; the earlier size check only covers the minimum
             * (no-options) header, so re-check before touching udphdr. */
            int udp_data_off = sizeof(struct ethhdr) + ip_hdr_len +
                               (int)sizeof(struct udphdr);
            if (udp_data_off > (int)rx_len) continue;

            struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip_hdr_len);
            if (ntohs(udp->dest) != RESOLVER_PORT) continue;

            int udp_data_len = (int)rx_len - udp_data_off;
            if (udp_data_len <= 0) continue;

            uint8_t *dns_query = rx_pkt + udp_data_off;

            /* Build DNS response via shared dns.c */
            uint8_t dns_response[DNS_BUF_SIZE];
            int dns_resp_len = process_dns(dns_query, udp_data_len,
                                           dns_response,
                                           sizeof(dns_response));
            if (dns_resp_len <= 0) continue;

            /* Grab a TX frame from the pool */
            uint64_t tx_addr = frame_pool_alloc();
            if (tx_addr == UINT64_MAX) break;  /* pool exhausted */

            uint8_t *tx_pkt = (uint8_t *)umem_area + tx_addr;
            int header_bytes = udp_data_off;
            memcpy(tx_pkt, rx_pkt, header_bytes);

            int tx_len = build_reply_frame(tx_pkt, header_bytes,
                                           FRAME_SIZE,
                                           dns_response, dns_resp_len);
            if (tx_len < 0) {
                frame_pool_free(tx_addr);
                continue;
            }

            plan[planned].addr = tx_addr;
            plan[planned].len  = (uint32_t)tx_len;
            planned++;
        }

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

        /* --- Reserve exactly `planned` TX slots and commit them --- */
        if (planned > 0) {
            __u32 tx_idx = 0;
            unsigned int got = xsk_ring_prod__reserve(&tx_ring, planned,
                                                      &tx_idx);
            if (got == planned) {
                for (unsigned int i = 0; i < planned; i++) {
                    struct xdp_desc *td =
                        xsk_ring_prod__tx_desc(&tx_ring, tx_idx + i);
                    td->addr    = plan[i].addr;
                    td->len     = plan[i].len;
                    td->options = 0;
                }
                xsk_ring_prod__submit(&tx_ring, planned);
                tx_pkts += planned;

                if (xsk_ring_prod__needs_wakeup(&tx_ring))
                    sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
            } else {
                /* TX ring full — drop these replies, return frames */
                for (unsigned int i = 0; i < planned; i++)
                    frame_pool_free(plan[i].addr);
            }
        }

        if (xsk_ring_prod__needs_wakeup(&fill_ring))
            recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    }

    fprintf(stderr, "\nafxdp_resolver: RX=%lu TX=%lu\n", rx_pkts, tx_pkts);

detach:
    bpf_xdp_detach(ifindex, xdp_mode_flag, NULL);
cleanup:
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    free(umem_area);
    if (bpf_obj) bpf_object__close(bpf_obj);

    return 0;
}
