/*
 * resolver.h — Iterative resolution engine shared by both front-ends
 *
 * The engine knows nothing about how client packets arrive or leave.
 * A front-end (socket_resolver.c or afxdp_resolver.c) hands it each
 * client query together with an opaque "client context" — whatever
 * bytes the front-end needs later to address the reply — and the engine
 * calls the front-end's reply function once the answer is ready, which
 * may be immediately (cache hit, --local, NOTIMP) or many round trips
 * later (iterative resolution).
 *
 * Upstream traffic (root / TLD / authoritative servers) always uses an
 * ordinary UDP socket owned by the engine, so both front-ends resolve
 * identically and differ only in their client-facing packet path.
 */
#ifndef RESOLVER_H
#define RESOLVER_H

#include <stdint.h>
#include "dns.h"

/* Largest client context a front-end may pass (bytes).  The AF_XDP
 * front-end stores the query's Ethernet+IPv4+UDP headers: <= 82 bytes. */
#define RESOLVER_CLIENT_CTX_MAX 128

/* Deliver a finished DNS response payload to the client identified by
 * ctx (the bytes the front-end passed to resolver_handle_query). */
typedef void (*resolver_reply_fn)(const void *ctx, int ctx_len,
                                  const uint8_t *dns, int dns_len);

/* local_mode = 1: answer A/AAAA from the built-in zone (benchmark mode).
 * local_mode = 0: iterative resolution from the root servers.
 * Returns the upstream UDP socket fd to poll for readability, or -1 in
 * local mode.  Exits on socket failure. */
int  resolver_init(int local_mode, resolver_reply_fn reply);

/* Process one client query (the UDP payload). */
void resolver_handle_query(const uint8_t *dns, int dns_len,
                           const void *ctx, int ctx_len);

/* Drain and process every pending reply on the upstream socket. */
void resolver_handle_upstream(void);

/* Retry / expire in-flight queries.  Call at least every 100 ms;
 * it rate-limits itself internally. */
void resolver_tick(void);

#endif /* RESOLVER_H */
