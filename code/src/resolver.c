/*
 * resolver.c — Iterative resolution engine shared by both front-ends
 *
 * Client side : recursive queries (RD=1) handed in by a front-end.
 * Upstream    : iterative queries (RD=0) on one ordinary UDP socket,
 *               root -> TLD -> authoritative, following referrals.
 *
 * Handles:
 *   - referrals with glue, and referrals WITHOUT glue ("glueless"):
 *     the NS name's address is resolved by a child query first
 *   - CNAME chains, inside one response or across zones; the client
 *     gets the full chain and the question it actually asked
 *   - NXDOMAIN and NODATA, both negatively cached (RFC 2308 TTL)
 *   - a TTL cache for answers, CNAMEs, negative results and in-bailiwick glue
 *   - per-hop timeout with failover to the next nameserver, and an
 *     overall per-query deadline
 *
 * Safety checks on every upstream reply: source port 53, source IP equal
 * to the server we asked, matching TXID, matching question; referrals
 * must move strictly down the tree toward the name being resolved;
 * A/AAAA RDATA must be exactly 4/16 bytes.
 */
#define _GNU_SOURCE
#include "resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/random.h>

/* ================================================================
 * CONFIGURATION
 * ================================================================ */
#define MAX_PENDING        4096   /* in-flight queries (client + NS lookups) */
#define MAX_REFERRALS      16     /* referral hops per name                 */
#define MAX_CNAME_CHAIN    8      /* CNAMEs followed per client query       */
#define MAX_NS             13     /* nameserver addresses tried per zone    */
#define MAX_GLUELESS       4      /* glueless NS names tried per zone       */
#define MAX_CHILD_DEPTH    2      /* NS lookup inside NS lookup, at most    */
#define QUERY_TIMEOUT_MS   5000   /* overall deadline per client query      */
#define HOP_TIMEOUT_MS     1000   /* wait per nameserver before failover    */
#define TICK_INTERVAL_MS   10

#define CACHE_BUCKETS      4096
#define CACHE_MAX_ENTRIES  8192
#define TTL_CAP            86400
#define NEG_TTL_DEFAULT    300
#define NEG_TTL_CAP        3600

static const char *ROOT_SERVERS[] = {
    "198.41.0.4",     "170.247.170.2", "192.33.4.12",   "199.7.91.13",
    "192.203.230.10", "192.5.5.241",   "192.112.36.4",  "198.97.190.53",
    "192.36.148.17",  "192.58.128.30", "193.0.14.129",  "199.7.83.42",
    "202.12.27.33",
};
#define NUM_ROOTS 13

/* ================================================================
 * GLOBAL STATE
 * ================================================================ */
static int               local_mode;
static int               upstream_fd = -1;
static resolver_reply_fn reply_cb;

/* ================================================================
 * UTILITIES
 * ================================================================ */
static uint16_t rand16(void) {
    uint16_t v;
    if (getrandom(&v, sizeof(v), 0) != sizeof(v))
        v = (uint16_t)(rand() ^ (rand() << 8));
    return v;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Is `name` equal to or below `zone`?  Names carry no trailing dot and
 * the root zone is "".  Example: in_zone("a.b.com", "b.com") == 1. */
static int in_zone(const char *name, const char *zone) {
    size_t n = strlen(name), z = strlen(zone);
    if (z == 0) return 1;
    if (n < z || strcasecmp(name + n - z, zone) != 0) return 0;
    return n == z || name[n - z - 1] == '.';
}

/* ================================================================
 * CACHE
 *
 * Keyed by (name, type).  An entry is one of:
 *   positive  — rr_count RRs (A/AAAA addresses, or one CNAME whose
 *               rdata holds the target as a NUL-terminated string)
 *   NXDOMAIN  — the name does not exist
 *   NODATA    — the name exists but has no RRs of this type
 * ================================================================ */
enum { NEG_NONE = 0, NEG_NXDOMAIN = 1, NEG_NODATA = 2 };

struct cache_entry {
    char     name[256];
    uint16_t type;
    int      neg;
    uint64_t expire_ms;
    int      rr_count;
    struct cached_rr rrs[MAX_CACHED_RRS];
    struct cache_entry *next;
};

static struct cache_entry *cache_ht[CACHE_BUCKETS];
static struct cache_entry  cache_pool[CACHE_MAX_ENTRIES];
static int                 cache_used;

static uint32_t cache_hash(const char *name, uint16_t type) {
    uint32_t h = type * 31u;
    for (const char *p = name; *p; p++)
        h = h * 131u + (uint32_t)tolower((unsigned char)*p);
    return h % CACHE_BUCKETS;
}

static struct cache_entry *cache_lookup(const char *name, uint16_t type) {
    uint64_t now = now_ms();
    for (struct cache_entry *e = cache_ht[cache_hash(name, type)]; e; e = e->next)
        if (e->type == type && dns_name_eq(e->name, name))
            return e->expire_ms > now ? e : NULL;
    return NULL;
}

static uint32_t cache_ttl_left(const struct cache_entry *e) {
    uint64_t now = now_ms();
    return e->expire_ms > now ? (uint32_t)((e->expire_ms - now + 999) / 1000) : 0;
}

static void cache_unlink(struct cache_entry *e) {
    struct cache_entry **pp = &cache_ht[cache_hash(e->name, e->type)];
    for (; *pp; pp = &(*pp)->next)
        if (*pp == e) { *pp = e->next; return; }
}

static struct cache_entry *cache_alloc(void) {
    if (cache_used < CACHE_MAX_ENTRIES)
        return &cache_pool[cache_used++];
    /* Full: evict the entry that expires first. */
    struct cache_entry *victim = &cache_pool[0];
    for (int i = 1; i < CACHE_MAX_ENTRIES; i++)
        if (cache_pool[i].expire_ms < victim->expire_ms)
            victim = &cache_pool[i];
    cache_unlink(victim);
    return victim;
}

static void cache_put(const char *name, uint16_t type,
                      const struct cached_rr *rrs, int n,
                      uint32_t ttl, int neg) {
    if (ttl == 0) return;
    if (ttl > TTL_CAP) ttl = TTL_CAP;
    if (n > MAX_CACHED_RRS) n = MAX_CACHED_RRS;

    struct cache_entry *e = NULL;
    for (struct cache_entry *c = cache_ht[cache_hash(name, type)]; c; c = c->next)
        if (c->type == type && dns_name_eq(c->name, name)) { e = c; break; }

    if (!e) {
        e = cache_alloc();
        snprintf(e->name, sizeof(e->name), "%s", name);
        e->type = type;
        uint32_t h = cache_hash(name, type);
        e->next = cache_ht[h];
        cache_ht[h] = e;
    }
    e->neg       = neg;
    e->expire_ms = now_ms() + (uint64_t)ttl * 1000;
    e->rr_count  = n;
    if (n > 0)
        memcpy(e->rrs, rrs, (size_t)n * sizeof(struct cached_rr));
}

/* ================================================================
 * IN-FLIGHT QUERIES
 *
 * A client query (depth 0) may spawn one child query at a time (depth
 * 1..MAX_CHILD_DEPTH) to find the address of a glueless nameserver.
 * chain[0] is the name the client asked; chain[k] is the current name
 * after following k CNAMEs.
 * ================================================================ */
enum { P_FREE = 0, P_BUSY, P_WAIT_NS, P_WAIT_CHILD };

struct pending {
    int      state;
    int      depth;                 /* 0 = client query, >0 = NS lookup  */
    int      parent;                /* query waiting on us, or -1        */
    int      child;                 /* our NS-address lookup, or -1      */

    uint16_t client_txid;
    uint8_t  ctx[RESOLVER_CLIENT_CTX_MAX];
    int      ctx_len;

    uint16_t qtype;
    char     chain[MAX_CNAME_CHAIN + 1][256];
    uint32_t chain_ttl[MAX_CNAME_CHAIN];
    int      chain_len;

    char     zone[256];             /* zone of the servers in ns[]       */
    int      referrals;
    struct sockaddr_in ns[MAX_NS];
    int      ns_count, ns_next;
    char     glueless[MAX_GLUELESS][256];
    int      gl_count, gl_next;

    uint16_t txid;                  /* of the query now outstanding      */
    struct sockaddr_in cur_ns;
    uint64_t deadline_ms;
    uint64_t hop_deadline_ms;
};

#define CUR(p) ((p)->chain[(p)->chain_len])

static struct pending pending[MAX_PENDING];
static int            alloc_hint;

static int pending_alloc(void) {
    for (int k = 0; k < MAX_PENDING; k++) {
        int i = (alloc_hint + k) % MAX_PENDING;
        if (pending[i].state == P_FREE) {
            alloc_hint = i + 1;
            memset(&pending[i], 0, sizeof(pending[i]));
            pending[i].state  = P_BUSY;
            pending[i].parent = -1;
            pending[i].child  = -1;
            return i;
        }
    }
    return -1;
}

static struct pending *pending_find(uint16_t txid, uint32_t server_ip) {
    for (int i = 0; i < MAX_PENDING; i++)
        if (pending[i].state == P_WAIT_NS && pending[i].txid == txid &&
            pending[i].cur_ns.sin_addr.s_addr == server_ip)
            return &pending[i];
    return NULL;
}

/* ================================================================
 * REPLY TO THE CLIENT
 *
 * Answer section = the CNAME chain followed (owner chain[i] -> target
 * chain[i+1]) and then the final RRset owned by chain[chain_len].
 * The question is always the name the client asked.
 * ================================================================ */
static int put_name(uint8_t *buf, int cap, int pos, const char *name) {
    int n = dns_encode_name(name, buf + pos, cap - pos);
    return n < 0 ? -1 : pos + n;
}

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xFF; p[2] = (v >> 8) & 0xFF; p[3] = v & 0xFF;
}

static int build_answer(uint8_t *buf, int cap, const struct pending *p,
                        uint8_t rcode, const struct cached_rr *rrs, int n,
                        uint32_t ttl) {
    if (cap < DNS_HDR_SIZE) return -1;
    memset(buf, 0, DNS_HDR_SIZE);
    put16(buf, p->client_txid);
    buf[2] = 0x81;                          /* QR=1, RD=1 */
    buf[3] = 0x80 | rcode;                  /* RA=1       */
    put16(buf + 4, 1);
    put16(buf + 6, (uint16_t)(p->chain_len + n));

    int pos = put_name(buf, cap, DNS_HDR_SIZE, p->chain[0]);
    if (pos < 0 || pos + 4 > cap) return -1;
    put16(buf + pos, p->qtype);
    put16(buf + pos + 2, DNS_CLASS_IN);
    pos += 4;

    for (int i = 0; i < p->chain_len; i++) {           /* CNAME chain */
        pos = put_name(buf, cap, pos, p->chain[i]);
        if (pos < 0 || pos + 10 > cap) return -1;
        int end = put_name(buf, cap, pos + 10, p->chain[i + 1]);
        if (end < 0) return -1;
        put16(buf + pos, DNS_TYPE_CNAME);
        put16(buf + pos + 2, DNS_CLASS_IN);
        put32(buf + pos + 4, p->chain_ttl[i]);
        put16(buf + pos + 8, (uint16_t)(end - pos - 10));
        pos = end;
    }
    for (int i = 0; i < n; i++) {                       /* final RRset */
        pos = put_name(buf, cap, pos, CUR(p));
        if (pos < 0 || pos + 10 + rrs[i].rdlength > cap) return -1;
        put16(buf + pos, rrs[i].type);
        put16(buf + pos + 2, DNS_CLASS_IN);
        put32(buf + pos + 4, ttl);
        put16(buf + pos + 8, rrs[i].rdlength);
        memcpy(buf + pos + 10, rrs[i].rdata, rrs[i].rdlength);
        pos += 10 + rrs[i].rdlength;
    }
    return pos;
}

/* ================================================================
 * RESOLUTION
 * ================================================================ */
static int  try_next_ns(struct pending *p);
static void notify_parent(int parent, int child, int ok,
                          const struct cached_rr *rrs, int n);

/* Complete a query.  A client query replies to its client; an NS lookup
 * hands its addresses (or its failure) back to the query waiting on it.
 * The caller must not touch p afterwards. */
static void finish(struct pending *p, uint8_t rcode,
                   const struct cached_rr *rrs, int n, uint32_t ttl) {
    if (p->depth > 0) {
        int parent = p->parent, self = (int)(p - pending);
        p->state = P_FREE;
        notify_parent(parent, self, rcode == DNS_RCODE_NOERROR, rrs, n);
        return;
    }
    uint8_t buf[DNS_BUF_SIZE];
    int len = build_answer(buf, sizeof(buf), p, rcode, rrs, n, ttl);
    if (len < 0)
        len = dns_build_error(buf, sizeof(buf), p->client_txid, p->chain[0],
                              p->qtype, DNS_RCODE_SERVFAIL);
    if (len > 0)
        reply_cb(p->ctx, p->ctx_len, buf, len);
    p->state = P_FREE;
}

static void fail(struct pending *p) {
    finish(p, DNS_RCODE_SERVFAIL, NULL, 0, 0);
}

static void add_ns(struct pending *p, const uint8_t ip[4]) {
    if (p->ns_count >= MAX_NS) return;
    struct sockaddr_in *a = &p->ns[p->ns_count++];
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_port   = htons(53);
    memcpy(&a->sin_addr, ip, 4);
}

static void send_query(struct pending *p, const struct sockaddr_in *ns) {
    uint8_t buf[512];
    p->txid = rand16();
    int len = dns_build_query(buf, sizeof(buf), p->txid, CUR(p), p->qtype);
    if (len < 0) { fail(p); return; }
    buf[2] = 0x00;                          /* RD=0: we iterate ourselves */

    p->cur_ns          = *ns;
    p->hop_deadline_ms = now_ms() + HOP_TIMEOUT_MS;
    p->state           = P_WAIT_NS;
    sendto(upstream_fd, buf, len, 0, (const struct sockaddr *)ns, sizeof(*ns));
    /* A failed send is handled like a lost packet: the hop times out. */
}

/* Answer from cache, following cached CNAMEs.  Returns 1 if the query
 * was completed (p is then gone), 0 if it still needs the network. */
static int resolve_from_cache(struct pending *p) {
    for (;;) {
        struct cache_entry *e = cache_lookup(CUR(p), p->qtype);
        if (e) {
            if (e->neg == NEG_NXDOMAIN)
                finish(p, DNS_RCODE_NXDOMAIN, NULL, 0, 0);
            else
                finish(p, DNS_RCODE_NOERROR, e->rrs, e->rr_count, cache_ttl_left(e));
            return 1;
        }
        struct cache_entry *c = cache_lookup(CUR(p), DNS_TYPE_CNAME);
        if (!c || c->rr_count == 0) return 0;
        if (p->chain_len >= MAX_CNAME_CHAIN) { fail(p); return 1; }
        p->chain_ttl[p->chain_len] = cache_ttl_left(c);
        p->chain_len++;
        snprintf(CUR(p), sizeof(p->chain[0]), "%.255s", (const char *)c->rrs[0].rdata);
    }
}

static void start_from_root(struct pending *p) {
    p->zone[0]  = '\0';
    p->ns_count = p->ns_next = p->gl_count = p->gl_next = 0;
    int first = rand16() % NUM_ROOTS;
    for (int i = 0; i < NUM_ROOTS; i++) {
        uint8_t ip[4];
        inet_pton(AF_INET, ROOT_SERVERS[(first + i) % NUM_ROOTS], ip);
        add_ns(p, ip);
    }
    try_next_ns(p);
}

/* Resolve the address of a glueless nameserver with a child query. */
static int spawn_child(struct pending *p, const char *ns_name) {
    if (p->depth >= MAX_CHILD_DEPTH) return -1;
    /* Refuse a lookup already running further up (delegation loop). */
    for (struct pending *a = p; a; a = a->parent >= 0 ? &pending[a->parent] : NULL)
        if (a->qtype == DNS_TYPE_A && dns_name_eq(CUR(a), ns_name)) return -1;

    int ci = pending_alloc();
    if (ci < 0) return -1;
    struct pending *c = &pending[ci];
    c->depth       = p->depth + 1;
    c->parent      = (int)(p - pending);
    c->qtype       = DNS_TYPE_A;
    c->deadline_ms = p->deadline_ms;
    snprintf(c->chain[0], sizeof(c->chain[0]), "%s", ns_name);

    p->state = P_WAIT_CHILD;
    p->child = ci;
    if (!resolve_from_cache(c))
        start_from_root(c);
    return 0;
}

/* Send to the next untried nameserver of the current zone; once those
 * run out, look up the next glueless nameserver.  Returns -1 when
 * nothing is left to try. */
static int try_next_ns(struct pending *p) {
    if (p->ns_next < p->ns_count) {
        send_query(p, &p->ns[p->ns_next++]);
        return 0;
    }
    while (p->gl_next < p->gl_count)
        if (spawn_child(p, p->glueless[p->gl_next++]) == 0)
            return 0;
    return -1;
}

static void notify_parent(int pi, int ci, int ok,
                          const struct cached_rr *rrs, int n) {
    if (pi < 0) return;
    struct pending *p = &pending[pi];
    if (p->state != P_WAIT_CHILD || p->child != ci) return;   /* gave up */
    p->state = P_BUSY;
    p->child = -1;
    if (ok) {
        p->ns_count = p->ns_next = 0;
        for (int i = 0; i < n; i++)
            if (rrs[i].type == DNS_TYPE_A && rrs[i].rdlength == 4)
                add_ns(p, rrs[i].rdata);
    }
    if (try_next_ns(p) < 0) fail(p);
}

/* Negative-cache TTL from the SOA in the authority section (RFC 2308):
 * min(SOA record TTL, SOA MINIMUM field). */
static uint32_t neg_ttl(const struct parsed_response *r) {
    for (int i = 0; i < r->ns_count; i++) {
        const struct parsed_rr *a = &r->authority[i];
        if (a->type != DNS_TYPE_SOA || a->rdlength < 22) continue;
        const uint8_t *m = a->rdata + a->rdlength - 4;
        uint32_t minimum = ((uint32_t)m[0] << 24) | ((uint32_t)m[1] << 16) |
                           ((uint32_t)m[2] << 8)  |  (uint32_t)m[3];
        uint32_t t = a->ttl < minimum ? a->ttl : minimum;
        return t > NEG_TTL_CAP ? NEG_TTL_CAP : t;
    }
    return NEG_TTL_DEFAULT;
}

static void handle_referral(struct pending *p, const struct parsed_response *r) {
    char zone[256] = "";
    int  have_zone = 0;
    for (int i = 0; i < r->ns_count; i++)
        if (r->authority[i].type == DNS_TYPE_NS) {
            snprintf(zone, sizeof(zone), "%s", r->authority[i].name);
            have_zone = 1;
            break;
        }

    /* A useful referral moves strictly down the tree toward our name. */
    if (!have_zone || !in_zone(CUR(p), zone) || !in_zone(zone, p->zone) ||
        strlen(zone) <= strlen(p->zone) || ++p->referrals > MAX_REFERRALS) {
        if (try_next_ns(p) < 0) fail(p);
        return;
    }

    p->ns_count = p->ns_next = p->gl_count = p->gl_next = 0;
    for (int i = 0; i < r->ns_count; i++) {
        const struct parsed_rr *ns = &r->authority[i];
        if (ns->type != DNS_TYPE_NS || !dns_name_eq(ns->name, zone) ||
            !ns->rdata_name[0])
            continue;

        int found = 0;
        for (int j = 0; j < r->ar_count; j++) {            /* glue */
            const struct parsed_rr *g = &r->additional[j];
            if (g->type != DNS_TYPE_A || g->rdlength != 4 ||
                !dns_name_eq(g->name, ns->rdata_name))
                continue;
            add_ns(p, g->rdata);
            found = 1;
            if (in_zone(ns->rdata_name, zone)) {          /* in-bailiwick only */
                struct cached_rr glue = { .type = DNS_TYPE_A, .rdlength = 4 };
                memcpy(glue.rdata, g->rdata, 4);
                cache_put(ns->rdata_name, DNS_TYPE_A, &glue, 1, g->ttl, NEG_NONE);
            }
        }
        if (!found) {                                      /* cached address? */
            struct cache_entry *e = cache_lookup(ns->rdata_name, DNS_TYPE_A);
            if (e && e->neg == NEG_NONE)
                for (int k = 0; k < e->rr_count; k++)
                    if (e->rrs[k].type == DNS_TYPE_A && e->rrs[k].rdlength == 4) {
                        add_ns(p, e->rrs[k].rdata);
                        found = 1;
                    }
        }
        if (!found && p->gl_count < MAX_GLUELESS)          /* resolve later */
            snprintf(p->glueless[p->gl_count++], sizeof(p->glueless[0]),
                     "%s", ns->rdata_name);
    }

    snprintf(p->zone, sizeof(p->zone), "%s", zone);
    if (try_next_ns(p) < 0) fail(p);
}

static void handle_response(struct pending *p, const struct parsed_response *r) {
    if (r->rcode == DNS_RCODE_NXDOMAIN) {
        cache_put(CUR(p), p->qtype, NULL, 0, neg_ttl(r), NEG_NXDOMAIN);
        finish(p, DNS_RCODE_NXDOMAIN, NULL, 0, 0);
        return;
    }
    if (r->rcode != DNS_RCODE_NOERROR) {                   /* SERVFAIL, REFUSED… */
        if (try_next_ns(p) < 0) fail(p);
        return;
    }

    /* 1. The answer, following any CNAME chain inside this response. */
    int moved = 0;
    for (int hop = 0; hop <= MAX_CNAME_CHAIN; hop++) {
        struct cached_rr rrs[MAX_CACHED_RRS];
        int      n   = 0;
        uint32_t ttl = TTL_CAP;
        uint16_t want_len = p->qtype == DNS_TYPE_A ? 4 : 16;

        for (int i = 0; i < r->an_count && n < MAX_CACHED_RRS; i++) {
            const struct parsed_rr *rr = &r->answers[i];
            if (rr->type != p->qtype || rr->cls != DNS_CLASS_IN ||
                rr->rdlength != want_len || !dns_name_eq(rr->name, CUR(p)))
                continue;
            rrs[n].type     = rr->type;
            rrs[n].rdlength = rr->rdlength;
            memcpy(rrs[n].rdata, rr->rdata, rr->rdlength);
            n++;
            if (rr->ttl < ttl) ttl = rr->ttl;
        }
        if (n > 0) {
            cache_put(CUR(p), p->qtype, rrs, n, ttl, NEG_NONE);
            finish(p, DNS_RCODE_NOERROR, rrs, n, ttl);
            return;
        }

        const struct parsed_rr *cn = NULL;
        for (int i = 0; i < r->an_count; i++)
            if (r->answers[i].type == DNS_TYPE_CNAME &&
                r->answers[i].rdata_name[0] &&
                dns_name_eq(r->answers[i].name, CUR(p))) {
                cn = &r->answers[i];
                break;
            }
        if (!cn) break;
        if (p->chain_len >= MAX_CNAME_CHAIN) { fail(p); return; }

        struct cached_rr c = { .type = DNS_TYPE_CNAME };
        size_t tl = strlen(cn->rdata_name) + 1;
        memcpy(c.rdata, cn->rdata_name, tl);
        c.rdlength = (uint16_t)tl;
        cache_put(CUR(p), DNS_TYPE_CNAME, &c, 1, cn->ttl, NEG_NONE);

        p->chain_ttl[p->chain_len] = cn->ttl;
        p->chain_len++;
        snprintf(CUR(p), sizeof(p->chain[0]), "%s", cn->rdata_name);
        moved = 1;
    }
    if (moved) {
        /* CNAME target not answered here: continue from cache or root. */
        if (resolve_from_cache(p)) return;
        p->referrals = 0;
        start_from_root(p);
        return;
    }

    /* 2. No answer: NODATA, or a referral further down. */
    int has_ns = 0, has_soa = 0;
    for (int i = 0; i < r->ns_count; i++) {
        if (r->authority[i].type == DNS_TYPE_NS)  has_ns  = 1;
        if (r->authority[i].type == DNS_TYPE_SOA) has_soa = 1;
    }
    if (r->aa || (has_soa && !has_ns)) {
        cache_put(CUR(p), p->qtype, NULL, 0, neg_ttl(r), NEG_NODATA);
        finish(p, DNS_RCODE_NOERROR, NULL, 0, 0);
        return;
    }
    if (has_ns) { handle_referral(p, r); return; }
    if (try_next_ns(p) < 0) fail(p);
}

/* ================================================================
 * PUBLIC API
 * ================================================================ */
int resolver_init(int local, resolver_reply_fn reply) {
    local_mode = local;
    reply_cb   = reply;
    if (local_mode) return -1;

    /* Never bound: the kernel picks an ephemeral source port, so replies
     * (dst port != 53) are passed by the XDP program to this socket. */
    upstream_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (upstream_fd < 0) { perror("socket(upstream)"); exit(1); }
    return upstream_fd;
}

void resolver_handle_query(const uint8_t *q, int qlen,
                           const void *ctx, int ctx_len) {
    char     qname[256];
    uint16_t qtype, txid;
    uint8_t  buf[DNS_BUF_SIZE];
    int      len;

    if (!dns_validate_query(q, qlen, qname, sizeof(qname), &qtype, &txid))
        return;

    if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
        len = dns_build_error(buf, sizeof(buf), txid, qname, qtype, DNS_RCODE_NOTIMP);
        if (len > 0) reply_cb(ctx, ctx_len, buf, len);
        return;
    }

    if (local_mode) {
        struct cached_rr ans[MAX_CACHED_RRS];
        int     an = 0;
        uint8_t rcode = DNS_RCODE_NOERROR;
        if (dns_local_lookup(qname, qtype, ans, &an) < 0) {
            rcode = DNS_RCODE_NXDOMAIN;
            an = 0;
        }
        len = dns_build_response(buf, sizeof(buf), txid, qname, qtype, rcode, ans, an);
        if (len > 0) reply_cb(ctx, ctx_len, buf, len);
        return;
    }

    int i = ctx_len <= RESOLVER_CLIENT_CTX_MAX ? pending_alloc() : -1;
    if (i < 0) {
        len = dns_build_error(buf, sizeof(buf), txid, qname, qtype, DNS_RCODE_SERVFAIL);
        if (len > 0) reply_cb(ctx, ctx_len, buf, len);
        return;
    }
    struct pending *p = &pending[i];
    p->client_txid = txid;
    p->qtype       = qtype;
    p->ctx_len     = ctx_len;
    memcpy(p->ctx, ctx, ctx_len);
    snprintf(p->chain[0], sizeof(p->chain[0]), "%s", qname);
    p->deadline_ms = now_ms() + QUERY_TIMEOUT_MS;

    if (!resolve_from_cache(p))
        start_from_root(p);
}

void resolver_handle_upstream(void) {
    static struct parsed_response r;        /* ~50 KB: keep it off the stack */
    uint8_t buf[DNS_BUF_SIZE];

    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t len = recvfrom(upstream_fd, buf, sizeof(buf), 0,
                               (struct sockaddr *)&from, &fl);
        if (len < 0) return;                /* EAGAIN: drained */
        if (len < DNS_HDR_SIZE || !(buf[2] & 0x80) || from.sin_port != htons(53))
            continue;

        uint16_t txid = (uint16_t)((buf[0] << 8) | buf[1]);
        struct pending *p = pending_find(txid, from.sin_addr.s_addr);
        if (!p) continue;

        if (dns_parse_response(buf, (int)len, &r) < 0) {
            if (try_next_ns(p) < 0) fail(p);    /* malformed: next server */
            continue;
        }
        if (r.qtype != p->qtype || !dns_name_eq(r.qname, CUR(p)))
            continue;                           /* not our question: ignore */

        handle_response(p, &r);
    }
}

void resolver_tick(void) {
    static uint64_t last;
    uint64_t now = now_ms();
    if (now - last < TICK_INTERVAL_MS) return;
    last = now;

    for (int i = 0; i < MAX_PENDING; i++) {
        struct pending *p = &pending[i];
        if (p->state != P_WAIT_NS && p->state != P_WAIT_CHILD) continue;

        if (now >= p->deadline_ms) {
            if (p->depth > 0) {                 /* its client query expires too */
                p->state = P_FREE;
                continue;
            }
            if (p->state == P_WAIT_CHILD && p->child >= 0)
                pending[p->child].state = P_FREE;
            fail(p);
            continue;
        }
        if (p->state == P_WAIT_NS && now >= p->hop_deadline_ms)
            if (try_next_ns(p) < 0) fail(p);
    }
}
