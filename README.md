# DNS Resolver using AF_XDP

CS331 Computer Networks project. A recursive DNS resolver whose client-facing
packet path is implemented twice — over a standard UDP socket and over an
AF_XDP (XSK) socket — so that the two I/O paths can be compared on latency,
throughput and CPU cost with otherwise identical DNS logic.

## Architecture

```
 client (RD=1) ──► NIC driver ──► XDP hook: xdp_kern.o
                                   │
             UDP dst port 53 ──────┴────── everything else (ARP, upstream replies, …)
             redirect via XSKMAP            XDP_PASS
                    │                             │
             AF_XDP socket (UMEM, rings)    Linux network stack ──► UDP socket
             afxdp_resolver                 socket_resolver
                    └──────────────┬──────────────┘
                                   ▼
               resolver.c — shared iterative engine (cache, referrals, CNAME, glue)
                                   │  cache miss
                                   ▼
               iterative queries (RD=0) on an ordinary UDP socket:
               root ──► TLD ──► authoritative
                                   │
               answer returned on the path the query arrived on
```

- **Policy** — `xdp_kern.c` decides per packet, in the driver, which traffic takes
  the AF_XDP path. Everything else, including replies from upstream servers
  (which arrive on an ephemeral port), continues through the kernel stack.
- **Resolution** — the client sends a recursive query; the resolver itself
  walks the hierarchy from the root servers. It never forwards to another resolver.
- **Fairness** — both binaries link the same `resolver.c` and `dns.c`; they
  differ only in client-side I/O (~100 lines each).

| Layer | Files | Responsibility |
|---|---|---|
| Wire format | `dns.c`, `dns.h` | Parse/build DNS messages, name compression, query validation, `--local` zone |
| Resolution | `resolver.c`, `resolver.h` | Iterative resolution, TTL cache, NXDOMAIN/NODATA, glueless delegations, timeouts |
| Client I/O | `socket_resolver.c` | `recvfrom` / `sendto` |
| | `afxdp_resolver.c` | UMEM, FILL/RX/TX/COMPLETION rings, Ethernet/IPv4/UDP frame construction |
| Packet steering | `xdp_kern.c` | XDP program: UDP/53 → XSKMAP, all else → stack |

## Repository layout

```
src/                      source code and Makefile (build and run from here)
  xsk_rx_test.c           AF_XDP receive-only check
  malformed.py            robustness test (7 malformed queries + 1 control)
local_offline_testing/    offline integration tests
  testbed.sh              veth pair + client namespace "dnstest" (10.0.0.2 → 10.0.0.1)
  mock_net.sh             starts/stops the mock DNS hierarchy
  mock_dns.py             mock root, TLD and authoritative servers
  test_matrix.sh          23 functional checks against a running resolver
  payload_recursive_mock.txt   5,000-query recursive load (mock only)
results_/                 benchmark data, summaries and diagnostics (see results_/README.md)
  payload_load.txt        dnsperf query list for --local benchmarks
```

## Build

```sh
sudo apt install -y clang llvm build-essential libbpf-dev libxdp-dev xdp-tools \
                    linux-tools-$(uname -r) dnsutils dnsperf sysstat ethtool \
                    iproute2 python3-dnspython
cd src
make                                      # socket_resolver, afxdp_resolver, xdp_kern.o, xsk_rx_test
make socket_resolver_asan afxdp_resolver_asan    # ASan/UBSan builds
```

## Running

Run from `src/`: `afxdp_resolver` loads `xdp_kern.o` from the working directory.

```sh
sudo ./socket_resolver [--local]
sudo ./afxdp_resolver <interface> [--local] [--skb | --drv]
```

| Option | Meaning |
|---|---|
| *(none)* | Recursive resolver (iterative resolution from the root servers) |
| `--local` | Answer A/AAAA from the built-in zone only; used for benchmarking |
| `--skb` / `--drv` | Force generic / native XDP; without either, the kernel chooses |

Both listen on UDP port 53. If `systemd-resolved` blocks the bind, set
`DNSStubListener=no`.

## Testing

All commands from `local_offline_testing/` unless noted; the resolver runs in a
second terminal from `src/`.

**1. Test network and mock DNS hierarchy**

```sh
sudo ./testbed.sh setup
sudo ./mock_net.sh up          # mock servers on the real root/TLD addresses
```

**2. AF_XDP receive path** (from `src/`, no resolver running)

```sh
sudo ./xsk_rx_test veth-dns
sudo ip netns exec dnstest dig @10.0.0.1 example.com A      # appears in xsk_rx_test
sudo ip netns exec dnstest dig @10.0.0.1 -p 5300 example.com # does not
```

**3. Functional matrix** — CNAME chains, NODATA, NXDOMAIN, glueless delegation,
delegation loop, timeout, cache

```sh
sudo ./afxdp_resolver veth-dns --skb      # terminal 2, from src/ (or ./socket_resolver)
sudo ./test_matrix.sh                     # expected: 23 passed, 0 failed
```

**4. Recursive load** — 5,000 queries, 4,000 of them uncached

```sh
sudo ip netns exec dnstest dnsperf -s 10.0.0.1 -d payload_recursive_mock.txt -n 1 -Q 1000 -c 8
# expected: 5000 completed, 0 lost, NOERROR 1000, NXDOMAIN 4000
```

**5. Malformed input** (from `src/`)

```sh
sudo ip netns exec dnstest python3 malformed.py 10.0.0.1 53   # 7 dropped, control answered
```

**Teardown**

```sh
sudo ./mock_net.sh down && sudo ./testbed.sh teardown
```

## Benchmarking

Resolvers run in `--local` mode so that only the I/O path is measured. Resolver
pinned to CPU 2; dnsperf on CPUs outside that physical core.

```sh
sudo taskset -c 2 ./afxdp_resolver veth-dns --local --skb         # from src/
sudo ip netns exec dnstest taskset -c 0,1,3,4,5,7 dnsperf -s 10.0.0.1 \
     -d ../results_/payload_load.txt -l 30 -c 8 -Q 2000000         # maximum throughput
sudo ip netns exec dnstest taskset -c 0,1,3,4,5,7 dnsperf -s 10.0.0.1 \
     -d ../results_/payload_load.txt -l 30 -c 8 -Q 150000          # latency at equal load
pidstat -u -p $(pgrep -x afxdp_resolver) 5 5                       # resolver CPU during a run
```

## Results

| Configuration | Socket QPS | AF_XDP QPS | CPU per query, equal load (socket → AF_XDP) |
|---|---|---|---|
| veth, generic XDP | 310.3k | 527.2k (1.70×) | 4.65 → 3.99 µs (−14%) |
| veth, native XDP | 310.3k | 490.6k (1.58×) | 4.65 → 3.97 µs (−15%) |
| Intel I219-LM, generic XDP | 358.4k | 373.2k* | 2.36 → 1.03 µs (−56%) |

\* Limited by the client's NIC transmit queue, not by either resolver.
Method, raw data and analysis: [`results_/README.md`](results_/README.md).

## Limitations

- AF_XDP in copy mode only; zero-copy needs a ZC-capable NIC (`i40e`, `ice`, `mlx5`).
- Single RX queue (queue 0); IPv4 only.
- Reply MAC addresses are the query's swapped, so clients must share the L2 segment.
- No EDNS0 or any TCP fallback 
