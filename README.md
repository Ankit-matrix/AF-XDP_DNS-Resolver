# DNS Resolver using AF_XDP

CS331 Computer Networks team project. A recursive DNS resolver benchmarked
two ways: over a normal UDP socket, and over an AF_XDP (XSK) socket with an
XDP program redirecting port-53 traffic straight to userspace.

## Files

| File | Purpose |
|---|---|
| `dns.h` / `dns.c` | Shared DNS logic: parsing, response building, local zone. Used by both resolvers — this is what keeps the benchmark fair. |
| `socket_resolver.c` | Baseline: normal UDP sockets (`recvfrom`/`sendto`). |
| `xdp_kern.c` | XDP program: redirects UDP/53 traffic to the AF_XDP socket via `XSKMAP`, passes everything else. |
| `xsk_rx_test.c` | Minimal AF_XDP receive-only tool — confirms the XDP redirect actually reaches userspace before trusting the full resolver. |
| `afxdp_resolver.c` | The AF_XDP resolver: UMEM/XSK setup, packet crafting, event loop, same `dns.c` as the baseline. |
| `testbed.sh` | Sets up/tears down a veth pair + client network namespace for reproducible benchmarking. |
| `payload.txt` | `dnsperf` query list generated from the local zone (see `dns.c`'s `local_zone`). |
| `malformed.py` | Robustness test: 7 malformed packets + 1 valid control query. A correct resolver drops all 7 silently and answers the control query. |
| `recursive_resolver.c` | Superseded by `socket_resolver.c` + `dns.c` — kept temporarily, see note below. |

## Build

```sh
sudo apt install -y clang llvm libbpf-dev libxdp-dev \
                    linux-tools-$(uname -r) build-essential \
                    dnsutils ethtool iproute2

make            # builds socket_resolver, xdp_kern.o, xsk_rx_test, afxdp_resolver
```

Debug builds with ASan/UBSan: `make socket_resolver_asan afxdp_resolver_asan`.

## Running (local-answer mode, for benchmarking)

Local mode answers from a fixed zone defined in `dns.c` instead of walking
the DNS hierarchy, so the benchmark measures transport overhead and not
upstream network latency.

```sh
# Baseline
sudo ./socket_resolver --local

# AF_XDP — generic (SKB) mode, works on any NIC/veth
sudo ./afxdp_resolver --local --skb <interface>

# AF_XDP — native (driver) mode, needs driver XDP support
sudo ./afxdp_resolver --local --drv <interface>
```

Test queries:

```sh
dig @127.0.0.1 -p 53 google.com A +short
python3 malformed.py 127.0.0.1 53
```

## Test network

```sh
sudo ./testbed.sh setup      # veth pair + "dnstest" namespace
sudo ip netns exec dnstest dig @10.0.0.1 -p 53 google.com A
sudo ./testbed.sh teardown
```

## AF_XDP attach mode and hardware

`afxdp_resolver` requires an explicit `--skb` or `--drv` flag — there is no
default, because "generic XDP" was silently wrong on veth in an earlier
version of this file (veth gave native-equivalent behavior with flags=0).

Zero-copy AF_XDP needs driver support that consumer/laptop NICs (Intel
`e1000e`/I219-series, Wi-Fi chipsets) don't have — only `i40e`, `ice`,
`ixgbe`, and Mellanox `mlx5_core` support it. On hardware without that
support, this project runs in copy mode (`XDP_COPY`), which still skips
socket-layer overhead but not the UMEM copy. Benchmarks note which NIC and
which mode (`--skb`/`--drv`) produced each result.

## Status

- [x] Baseline resolver (local + recursive mode), shared `dns.c`
- [x] XDP redirect program, AF_XDP RX confirmed via `xsk_rx_test`
- [x] AF_XDP resolver (local mode)
- [ ] Benchmark scripts (`bench.sh`, `analyze.py`)
- [ ] AF_XDP recursive mode (hybrid: AF_XDP client path + UDP socket upstream)
