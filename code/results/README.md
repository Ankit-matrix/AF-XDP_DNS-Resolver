# Benchmark results

Comparison of `socket_resolver` and `afxdp_resolver` with identical DNS logic.
All runs use `--local` mode and `payload_load.txt`, so that only the client I/O
path is measured. AF_XDP always runs in copy mode (`XDP_COPY`).

## Method

| Parameter | Value |
|---|---|
| Resolver host | Dell Latitude 5420, 8 logical CPUs, Ubuntu, kernel 7.0, `performance` governor |
| CPU placement | Resolver on CPU 2; load generator on CPUs outside that physical core |
| Throughput | 5 runs × 30 s, dnsperf `-c 8 -Q 2000000` |
| Latency | 3 runs × 30 s at a fixed 150k QPS |
| CPU | `pidstat` (resolver process), `mpstat` (whole machine) |
| Exclusion rule | Runs with lost queries are excluded from the tables |

| Configuration | Interface | Client | XDP mode |
|---|---|---|---|
| `veth/socket` | veth testbed | dnsperf in namespace, same host | — |
| `veth/afxdp_generic` | veth testbed | dnsperf in namespace, same host | generic (`--skb`) |
| `veth/afxdp_native` | veth testbed | dnsperf in namespace, same host | native (`--drv`) |
| `i219(nic)/final/socket` | Intel I219-LM (`e1000e`), 1 GbE cable | Arch Linux host, Realtek `r8169` | — |
| `i219(nic)/final/afxdp_generic` | Intel I219-LM (`e1000e`), 1 GbE cable | Arch Linux host, Realtek `r8169` | generic (`--skb`) |

I219 tuning for the final runs: NIC rings 256 → 4096, NIC interrupt moved off the
resolver's physical core. Native XDP is not supported by `e1000e`
(`diagnostics/i219_native_xdp_unsupported.txt`).

```sh
sudo ethtool -G enp0s31f6 rx 4096 tx 4096
for i in $(grep enp0s31f6 /proc/interrupts | cut -d: -f1); do echo 1 | sudo tee /proc/irq/$i/smp_affinity_list; done
```

## Results

**Maximum throughput**

| Configuration | QPS (mean ± s.d.) | vs socket | Resolver CPU | CPU per query |
|---|---|---|---|---|
| veth, socket | 310.3k ± 2.6k | 1.00× | 99.3% | 3.20 µs |
| veth, AF_XDP generic | 527.2k ± 13.9k | 1.70× | 99.3% | 1.88 µs |
| veth, AF_XDP native | 490.6k ± 3.4k | 1.58× | 98.9% | 2.02 µs |
| I219, socket | 358.4k ± 22.1k | 1.00× | 84.8% | 2.38 µs |
| I219, AF_XDP generic | 373.2k ± 0.8k | 1.04× | 37.4% | 1.00 µs |

**Equal load (150k QPS)**

| Configuration | Avg latency | Resolver CPU | CPU per query | Whole machine |
|---|---|---|---|---|
| veth, socket | 11.0 µs | 69.7% | 4.65 µs | 2.36 cores |
| veth, AF_XDP generic | 10.3 µs | 59.9% | 3.99 µs | 2.54 cores |
| veth, AF_XDP native | 9.0 µs | 59.6% | 3.97 µs | 2.47 cores |
| I219, socket | 119 µs | 35.4% | 2.36 µs | 1.28 cores |
| I219, AF_XDP generic | 122 µs | 15.4% | 1.03 µs | 1.03 cores |

## Observations

1. On veth, AF_XDP delivers 1.58–1.70× the throughput of the socket path on one core.
2. On the I219-LM, AF_XDP reduces resolver CPU per query by 56–58% and whole-machine
   CPU by about 19% at equal load.
3. I219 throughput saturates at ~375k QPS for both resolvers. The client's qdisc
   requeue counter rises in every run (`run*_client_qdisc.txt`), placing the limit
   in the client NIC's transmit path; the resolver host was not saturated.
4. Generic XDP outperformed native XDP on veth, consistent with veth packets
   already being SKBs when they reach the XDP hook.
5. The socket baseline spends ~90% of its CPU time in the kernel (`sys`).
6. At equal load, latency differs little; at saturation, latency mainly reflects queueing.

Excluded runs: `i219(nic)/final/socket/throughput/run1`,
`i219(nic)/final/afxdp_generic/throughput/run4` (both lost queries).

## Layout

```
veth/{socket,afxdp_generic,afxdp_native}/
i219(nic)/final/{socket,afxdp_generic}/
i219(nic)/pre_modification/{socket,afxdp_generic}/   superseded: before NIC tuning;
                                                     socket CPU not captured
summaries/      veth.txt, i219_final.txt, i219_pre_tuning_superseded.txt (one line per run)
diagnostics/    native-XDP attach failure; per-core CPU during the bottleneck search
payload_load.txt    dnsperf query list used for every run
```

Each configuration folder contains:

| File | Content |
|---|---|
| `info.txt` | Resolver PID and XDP mode at the start of the run |
| `throughput/runN_dnsperf.txt` | dnsperf output, maximum load |
| `throughput/runN_resolver_cpu.txt` | `pidstat` of the resolver |
| `throughput/runN_server_percpu.txt` | Per-core CPU on the resolver host (I219 final) |
| `throughput/runN_client_cpu.txt` | CPU on the client host (I219) |
| `throughput/runN_client_qdisc.txt` | Client `tc -s qdisc` and `softnet_stat` (I219 final) |
| `latency_150k/runN_dnsperf.txt` | dnsperf output at 150k QPS |
| `latency_150k/runN_resolver_cpu.txt` | `pidstat` of the resolver |
| `latency_150k/runN_system_cpu.txt` | Whole-machine `mpstat` |
