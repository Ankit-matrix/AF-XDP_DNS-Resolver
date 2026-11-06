# Benchmark results

All runs: resolvers in `--local` mode, resolver pinned to CPU 2, dnsperf
with `payload.txt`. Throughput = 5 runs x 30 s at max load; latency = 3 runs
x 30 s at a fixed 150k QPS. AF_XDP always in copy mode (XDP_COPY).

| Folder | Interface | Resolver | XDP mode |
|---|---|---|---|
| `veth/socket` | veth testbed | socket_resolver | none |
| `veth/afxdp_generic` (config A) | veth testbed | afxdp_resolver | generic (`--skb`) |
| `veth/afxdp_native` (config B) | veth testbed | afxdp_resolver | native (`--drv`) |
| `i219/final/socket` | Intel I219-LM, cable to Arch client | socket_resolver | none |
| `i219/final/afxdp_generic` (config C) | Intel I219-LM, cable to Arch client | afxdp_resolver | generic (`--skb`) |
| `i219/pre_tuning_superseded/*` | I219-LM, default 256-entry rings | both | superseded: socket CPU not captured, leftover XDP program attached |

The final I219 runs used 4096-entry NIC rings and the NIC IRQ moved to CPU 1
(off the resolver's physical core). Throughput there is capped at ~375k QPS
by the client's Realtek NIC (see `run*_client_qdisc.txt`: requeues rise every run).

## Files in each configuration folder

| File | Content |
|---|---|
| `info.txt` | resolver PID and XDP mode at the start of the run |
| `throughput/runN_dnsperf.txt` | dnsperf output at maximum load |
| `throughput/runN_resolver_cpu.txt` | `pidstat` of the resolver process |
| `throughput/runN_server_percpu.txt` | `mpstat -P ALL` on the resolver host (I219 only) |
| `throughput/runN_client_cpu.txt` | `mpstat` on the client machine (I219 only) |
| `throughput/runN_client_qdisc.txt` | client `tc -s qdisc` + `softnet_stat` (I219 final only) |
| `latency_150k/runN_dnsperf.txt` | dnsperf output at a fixed 150k QPS |
| `latency_150k/runN_resolver_cpu.txt` | `pidstat` of the resolver process |
| `latency_150k/runN_system_cpu.txt` | whole-machine `mpstat` |

Runs excluded from the final tables (lost queries during the run):
`i219/final/socket/throughput/run1`, `i219/final/afxdp_generic/throughput/run4`.

## Other folders

- `summaries/` — one line per run, as printed by the summary loop
- `diagnostics/` — native-XDP attach failure on e1000e; per-core CPU during the bottleneck search
