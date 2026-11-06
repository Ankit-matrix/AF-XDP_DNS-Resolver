#!/usr/bin/env bash
# mock_net.sh — put the mock DNS hierarchy (mock_dns.py) on the real root/TLD
# server addresses, inside network namespace "inet", and route the host's
# queries for those /32s into it.  While it is up, the resolver's iterative
# queries go to the mock instead of the Internet; nothing else is affected.
#
#   sudo ./mock_net.sh up       # create namespace, routes, start mock_dns.py
#   sudo ./mock_net.sh down     # stop it and remove everything
set -euo pipefail
cd "$(dirname "$0")"

ADDRS="198.41.0.4 170.247.170.2 192.33.4.12 199.7.91.13 192.203.230.10 192.5.5.241
       192.112.36.4 198.97.190.53 192.36.148.17 192.58.128.30 193.0.14.129 199.7.83.42
       202.12.27.33 192.5.6.30 216.239.32.10 198.51.44.8 203.0.113.53 198.51.100.99"

up() {
    ip netns add inet
    ip link add veth-up type veth peer name veth-inet
    ip link set veth-inet netns inet
    ip addr add 172.31.0.1/24 dev veth-up
    ip link set veth-up up
    ip netns exec inet ip addr add 172.31.0.2/24 dev veth-inet
    ip netns exec inet ip link set veth-inet up
    ip netns exec inet ip link set lo up
    ip netns exec inet ip route add default via 172.31.0.1
    for a in $ADDRS; do
        ip netns exec inet ip addr add "$a/32" dev lo
        ip route add "$a/32" via 172.31.0.2
    done
    ip netns exec inet python3 -I mock_dns.py > mock_dns.log 2>&1 &
    sleep 1
    head -1 mock_dns.log
    echo "mock hierarchy up (log: mock_dns.log)"
}

down() {
    pkill -f mock_dns.py 2>/dev/null || true
    for a in $ADDRS; do ip route del "$a/32" 2>/dev/null || true; done
    ip link del veth-up 2>/dev/null || true
    ip netns del inet 2>/dev/null || true
    echo "mock hierarchy removed"
}

case "${1:-}" in
    up)   up ;;
    down) down ;;
    *)    echo "Usage: $0 {up|down}"; exit 1 ;;
esac
