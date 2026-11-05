# Makefile — AF_XDP DNS Resolver project
#
# Targets:
#   socket_resolver   — baseline resolver (normal UDP sockets)
#   xdp_kern.o        — BPF object (XDP redirect program)
#   xsk_rx_test       — AF_XDP receive-only test tool
#   afxdp_resolver    — AF_XDP resolver (local mode)
#
# Prerequisites:
#   sudo apt install -y clang llvm libbpf-dev libxdp-dev \
#                       linux-tools-$(uname -r) build-essential \
#                       dnsutils ethtool iproute2

CC       = gcc
CLANG    = clang
CFLAGS   = -O3 -Wall -Wextra
LDFLAGS  =
UNAME_M  := $(shell uname -m)
# linux/bpf.h -> linux/types.h -> asm/types.h, which clang -target bpf
# doesn't find on its own default include path; point it at the
# multiarch dir gcc/the distro headers normally live in.
BPF_CFLAGS = -O2 -g -target bpf -I/usr/include/$(UNAME_M)-linux-gnu

XDP_LIBS = -lxdp -lbpf
# UBSan flags the IP header at byte offset 14 in a packet buffer as
# misaligned; that's expected for raw packet code and harmless on x86,
# so alignment checking is disabled for the sanitizer builds below.
ASAN_FLAGS = -g -O1 -Wall -Wextra -fsanitize=address,undefined \
             -fno-sanitize=alignment

.PHONY: all clean

all: socket_resolver xdp_kern.o xsk_rx_test afxdp_resolver

# --- Baseline resolver (normal sockets) ---
socket_resolver: socket_resolver.c dns.c dns.h
	$(CC) $(CFLAGS) -o $@ socket_resolver.c dns.c $(LDFLAGS)

socket_resolver_asan: socket_resolver.c dns.c dns.h
	$(CC) $(ASAN_FLAGS) -o $@ socket_resolver.c dns.c

# --- XDP BPF program ---
xdp_kern.o: xdp_kern.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# --- AF_XDP receive test ---
xsk_rx_test: xsk_rx_test.c
	$(CC) $(CFLAGS) -o $@ $< $(XDP_LIBS)

# --- AF_XDP resolver ---
afxdp_resolver: afxdp_resolver.c dns.c dns.h
	$(CC) $(CFLAGS) -o $@ afxdp_resolver.c dns.c $(XDP_LIBS)

afxdp_resolver_asan: afxdp_resolver.c dns.c dns.h
	$(CC) $(ASAN_FLAGS) -o $@ afxdp_resolver.c dns.c $(XDP_LIBS)

clean:
	rm -f socket_resolver socket_resolver_asan \
	      afxdp_resolver afxdp_resolver_asan \
	      xdp_kern.o xsk_rx_test
