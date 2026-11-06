#!/usr/bin/env python3
"""
malformed.py — Robustness test: malformed DNS packets + one valid control query

Sends 7 deliberately malformed UDP payloads to the resolver, then one
well-formed query as a control to confirm the resolver is still alive
and answering correctly after the malformed packets.  A resolver that
is parsing the DNS wire format safely should silently drop every
malformed packet (no crash, no reply, no hang) and answer the control
query normally.

Usage:
    python3 malformed.py [host] [port]
    python3 malformed.py 127.0.0.1 53
"""

import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 53
TIMEOUT = 1.0

# Each entry: (description, raw bytes to send)
MALFORMED_PACKETS = [
    ("empty packet", b""),
    ("truncated header (1 byte)", b"\x12"),
    ("header only, no question (12 bytes)",
     b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
    ("qdcount=1 but no question bytes follow",
     b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
    ("label length overruns packet",
     b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x3f" + b"A" * 10),
    ("compression pointer loop (points to itself)",
     b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c\x00\x01\x00\x01"),
    ("oversized qdcount (claims 500 questions, none present)",
     b"\x12\x34\x01\x00\x01\xf4\x00\x00\x00\x00\x00\x00"),
    ("garbage / random bytes (20 bytes)",
     bytes(range(20))),
]

# Valid control query: TXID 0x1234, flags 0x0100 (standard query, RD=1),
# QDCOUNT=1, question = google.com A IN
CONTROL_QUERY = (
    b"\x12\x34"          # TXID
    b"\x01\x00"          # flags: standard query, RD=1
    b"\x00\x01"          # QDCOUNT=1
    b"\x00\x00"          # ANCOUNT=0
    b"\x00\x00"          # NSCOUNT=0
    b"\x00\x00"          # ARCOUNT=0
    b"\x06google\x03com\x00"  # QNAME: google.com
    b"\x00\x01"          # QTYPE=A
    b"\x00\x01"          # QCLASS=IN
)


def send_and_check(sock, desc, payload, expect_reply):
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(payload, (HOST, PORT))
    except OSError as e:
        print(f"[FAIL] {desc}: send() raised {e}")
        return False

    try:
        data, _ = sock.recvfrom(4096)
        if expect_reply:
            print(f"[ OK ] {desc}: got {len(data)}-byte reply (expected)")
            return True
        else:
            print(f"[FAIL] {desc}: resolver replied to malformed input "
                  f"({len(data)} bytes) — should have silently dropped it")
            return False
    except socket.timeout:
        if expect_reply:
            print(f"[FAIL] {desc}: no reply (expected one for the control query)")
            return False
        else:
            print(f"[ OK ] {desc}: dropped (no reply, as expected)")
            return True


def main():
    print(f"Target: {HOST}:{PORT}  (timeout={TIMEOUT}s per packet)\n")

    passed = 0
    total = len(MALFORMED_PACKETS) + 1

    for desc, payload in MALFORMED_PACKETS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if send_and_check(sock, desc, payload, expect_reply=False):
            passed += 1
        sock.close()
        time.sleep(0.05)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if send_and_check(sock, "control query (google.com A)", CONTROL_QUERY,
                      expect_reply=True):
        passed += 1
    sock.close()

    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
