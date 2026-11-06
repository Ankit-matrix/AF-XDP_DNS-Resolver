#!/usr/bin/env bash
# test_matrix.sh — functional check of a running resolver against mock_dns.py
# Usage: sudo ./test_matrix.sh [server-ip]      (default 10.0.0.1, queried from netns dnstest)
SERVER=${1:-10.0.0.1}
pass=0; fail=0

# name type expected-status expected-answer-regex (empty = no answer lines)
CASES=(
  "google.com A NOERROR 142.250.183.14"
  "google.com AAAA NOERROR 2404:6800:4009:82a::200e"
  "www.google.com A NOERROR google.com\.\s+[0-9]+\s+IN\s+A\s+142.250.183.14"
  "www.github.com A NOERROR github.com\.\s+[0-9]+\s+IN\s+A\s+140.82.121.3"
  "mail.google.com A NOERROR github.com\.\s+[0-9]+\s+IN\s+A\s+140.82.121.3"
  "github.com AAAA NOERROR -"
  "nope.google.com A NXDOMAIN -"
  "doesnotexist.com A NXDOMAIN -"
  "www.glueless.com A NOERROR 198.18.0.1"
  "www.selfloop.com A SERVFAIL -"
  "google.com TXT NOTIMP -"
)

run() {   # name type status regex label
  local out st ans t
  out=$(ip netns exec dnstest dig @"$SERVER" +tries=1 +time=8 "$1" "$2" 2>&1)
  st=$(grep -oP 'status: \K[A-Z]+' <<<"$out")
  ans=$(sed -n '/ANSWER SECTION/,/^$/p' <<<"$out" | grep -v '^;' | grep -v '^$')
  t=$(grep -oP 'Query time: \K[0-9]+' <<<"$out")
  local ok=1
  [ "$st" = "$3" ] || ok=0
  if [ "$4" = "-" ]; then [ -z "$ans" ] || ok=0
  else grep -qP "$4" <<<"$ans" || ok=0; fi
  grep -q 'mismatch' <<<"$out" && ok=0
  if [ $ok = 1 ]; then pass=$((pass+1)); r=PASS; else fail=$((fail+1)); r=FAIL; fi
  printf '%-4s %-6s %-18s %-5s -> %-8s %5s ms  %s\n' "$r" "$5" "$1" "$2" "${st:-none}" "${t:-?}" \
         "$(tr '\n' ' ' <<<"$ans" | tr -s ' \t' ' ' | cut -c1-90)"
}

for c in "${CASES[@]}"; do set -- $c; run "$1" "$2" "$3" "$4" cold; done
for c in "${CASES[@]}"; do set -- $c; run "$1" "$2" "$3" "$4" cached; done
set -- www.dead.com A SERVFAIL -; run "$1" "$2" "$3" "$4" timeout

echo "== $pass passed, $fail failed"
