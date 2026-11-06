#!/usr/bin/env python3
# mock_dns.py: a miniature DNS hierarchy (root -> TLD -> authoritative)
# for testing the iterative resolver offline and repeatably.
#
# Every server listens on its real-world address inside a network
# namespace; host routes for those /32s send the resolver's queries here
# instead of the Internet (see TESTING_UBUNTU.md, section 6.2).
# Needs python3-dnspython.
#
# Test names and expected answers:
#   google.com A / AAAA       plain answer                 NOERROR
#   www.google.com A          in-zone CNAME + A            NOERROR, CNAME chain
#   www.github.com A          in-zone CNAME + A            NOERROR, CNAME chain
#   mail.google.com A         cross-zone CNAME -> github   NOERROR, CNAME chain
#   github.com AAAA           name exists, no AAAA         NOERROR, empty (NODATA)
#   nope.google.com A         authoritative NXDOMAIN       NXDOMAIN
#   doesnotexist.com A        NXDOMAIN at the TLD          NXDOMAIN
#   www.glueless.com A        referral without glue        NOERROR (NS resolved first)
#   www.selfloop.com A        glueless NS inside own zone  SERVFAIL (quickly, no hang)
#   www.dead.com A            nameserver never answers     SERVFAIL after timeout
import socket, select, dns.message, dns.rrset, dns.rcode, dns.flags, dns.rdatatype

ROOTS = ["198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
         "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
         "193.0.14.129", "199.7.83.42", "202.12.27.33"]
TLD   = "192.5.6.30"      # serves com. and org.
GOOG  = "216.239.32.10"   # google.com
GH    = "198.51.44.8"     # github.com
ELSE  = "203.0.113.53"    # elsewhere.org and glueless.com
DEAD  = "198.51.100.99"   # has an address, never answers DNS

TLDS = {"com.", "org."}

# Delegations held by the TLD server: zone -> [(ns name, glue IP or None)]
DELEG = {
    "google.com.":    [("ns1.google.com.", GOOG)],
    "github.com.":    [("dns1.p08.nsone.net.", GH)],
    "elsewhere.org.": [("ns1.elsewhere.org.", ELSE)],
    "glueless.com.":  [("ns1.elsewhere.org.", None)],   # glue lives in another TLD
    "selfloop.com.":  [("ns1.selfloop.com.", None)],    # unresolvable on purpose
    "dead.com.":      [("ns1.dead.com.", DEAD)],
}

# Authoritative data: zone -> (server IP, {name: {type: [rdata]}})
ZONES = {
    "google.com.": (GOOG, {
        "google.com.":        {"A": ["142.250.183.14"], "AAAA": ["2404:6800:4009:82a::200e"]},
        "www.google.com.":    {"CNAME": ["google.com."]},
        "mail.google.com.":   {"CNAME": ["github.com."]},
        "ns1.google.com.":    {"A": [GOOG]},
    }),
    "github.com.": (GH, {
        "github.com.":        {"A": ["140.82.121.3"]},
        "www.github.com.":    {"CNAME": ["github.com."]},
    }),
    "elsewhere.org.": (ELSE, {
        "ns1.elsewhere.org.": {"A": [ELSE]},
    }),
    "glueless.com.": (ELSE, {
        "www.glueless.com.":  {"A": ["198.18.0.1"]},
    }),
}

def under(name, zone):
    return name == zone or name.endswith("." + zone)

def soa(zone):
    return dns.rrset.from_text(zone, 300, "IN", "SOA",
                               f"ns1.{zone} admin.{zone} 1 7200 3600 1209600 300")

def referral(q, zone, servers):
    r = dns.message.make_response(q)
    r.flags &= ~dns.flags.AA
    r.authority.append(dns.rrset.from_text(zone, 172800, "IN", "NS", *[n for n, _ in servers]))
    for n, ip in servers:
        if ip:
            r.additional.append(dns.rrset.from_text(n, 172800, "IN", "A", ip))
    return r

def nxdomain(q, zone):
    r = dns.message.make_response(q)
    r.set_rcode(dns.rcode.NXDOMAIN)
    r.authority.append(soa(zone))
    return r

def answer(ip, q):
    name = q.question[0].name.to_text().lower()
    qt = dns.rdatatype.to_text(q.question[0].rdtype)

    if ip in ROOTS:
        tld = name.rstrip(".").split(".")[-1] + "."
        if tld in TLDS:
            return referral(q, tld, [("a.gtld-servers.net.", TLD)])
        return nxdomain(q, ".")

    if ip == TLD:
        for zone, servers in DELEG.items():
            if under(name, zone):
                return referral(q, zone, servers)
        return nxdomain(q, name.rstrip(".").split(".")[-1] + ".")

    for zone, (server, recs) in ZONES.items():
        if server != ip or not under(name, zone):
            continue
        r = dns.message.make_response(q)
        r.flags |= dns.flags.AA
        owner = name
        for _ in range(8):                        # in-zone CNAME chasing
            rr = recs.get(owner)
            if rr is None:
                break
            if qt in rr:
                r.answer.append(dns.rrset.from_text(owner, 300, "IN", qt, *rr[qt]))
                return r
            if "CNAME" in rr:
                r.answer.append(dns.rrset.from_text(owner, 300, "IN", "CNAME", *rr["CNAME"]))
                owner = rr["CNAME"][0]
                if not under(owner, zone):
                    return r                      # target is in another zone
                continue
            r.authority.append(soa(zone))         # NODATA
            return r
        if r.answer:
            return r
        return nxdomain(q, zone)
    return None                                   # not authoritative: stay silent

socks = {}
for ip in ROOTS + [TLD, GOOG, GH, ELSE]:          # DEAD deliberately has no listener
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, 53))
    socks[s] = ip
print("mock DNS hierarchy up", flush=True)

while True:
    for s in select.select(list(socks), [], [])[0]:
        data, peer = s.recvfrom(4096)
        try:
            q = dns.message.from_wire(data)
            r = answer(socks[s], q)
            if r is not None:
                s.sendto(r.to_wire(), peer)
            print(socks[s], q.question[0].to_text(), flush=True)
        except Exception as e:
            print("err", e, flush=True)
