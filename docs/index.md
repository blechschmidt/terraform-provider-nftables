---
page_title: "nftables Provider"
subcategory: ""
description: |-
  Terraform provider for managing nftables firewall rules via netlink.
---

# nftables Provider

The nftables provider allows you to manage Linux [nftables](https://wiki.nftables.org/) firewall rules declaratively using Terraform. It communicates directly with the kernel via netlink using the [google/nftables](https://github.com/google/nftables) Go library — no `nft` CLI dependency required.

## Supported Resources

| Resource | Description |
|----------|-------------|
| `nftables_table` | Tables (all 6 address families) |
| `nftables_chain` | Base chains and regular chains |
| `nftables_rule` | Rules with full nft expression syntax |
| `nftables_set` | Named sets with elements |
| `nftables_map` | Named maps and verdict maps |
| `nftables_flowtable` | Flowtables for conntrack fastpath |
| `nftables_counter` | Named counters |
| `nftables_quota` | Named quotas |
| `nftables_limit` | Named rate limits |
| `nftables_ct_helper` | Conntrack helpers |
| `nftables_ct_timeout` | Conntrack timeout policies |
| `nftables_ct_expectation` | Conntrack expectations |
| `nftables_synproxy` | SYN proxy objects |
| `nftables_secmark` | Security marking objects |

## Address Families

All six nftables address families are supported:

- `ip` — IPv4
- `ip6` — IPv6
- `inet` — Dual-stack (IPv4 + IPv6)
- `arp` — ARP
- `bridge` — Bridging
- `netdev` — Device-level (ingress/egress)

## Provider Functions

The provider includes 64 provider-defined functions for composing nftables rule expressions in a type-safe way. Functions are called with the `provider::nftables::` prefix and return JSON-encoded expression lists. Use `combine()` to merge them into a single rule.

| Category | Functions | Description |
|----------|-----------|-------------|
| Combiner | `combine` | Merge expression lists into a single rule |
| Verdicts | `accept`, `drop`, `return_verdict`, `jump`, `goto_chain` | Packet disposition |
| Actions | `counter`, `log`, `limit`, `reject*`, `masquerade*`, `snat*`, `dnat*`, `redirect`, `notrack`, `flow_offload`, `queue` | Logging, rate limiting, NAT, and more |
| Setters | `set_mark`, `set_ct_mark`, `set_priority`, `set_nftrace` | Modify packet/connection metadata |
| IPv4 Matchers | `match_ip_saddr`, `match_ip_daddr`, `match_ip_protocol`, `match_ip_ttl`, `match_ip_length` | IPv4 header matching |
| IPv6 Matchers | `match_ip6_saddr`, `match_ip6_daddr`, `match_ip6_hoplimit`, `match_ip6_nexthdr` | IPv6 header matching |
| Transport Matchers | `match_tcp_dport`, `match_tcp_sport`, `match_tcp_flags`, `match_udp_*`, `match_sctp_*`, `match_dccp_*` | TCP/UDP/SCTP/DCCP matching |
| ICMP Matchers | `match_icmp_type`, `match_icmpv6_type` | ICMP message type matching |
| Meta Matchers | `match_iifname`, `match_oifname`, `match_mark`, `match_nfproto`, `match_l4proto`, `match_pkttype`, `match_skuid`, `match_skgid` | Interface, mark, and socket matching |
| CT Matchers | `match_ct_state`, `match_ct_mark`, `match_ct_status`, `match_ct_direction` | Connection tracking matching |

See the [Provider Functions documentation](functions/) for detailed signatures, arguments, and examples for every function.

## Example Usage

```terraform
provider "nftables" {
  # Optional: operate within a network namespace
  # namespace = "my_namespace"
}

resource "nftables_table" "filter" {
  family = "inet"
  name   = "filter"
}

resource "nftables_chain" "input" {
  family   = nftables_table.filter.family
  table    = nftables_table.filter.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "drop"
}

# Accept established/related connections
resource "nftables_rule" "established" {
  family     = nftables_table.filter.family
  table      = nftables_table.filter.name
  chain      = nftables_chain.input.name
  expression = "ct state established,related accept"
}

# Accept loopback
resource "nftables_rule" "loopback" {
  family     = nftables_table.filter.family
  table      = nftables_table.filter.name
  chain      = nftables_chain.input.name
  expression = "iifname lo accept"
}

# Accept SSH
resource "nftables_rule" "ssh" {
  family     = nftables_table.filter.family
  table      = nftables_table.filter.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 22 counter accept"
}

# Accept ICMP ping
resource "nftables_rule" "ping" {
  family     = nftables_table.filter.family
  table      = nftables_table.filter.name
  chain      = nftables_chain.input.name
  expression = "icmp type echo-request accept"
}
```

### v2: JSON netlink VM expressions

For advanced use cases, rules can be specified as JSON-encoded netlink VM statement lists using the `expr` attribute. This maps directly to the kernel's expression model.

```terraform
resource "nftables_rule" "ssh_v2" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = jsonencode([
    {type = "meta", key = "l4proto", dreg = 1},
    {type = "cmp", op = "eq", sreg = 1, data = base64encode("\u0006")},
    {type = "payload", base = "transport", offset = 2, len = 2, dreg = 1},
    {type = "cmp", op = "eq", sreg = 1, data = base64encode("\u0000\u0016")},
    {type = "counter"},
    {type = "verdict", kind = "accept"}
  ])
}
```

A Go helper library (`internal/nfthelper`) is also provided for programmatic rule construction:

```go
import "github.com/blechschmidt/terraform-provider-nftables/internal/nfthelper"

rule := nfthelper.Combine(
    nfthelper.MatchIifname("eth0"),
    nfthelper.MatchTCPDport(443),
    nfthelper.MatchCTState("new"),
    nfthelper.Counter(),
    nfthelper.Accept(),
)
```

## Quick reference

The table below maps every rule from the [nftables in 10 minutes](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes) quick-reference guide to its two Terraform equivalents: the **string-expression form** (`expression = "..."`) and the **provider-function form** (`expr = provider::nftables::combine(...)`). Both produce the same kernel ruleset; each row is exercised by a dedicated acceptance test that applies the rule in a fresh network namespace and verifies the output of `nft list ruleset`.

Values like `cs1`, `ip`, and `arp` are expanded to their numeric equivalents (DSCP 8, EtherType `0x0800`, EtherType `0x0806`) because the expression parser accepts numeric forms uniformly across all fields.

### IPv4 header matches

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `ip saddr 192.168.2.0/24 accept` | `ip saddr 192.168.2.0/24 accept` | `match_ip_saddr("192.168.2.0/24"), accept()` |
| `ip daddr 10.0.0.1 accept` | `ip daddr 10.0.0.1 accept` | `match_ip_daddr("10.0.0.1"), accept()` |
| `ip protocol tcp accept` | `ip protocol tcp accept` | `match_ip_protocol("tcp"), accept()` |
| `ip ttl 64 accept` | `ip ttl 64 accept` | `match_ip_ttl(64), accept()` |
| `ip length 232 drop` | `ip length 232 drop` | `match_ip_length(232), drop()` |
| `ip dscp cs1 accept` | `ip dscp 8 accept` | `match_ip_dscp(8), accept()` |
| `ip id 22 accept` | `ip id 22 accept` | `match_ip_id(22), accept()` |
| `ip version 4 accept` | `ip version 4 accept` | `match_ip_version(4), accept()` |
| `ip hdrlength 5 accept` | `ip hdrlength 5 accept` | `match_ip_hdrlength(5), accept()` |

### IPv6 header matches

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `ip6 saddr fd00::/8 accept` | `ip6 saddr fd00::/8 accept` | `match_ip6_saddr("fd00::/8"), accept()` |
| `ip6 daddr ::1 accept` | `ip6 daddr ::1 accept` | `match_ip6_daddr("::1"), accept()` |
| `ip6 hoplimit 255 accept` | `ip6 hoplimit 255 accept` | `match_ip6_hoplimit(255), accept()` |
| `ip6 nexthdr tcp accept` | `ip6 nexthdr tcp accept` | `match_ip6_nexthdr("tcp"), accept()` |
| `ip6 flowlabel 22 accept` | `ip6 flowlabel 22 accept` | `match_ip6_flowlabel(22), accept()` |
| `ip6 length 100 accept` | `ip6 length 100 accept` | `match_ip6_length(100), accept()` |
| `ip6 version 6 accept` | `ip6 version 6 accept` | `match_ip6_version(6), accept()` |

### TCP / UDP / SCTP / DCCP matches

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `tcp dport 22 accept` | `tcp dport 22 accept` | `match_tcp_dport(22), accept()` |
| `tcp sport 80 accept` | `tcp sport 80 accept` | `match_tcp_sport(80), accept()` |
| `tcp flags syn accept` | `tcp flags syn accept` | `match_tcp_flags("syn"), accept()` |
| `tcp sequence 22 accept` | `tcp sequence 22 accept` | `match_tcp_sequence(22), accept()` |
| `tcp window 100 accept` | `tcp window 100 accept` | `match_tcp_window(100), accept()` |
| `udp dport 53 accept` | `udp dport 53 accept` | `match_udp_dport(53), accept()` |
| `udp sport 53 accept` | `udp sport 53 accept` | `match_udp_sport(53), accept()` |
| `udp length 100 accept` | `udp length 100 accept` | `match_udp_length(100), accept()` |
| `sctp dport 5060 accept` | `sctp dport 5060 accept` | `match_sctp_dport(5060), accept()` |
| `sctp sport 5060 accept` | `sctp sport 5060 accept` | `match_sctp_sport(5060), accept()` |
| `dccp dport 5004 accept` | `dccp dport 5004 accept` | `match_dccp_dport(5004), accept()` |
| `dccp sport 5004 accept` | `dccp sport 5004 accept` | `match_dccp_sport(5004), accept()` |

### ICMP / ICMPv6 matches

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `icmp type echo-request accept` | `icmp type echo-request accept` | `match_icmp_type("echo-request"), accept()` |
| `icmp type echo-reply accept` | `icmp type echo-reply accept` | `match_icmp_type("echo-reply"), accept()` |
| `icmp type destination-unreachable accept` | `icmp type destination-unreachable accept` | `match_icmp_type("destination-unreachable"), accept()` |
| `icmp type time-exceeded accept` | `icmp type time-exceeded accept` | `match_icmp_type("time-exceeded"), accept()` |
| `icmpv6 type echo-request accept` | `icmpv6 type echo-request accept` | `match_icmpv6_type("echo-request"), accept()` |
| `icmpv6 type nd-neighbor-solicit accept` | `icmpv6 type nd-neighbor-solicit accept` | `match_icmpv6_type("nd-neighbor-solicit"), accept()` |
| `icmpv6 type nd-router-advert accept` | `icmpv6 type nd-router-advert accept` | `match_icmpv6_type("nd-router-advert"), accept()` |
| `icmpv6 type packet-too-big accept` | `icmpv6 type packet-too-big accept` | `match_icmpv6_type("packet-too-big"), accept()` |

### Ethernet / VLAN / ARP matches

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `ether saddr 00:11:22:33:44:55 accept` | `ether saddr 00:11:22:33:44:55 accept` | `match_ether_saddr("00:11:22:33:44:55"), accept()` |
| `ether type ip accept` | `ether type 0x0800 accept` | `match_ether_type(2048), accept()` |
| `vlan id 100 accept` | `vlan id 100 accept` | `match_vlan_id(100), accept()` |
| `arp operation request accept` | `arp operation request accept` | `match_arp_operation("request"), accept()` |
| `arp htype 1 accept` | `arp htype 1 accept` | `match_arp_htype(1), accept()` |

### Meta matches

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `iifname "lo" accept` | `iifname lo accept` | `match_iifname("lo"), accept()` |
| `oifname "lo" accept` | `oifname lo accept` | `match_oifname("lo"), accept()` |
| `meta mark 42 accept` | `meta mark 42 accept` | `match_mark(42), accept()` |
| `meta nfproto ipv4 accept` | `meta nfproto ipv4 accept` | `match_nfproto("ipv4"), accept()` |
| `meta l4proto tcp accept` | `meta l4proto tcp accept` | `match_l4proto("tcp"), accept()` |
| `meta pkttype broadcast drop` | `meta pkttype broadcast drop` | `match_pkttype("broadcast"), drop()` |
| `meta skuid 0 accept` | `meta skuid 0 accept` | `match_skuid(0), accept()` |
| `meta skgid 0 accept` | `meta skgid 0 accept` | `match_skgid(0), accept()` |
| `meta length 1000 accept` | `meta length 1000 accept` | `match_meta_length(1000), accept()` |
| `meta protocol ip accept` | `meta protocol 0x0800 accept` | `match_meta_protocol(2048), accept()` |

### Connection tracking matches

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `ct state established,related accept` | `ct state established,related accept` | `match_ct_state(["established", "related"]), accept()` |
| `ct state new accept` | `ct state new accept` | `match_ct_state(["new"]), accept()` |
| `ct state invalid drop` | `ct state invalid drop` | `match_ct_state(["invalid"]), drop()` |
| `ct state untracked accept` | `ct state untracked accept` | `match_ct_state(["untracked"]), accept()` |
| `ct direction original accept` | `ct direction original accept` | `match_ct_direction("original"), accept()` |
| `ct status assured accept` | `ct status assured accept` | `match_ct_status(["assured"]), accept()` |
| `ct mark 1 accept` | `ct mark 1 accept` | `match_ct_mark(1), accept()` |

### Verdicts

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `accept` | `accept` | `accept()` |
| `drop` | `drop` | `drop()` |
| `return` | `return` | `return_verdict()` |
| `tcp dport 80 jump mychain` | `tcp dport 80 jump mychain` | `match_tcp_dport(80), jump("mychain")` |
| `tcp dport 443 goto mychain` | `tcp dport 443 goto mychain` | `match_tcp_dport(443), goto_chain("mychain")` |

### NAT

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `oifname "lo" masquerade` | `oifname lo masquerade` | `match_oifname("lo"), masquerade()` |
| `masquerade random` | `masquerade random` | `masquerade_random()` |
| `ip saddr 172.16.0.0/12 snat to 203.0.113.1` | `ip saddr 172.16.0.0/12 snat to 203.0.113.1` | `match_ip_saddr("172.16.0.0/12"), snat("203.0.113.1")` |
| `tcp dport 8080 dnat to 10.0.0.5:80` | `tcp dport 8080 dnat to 10.0.0.5:80` | `match_tcp_dport(8080), dnat_port("10.0.0.5", 80)` |
| `tcp dport 80 redirect to :3128` | `tcp dport 80 redirect to :3128` | `match_tcp_dport(80), redirect(3128)` |

### Counter, limit, log

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `tcp dport 80 counter accept` | `tcp dport 80 counter accept` | `match_tcp_dport(80), counter(), accept()` |
| `limit rate 10/second accept` | `limit rate 10/second accept` | `limit(10, "second"), accept()` |
| `limit rate 400/minute accept` | `limit rate 400/minute accept` | `limit(400, "minute"), accept()` |
| `limit rate 100/second burst 50 accept` | `limit rate 100/second burst 50 packets accept` | `limit_burst(100, "second", 50), accept()` |
| `limit rate 1 mbytes/second accept` | `limit rate 1048576 bytes/second accept` | `limit_bytes(1048576, "second"), accept()` |
| `log prefix "INPUT" accept` | `log prefix "INPUT" accept` | `log("INPUT", "info"), accept()` |

### Reject

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `reject` | `reject` | `reject()` |
| `tcp dport 80 reject with tcp reset` | `tcp dport 80 reject with tcp reset` | `match_tcp_dport(80), reject_tcp_reset()` |
| `reject with icmp type host-unreachable` | `reject with icmp type host-unreachable` | `reject_icmp("host-unreachable")` |
| `reject with icmp type admin-prohibited` | `reject with icmp type admin-prohibited` | `reject_icmp("admin-prohibited")` |
| `reject with icmpv6 type admin-prohibited` | `reject with icmpv6 type admin-prohibited` | `reject_icmpv6("admin-prohibited")` |
| `reject with icmpx type admin-prohibited` | `reject with icmpx type admin-prohibited` | `reject_icmpx("admin-prohibited")` |

### Mark / priority / queue / notrack

| nft rule | `expression = ` | `expr = combine(...)` |
|---|---|---|
| `tcp dport 80 meta mark set 42` | `tcp dport 80 meta mark set 42` | `match_tcp_dport(80), set_mark(42)` |
| `tcp dport 80 ct mark set 1` | `tcp dport 80 ct mark set 1` | `match_tcp_dport(80), set_ct_mark(1)` |
| `tcp dport 22 meta priority set 10` | `tcp dport 22 meta priority set 10` | `match_tcp_dport(22), set_priority(10)` |
| `udp dport 53 notrack` | `udp dport 53 notrack` | `match_udp_dport(53), notrack()` |
| `tcp dport 8080 queue num 1` | `tcp dport 8080 queue num 1` | `match_tcp_dport(8080), queue(1)` |

### Combined examples

| `expression = ` | `expr = combine(...)` |
|---|---|
| `ip saddr 10.0.0.0/8 tcp dport 22 ct state new counter accept` | `match_ip_saddr("10.0.0.0/8"), match_tcp_dport(22), match_ct_state(["new"]), counter(), accept()` |
| `icmp type echo-request limit rate 10/second burst 20 packets accept` | `match_icmp_type("echo-request"), limit_burst(10, "second", 20), accept()` |
| `iifname lo tcp dport 8080 dnat to 10.0.0.5:80` | `match_iifname("lo"), match_tcp_dport(8080), dnat_port("10.0.0.5", 80)` |
| `oifname lo masquerade` | `match_oifname("lo"), masquerade()` |

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `namespace` (String) Network namespace to operate in. If not set, uses the default namespace.
