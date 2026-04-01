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

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `namespace` (String) Network namespace to operate in. If not set, uses the default namespace.
