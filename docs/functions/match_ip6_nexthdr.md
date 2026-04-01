---
page_title: "match_ip6_nexthdr function - nftables"
subcategory: ""
description: |-
  Match IPv6 next header protocol
---

# function: match_ip6_nexthdr

Match IPv6 next header protocol

## Example Usage

```terraform
resource "nftables_rule" "v6_tcp" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_nexthdr("tcp"),
    provider::nftables::match_tcp_dport(22),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ip6_nexthdr(proto string) string
```

## Arguments

1. `proto` (String) Protocol name: `tcp`, `udp`, `icmpv6`, etc.
