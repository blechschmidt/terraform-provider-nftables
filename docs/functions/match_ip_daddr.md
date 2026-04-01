---
page_title: "match_ip_daddr function - nftables"
subcategory: ""
description: |-
  Match IPv4 destination address (IP or CIDR)
---

# function: match_ip_daddr

Match IPv4 destination address (IP or CIDR)

## Example Usage

```terraform
resource "nftables_rule" "to_server" {
  family = "ip"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_daddr("10.0.0.5"),
    provider::nftables::match_tcp_dport(80),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ip_daddr(addr string) string
```

## Arguments

1. `addr` (String) IPv4 address or CIDR prefix.
