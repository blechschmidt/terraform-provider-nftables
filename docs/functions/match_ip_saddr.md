---
page_title: "match_ip_saddr function - nftables"
subcategory: ""
description: |-
  Match IPv4 source address (IP or CIDR)
---

# function: match_ip_saddr

Match IPv4 source address (IP or CIDR)

## Example Usage

```terraform
resource "nftables_rule" "trusted_lan" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("10.0.0.0/8"),
    provider::nftables::match_tcp_dport(22),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ip_saddr(addr string) string
```

## Arguments

1. `addr` (String) IPv4 address or CIDR prefix.
