---
page_title: "match_ip6_saddr function - nftables"
subcategory: ""
description: |-
  Match IPv6 source address (IP or CIDR)
---

# function: match_ip6_saddr

Match IPv6 source address (IP or CIDR)

## Example Usage

```terraform
resource "nftables_rule" "v6_trusted" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_saddr("fd00::/8"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ip6_saddr(addr string) string
```

## Arguments

1. `addr` (String) IPv6 address or CIDR prefix.
