---
page_title: "match_ip6_daddr function - nftables"
subcategory: ""
description: |-
  Match IPv6 destination address (IP or CIDR)
---

# function: match_ip6_daddr

Match IPv6 destination address (IP or CIDR)

## Example Usage

```terraform
resource "nftables_rule" "block_v6" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_daddr("fd00:bad::/32"),
    provider::nftables::drop(),
  )
}
```

## Signature

```text
match_ip6_daddr(addr string) string
```

## Arguments

1. `addr` (String) IPv6 address or CIDR prefix.
