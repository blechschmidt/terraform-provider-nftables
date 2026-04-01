---
page_title: "match_udp_dport function - nftables"
subcategory: ""
description: |-
  Match UDP destination port
---

# function: match_udp_dport

Match UDP destination port

## Example Usage

```terraform
resource "nftables_rule" "allow_dns" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_udp_dport(53),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_udp_dport(port number) string
```

## Arguments

1. `port` (Number) UDP destination port number.
