---
page_title: "match_udp_sport function - nftables"
subcategory: ""
description: |-
  Match UDP source port
---

# function: match_udp_sport

Match UDP source port

## Example Usage

```terraform
resource "nftables_rule" "from_dns" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_udp_sport(53),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_udp_sport(port number) string
```

## Arguments

1. `port` (Number) UDP source port number.
