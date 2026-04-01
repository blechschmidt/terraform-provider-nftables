---
page_title: "match_ip6_hoplimit function - nftables"
subcategory: ""
description: |-
  Match IPv6 hop limit
---

# function: match_ip6_hoplimit

Match IPv6 hop limit

## Example Usage

```terraform
resource "nftables_rule" "hoplimit" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_hoplimit(255),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ip6_hoplimit(hoplimit number) string
```

## Arguments

1. `hoplimit` (Number) Hop limit value.
