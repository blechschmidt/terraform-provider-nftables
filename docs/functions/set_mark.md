---
page_title: "set_mark function - nftables"
subcategory: ""
description: |-
  Set packet mark
---

# function: set_mark

Set packet mark

## Example Usage

```terraform
resource "nftables_rule" "tag_vpn" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(1194),
    provider::nftables::set_mark(200),
  )
}
```

## Signature

```text
set_mark(mark number) string
```

## Arguments

1. `mark` (Number) Mark value.
