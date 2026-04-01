---
page_title: "match_ct_direction function - nftables"
subcategory: ""
description: |-
  Match conntrack direction
---

# function: match_ct_direction

Match conntrack direction

## Example Usage

```terraform
resource "nftables_rule" "ct_orig" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_direction("original"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ct_direction(direction string) string
```

## Arguments

1. `direction` (String) Direction: `original` or `reply`.
