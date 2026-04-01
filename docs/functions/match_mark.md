---
page_title: "match_mark function - nftables"
subcategory: ""
description: |-
  Match packet mark
---

# function: match_mark

Match packet mark

## Example Usage

```terraform
resource "nftables_rule" "marked" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_mark(100),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_mark(mark number) string
```

## Arguments

1. `mark` (Number) Mark value.
