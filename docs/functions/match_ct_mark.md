---
page_title: "match_ct_mark function - nftables"
subcategory: ""
description: |-
  Match conntrack mark
---

# function: match_ct_mark

Match conntrack mark

## Example Usage

```terraform
resource "nftables_rule" "ct_marked" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_mark(42),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ct_mark(mark number) string
```

## Arguments

1. `mark` (Number) CT mark value.
