---
page_title: "set_ct_mark function - nftables"
subcategory: ""
description: |-
  Set conntrack mark
---

# function: set_ct_mark

Set conntrack mark

## Example Usage

```terraform
resource "nftables_rule" "tag_ct" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::set_ct_mark(1),
  )
}
```

## Signature

```text
set_ct_mark(mark number) string
```

## Arguments

1. `mark` (Number) CT mark value.
