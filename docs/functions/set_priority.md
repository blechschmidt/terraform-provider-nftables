---
page_title: "set_priority function - nftables"
subcategory: ""
description: |-
  Set packet priority
---

# function: set_priority

Set packet priority

## Example Usage

```terraform
resource "nftables_rule" "prio" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(22),
    provider::nftables::set_priority(10),
  )
}
```

## Signature

```text
set_priority(priority number) string
```

## Arguments

1. `priority` (Number) Priority value.
