---
page_title: "combine function - nftables"
subcategory: ""
description: |-
  Combine multiple expression lists into a single rule expression
---

# function: combine

Combine multiple expression lists into a single rule expression

## Example Usage

```terraform
resource "nftables_rule" "firewall" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_iifname("lo"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
combine(parts... string) string
```

## Arguments

1. `parts` (Variadic String) JSON expression lists to combine.
