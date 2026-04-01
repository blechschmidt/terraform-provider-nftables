---
page_title: "match_iifname function - nftables"
subcategory: ""
description: |-
  Match input interface name
---

# function: match_iifname

Match input interface name

## Example Usage

```terraform
resource "nftables_rule" "loopback" {
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
match_iifname(name string) string
```

## Arguments

1. `name` (String) Interface name (e.g., `eth0`, `lo`).
