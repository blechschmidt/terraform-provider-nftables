---
page_title: "jump function - nftables"
subcategory: ""
description: |-
  Jump to another chain
---

# function: jump

Jump to another chain

## Example Usage

```terraform
resource "nftables_rule" "jump_web" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::jump("web_traffic"),
  )
}
```

## Signature

```text
jump(chain string) string
```

## Arguments

1. `chain` (String) Target chain name.
