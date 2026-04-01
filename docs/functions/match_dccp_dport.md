---
page_title: "match_dccp_dport function - nftables"
subcategory: ""
description: |-
  Match DCCP destination port
---

# function: match_dccp_dport

Match DCCP destination port

## Example Usage

```terraform
resource "nftables_rule" "dccp" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_dccp_dport(5004),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_dccp_dport(port number) string
```

## Arguments

1. `port` (Number) DCCP destination port number.
