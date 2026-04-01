---
page_title: "match_dccp_sport function - nftables"
subcategory: ""
description: |-
  Match DCCP source port
---

# function: match_dccp_sport

Match DCCP source port

## Example Usage

```terraform
resource "nftables_rule" "dccp_src" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_dccp_sport(5004),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_dccp_sport(port number) string
```

## Arguments

1. `port` (Number) DCCP source port number.
