---
page_title: "match_pkttype function - nftables"
subcategory: ""
description: |-
  Match packet type
---

# function: match_pkttype

Match packet type

## Example Usage

```terraform
resource "nftables_rule" "no_broadcast" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_pkttype("broadcast"),
    provider::nftables::drop(),
  )
}
```

## Signature

```text
match_pkttype(pkttype string) string
```

## Arguments

1. `pkttype` (String) Packet type: `host`, `broadcast`, `multicast`, `other`.
