---
page_title: "match_l4proto function - nftables"
subcategory: ""
description: |-
  Match L4 protocol by name
---

# function: match_l4proto

Match L4 protocol by name

## Example Usage

```terraform
resource "nftables_rule" "sctp_allow" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_l4proto("sctp"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_l4proto(proto string) string
```

## Arguments

1. `proto` (String) Protocol: `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `dccp`, etc.
