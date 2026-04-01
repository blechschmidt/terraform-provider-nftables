---
page_title: "notrack function - nftables"
subcategory: ""
description: |-
  Disable connection tracking
---

# function: notrack

Disable connection tracking

## Example Usage

```terraform
resource "nftables_rule" "notrack_dns" {
  family = "ip"
  table  = "raw"
  chain  = "prerouting"
  expr = provider::nftables::combine(
    provider::nftables::match_udp_dport(53),
    provider::nftables::notrack(),
  )
}
```

## Signature

```text
notrack() string
```
