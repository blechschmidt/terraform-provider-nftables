---
page_title: "masquerade_persistent function - nftables"
subcategory: ""
description: |-
  Masquerade with persistent mapping
---

# function: masquerade_persistent

Masquerade with persistent mapping

## Example Usage

```terraform
resource "nftables_rule" "masq_persist" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade_persistent(),
  )
}
```

## Signature

```text
masquerade_persistent() string
```
