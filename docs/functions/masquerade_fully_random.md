---
page_title: "masquerade_fully_random function - nftables"
subcategory: ""
description: |-
  Masquerade with fully random port selection
---

# function: masquerade_fully_random

Masquerade with fully random port selection

## Example Usage

```terraform
resource "nftables_rule" "masq_fr" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade_fully_random(),
  )
}
```

## Signature

```text
masquerade_fully_random() string
```
