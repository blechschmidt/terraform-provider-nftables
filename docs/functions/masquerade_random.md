---
page_title: "masquerade_random function - nftables"
subcategory: ""
description: |-
  Masquerade with random port selection
---

# function: masquerade_random

Masquerade with random port selection

## Example Usage

```terraform
resource "nftables_rule" "masq_rand" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade_random(),
  )
}
```

## Signature

```text
masquerade_random() string
```
