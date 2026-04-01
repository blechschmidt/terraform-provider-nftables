---
page_title: "masquerade function - nftables"
subcategory: ""
description: |-
  Masquerade (auto source NAT)
---

# function: masquerade

Masquerade (auto source NAT)

## Example Usage

```terraform
resource "nftables_rule" "masq" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade(),
  )
}
```

## Signature

```text
masquerade() string
```
