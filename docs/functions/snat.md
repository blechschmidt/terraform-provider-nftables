---
page_title: "snat function - nftables"
subcategory: ""
description: |-
  Source NAT to address
---

# function: snat

Source NAT to address

## Example Usage

```terraform
resource "nftables_rule" "snat_out" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("172.16.0.0/12"),
    provider::nftables::snat("203.0.113.1"),
  )
}
```

## Signature

```text
snat(addr string) string
```

## Arguments

1. `addr` (String) Target IPv4 address.
