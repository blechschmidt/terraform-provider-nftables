---
page_title: "dnat function - nftables"
subcategory: ""
description: |-
  Destination NAT to address
---

# function: dnat

Destination NAT to address

## Example Usage

```terraform
resource "nftables_rule" "dnat_web" {
  family = "ip"
  table  = "nat"
  chain  = "prerouting"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::dnat("10.0.0.5"),
  )
}
```

## Signature

```text
dnat(addr string) string
```

## Arguments

1. `addr` (String) Target IPv4 address.
