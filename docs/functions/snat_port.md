---
page_title: "snat_port function - nftables"
subcategory: ""
description: |-
  Source NAT to address and port
---

# function: snat_port

Source NAT to address and port

## Example Usage

```terraform
resource "nftables_rule" "snat_fixed" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("172.16.0.0/12"),
    provider::nftables::snat_port("203.0.113.1", 1024),
  )
}
```

## Signature

```text
snat_port(addr string, port number) string
```

## Arguments

1. `addr` (String) Target IPv4 address.
2. `port` (Number) Target port.
