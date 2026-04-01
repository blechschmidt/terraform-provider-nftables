---
page_title: "dnat_port function - nftables"
subcategory: ""
description: |-
  Destination NAT to address and port
---

# function: dnat_port

Destination NAT to address and port

## Example Usage

```terraform
resource "nftables_rule" "port_forward" {
  family = "ip"
  table  = "nat"
  chain  = "prerouting"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(8080),
    provider::nftables::dnat_port("10.0.0.5", 80),
  )
}
```

## Signature

```text
dnat_port(addr string, port number) string
```

## Arguments

1. `addr` (String) Target IPv4 address.
2. `port` (Number) Target port number.
