---
page_title: "dnat_port function - nftables"
subcategory: ""
description: |-
  Destination NAT to address and port.
---

# function: dnat_port

Returns expressions that perform destination NAT, rewriting the destination address and port. Use in prerouting nat chains.

## Example Usage

```terraform
# Port forward: external :8080 -> internal 10.0.0.5:80
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
dnat_port(addr, port) string
```

## Arguments

- `addr` (String) Target IPv4 address.
- `port` (Number) Target port number.

## Related

- `dnat(addr)` — DNAT without port rewriting.
- `snat(addr)` — Source NAT.
- `snat_port(addr, port)` — Source NAT with port.
- `redirect(port)` — Redirect to local port.
