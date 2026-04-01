---
page_title: "match_ip_protocol function - nftables"
subcategory: ""
description: |-
  Match IP protocol (tcp, udp, icmp, ...)
---

# function: match_ip_protocol

Match IP protocol (tcp, udp, icmp, ...)

## Example Usage

```terraform
resource "nftables_rule" "allow_gre" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_protocol("gre"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ip_protocol(proto string) string
```

## Arguments

1. `proto` (String) Protocol name: `tcp`, `udp`, `icmp`, `gre`, `esp`, `ah`, etc.
