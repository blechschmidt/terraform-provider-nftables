---
page_title: "match_ip_ttl function - nftables"
subcategory: ""
description: |-
  Match IP TTL
---

# function: match_ip_ttl

Match IP TTL

## Example Usage

```terraform
resource "nftables_rule" "ttl_check" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_ttl(1),
    provider::nftables::drop(),
  )
}
```

## Signature

```text
match_ip_ttl(ttl number) string
```

## Arguments

1. `ttl` (Number) TTL value (0-255).
