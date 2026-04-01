---
page_title: "match_ip_length function - nftables"
subcategory: ""
description: |-
  Match IP total length
---

# function: match_ip_length

Match IP total length

## Example Usage

```terraform
resource "nftables_rule" "jumbo" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_length(1500),
    provider::nftables::drop(),
  )
}
```

## Signature

```text
match_ip_length(length number) string
```

## Arguments

1. `length` (Number) IP total length in bytes.
