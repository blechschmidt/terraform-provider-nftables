---
page_title: "set_tcp_mss function - nftables"
subcategory: ""
description: |-
  Clamp the TCP MSS option to a fixed value
---

# function: set_tcp_mss

Clamp the TCP MSS option to a fixed value

## Example Usage

```terraform
resource "nftables_rule" "clamp_mss" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_flags("syn"),
    provider::nftables::set_tcp_mss(1400),
  )
}
```

## Signature

```text
set_tcp_mss(mss number) string
```

## Arguments

1. `mss` (Number) Maximum segment size in bytes.
