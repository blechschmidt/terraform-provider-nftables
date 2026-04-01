---
page_title: "limit_bytes function - nftables"
subcategory: ""
description: |-
  Rate limit bytes
---

# function: limit_bytes

Rate limit bytes

## Example Usage

```terraform
resource "nftables_rule" "bandwidth" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::limit_bytes(1048576, "second"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
limit_bytes(rate number, unit string) string
```

## Arguments

1. `rate` (Number) Rate in bytes.
2. `unit` (String) Time unit: `second`, `minute`, `hour`, `day`, `week`.
