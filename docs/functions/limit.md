---
page_title: "limit function - nftables"
subcategory: ""
description: |-
  Rate limit packets
---

# function: limit

Rate limit packets

## Example Usage

```terraform
resource "nftables_rule" "rate_limit_icmp" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_icmp_type("echo-request"),
    provider::nftables::limit(10, "second"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
limit(rate number, unit string) string
```

## Arguments

1. `rate` (Number) Maximum rate value.
2. `unit` (String) Time unit: `second`, `minute`, `hour`, `day`, `week`.
