---
page_title: "limit_burst function - nftables"
subcategory: ""
description: |-
  Rate limit packets with burst
---

# function: limit_burst

Rate limit packets with burst

## Example Usage

```terraform
resource "nftables_rule" "web_rate" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(443),
    provider::nftables::match_ct_state(["new"]),
    provider::nftables::limit_burst(100, "second", 200),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
limit_burst(rate number, unit string, burst number) string
```

## Arguments

1. `rate` (Number) Maximum rate value.
2. `unit` (String) Time unit: `second`, `minute`, `hour`, `day`, `week`.
3. `burst` (Number) Burst allowance.
