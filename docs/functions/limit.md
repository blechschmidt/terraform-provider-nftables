---
page_title: "limit function - nftables"
subcategory: ""
description: |-
  Rate limit packets.
---

# function: limit

Returns an expression that rate-limits matching packets.

## Example Usage

```terraform
# Accept ICMP at max 10/second
expr = provider::nftables::combine(
  provider::nftables::match_icmp_type("echo-request"),
  provider::nftables::limit(10, "second"),
  provider::nftables::accept(),
)
```

## Signature

```text
limit(rate, unit) string
```

## Arguments

- `rate` (Number) Maximum rate value.
- `unit` (String) Time unit: `"second"`, `"minute"`, `"hour"`, `"day"`, `"week"`.

## Related

- `limit_burst(rate, unit, burst)` — Rate limit with burst allowance.
- `limit_bytes(rate, unit)` — Rate limit by byte count.
