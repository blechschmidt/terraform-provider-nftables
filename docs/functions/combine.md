---
page_title: "combine function - nftables"
subcategory: ""
description: |-
  Combine multiple expression lists into a single rule expression.
---

# function: combine

Concatenates JSON expression lists produced by matcher and action functions into a single list suitable for the `expr` attribute of `nftables_rule`.

This is the primary composition function. All other provider functions produce expression fragments; `combine()` merges them into a complete rule.

## Example Usage

```terraform
resource "nftables_rule" "ssh" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("10.0.0.0/8"),
    provider::nftables::match_tcp_dport(22),
    provider::nftables::match_ct_state(["new"]),
    provider::nftables::counter(),
    provider::nftables::log("SSH", "info"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
combine(parts...) string
```

## Arguments

- `parts` (variadic string) One or more JSON expression lists returned by other provider functions.
