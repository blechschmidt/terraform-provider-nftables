---
page_title: "match_ct_status function - nftables"
subcategory: ""
description: |-
  Match conntrack status
---

# function: match_ct_status

Match conntrack status

## Example Usage

```terraform
resource "nftables_rule" "ct_assured" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_status(["assured"]),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ct_status(statuses list) string
```

## Arguments

1. `statuses` (List of String) Statuses: `expected`, `seen-reply`, `assured`, `confirmed`, `snat`, `dnat`, `dying`.
