---
page_title: "match_ct_state function - nftables"
subcategory: ""
description: |-
  Match conntrack state
---

# function: match_ct_state

Match conntrack state

## Example Usage

```terraform
resource "nftables_rule" "established" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["established", "related"]),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_ct_state(states list) string
```

## Arguments

1. `states` (List of String) States: `new`, `established`, `related`, `invalid`, `untracked`.
