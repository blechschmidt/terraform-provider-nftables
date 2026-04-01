---
page_title: "match_ct_state function - nftables"
subcategory: ""
description: |-
  Match conntrack state.
---

# function: match_ct_state

Returns expressions that match the connection tracking state. Multiple states are combined with bitwise OR.

## Example Usage

```terraform
# Accept established and related connections
expr = provider::nftables::combine(
  provider::nftables::match_ct_state(["established", "related"]),
  provider::nftables::accept(),
)

# Drop invalid packets
expr = provider::nftables::combine(
  provider::nftables::match_ct_state(["invalid"]),
  provider::nftables::drop(),
)
```

## Signature

```text
match_ct_state(states) string
```

## Arguments

- `states` (List of String) One or more of: `"new"`, `"established"`, `"related"`, `"invalid"`, `"untracked"`.
