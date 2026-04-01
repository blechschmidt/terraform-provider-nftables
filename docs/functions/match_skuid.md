---
page_title: "match_skuid function - nftables"
subcategory: ""
description: |-
  Match socket UID
---

# function: match_skuid

Match socket UID

## Example Usage

```terraform
resource "nftables_rule" "uid_filter" {
  family = "inet"
  table  = "filter"
  chain  = "output"
  expr = provider::nftables::combine(
    provider::nftables::match_skuid(0),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_skuid(uid number) string
```

## Arguments

1. `uid` (Number) UID value.
