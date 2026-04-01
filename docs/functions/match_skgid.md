---
page_title: "match_skgid function - nftables"
subcategory: ""
description: |-
  Match socket GID
---

# function: match_skgid

Match socket GID

## Example Usage

```terraform
resource "nftables_rule" "gid_filter" {
  family = "inet"
  table  = "filter"
  chain  = "output"
  expr = provider::nftables::combine(
    provider::nftables::match_skgid(1000),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_skgid(gid number) string
```

## Arguments

1. `gid` (Number) GID value.
