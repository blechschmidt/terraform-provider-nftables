---
page_title: "match_icmpv6_type function - nftables"
subcategory: ""
description: |-
  Match ICMPv6 type
---

# function: match_icmpv6_type

Match ICMPv6 type

## Example Usage

```terraform
resource "nftables_rule" "allow_nd" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_icmpv6_type("nd-neighbor-solicit"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_icmpv6_type(type_name string) string
```

## Arguments

1. `type_name` (String) ICMPv6 type: `echo-request`, `echo-reply`, `nd-neighbor-solicit`, `nd-router-advert`, etc.
