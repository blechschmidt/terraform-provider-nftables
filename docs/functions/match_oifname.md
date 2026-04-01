---
page_title: "match_oifname function - nftables"
subcategory: ""
description: |-
  Match output interface name
---

# function: match_oifname

Match output interface name

## Example Usage

```terraform
resource "nftables_rule" "outbound" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade(),
  )
}
```

## Signature

```text
match_oifname(name string) string
```

## Arguments

1. `name` (String) Interface name.
