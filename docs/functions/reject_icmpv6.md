---
page_title: "reject_icmpv6 function - nftables"
subcategory: ""
description: |-
  Reject with ICMPv6 code
---

# function: reject_icmpv6

Reject with ICMPv6 code

## Example Usage

```terraform
resource "nftables_rule" "v6_reject" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::reject_icmpv6("admin-prohibited"),
  )
}
```

## Signature

```text
reject_icmpv6(code string) string
```

## Arguments

1. `code` (String) ICMPv6 code: `no-route`, `admin-prohibited`, `addr-unreachable`, `port-unreachable`.
