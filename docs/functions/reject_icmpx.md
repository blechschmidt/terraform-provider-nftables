---
page_title: "reject_icmpx function - nftables"
subcategory: ""
description: |-
  Reject with ICMPx code (inet family)
---

# function: reject_icmpx

Reject with ICMPx code (inet family)

## Example Usage

```terraform
resource "nftables_rule" "inet_reject" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::reject_icmpx("admin-prohibited"),
  )
}
```

## Signature

```text
reject_icmpx(code string) string
```

## Arguments

1. `code` (String) ICMPx code: `port-unreachable`, `admin-prohibited`, `no-route`, `host-unreachable`.
