---
page_title: "reject_icmp function - nftables"
subcategory: ""
description: |-
  Reject with ICMP code
---

# function: reject_icmp

Reject with ICMP code

## Example Usage

```terraform
resource "nftables_rule" "admin_prohib" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::reject_icmp("admin-prohibited"),
  )
}
```

## Signature

```text
reject_icmp(code string) string
```

## Arguments

1. `code` (String) ICMP code: `port-unreachable`, `host-unreachable`, `net-unreachable`, `admin-prohibited`, etc.
