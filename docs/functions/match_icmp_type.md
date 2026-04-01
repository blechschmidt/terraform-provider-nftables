---
page_title: "match_icmp_type function - nftables"
subcategory: ""
description: |-
  Match ICMP type
---

# function: match_icmp_type

Match ICMP type

## Example Usage

```terraform
resource "nftables_rule" "allow_ping" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_icmp_type("echo-request"),
    provider::nftables::limit(10, "second"),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_icmp_type(type_name string) string
```

## Arguments

1. `type_name` (String) ICMP type: `echo-request`, `echo-reply`, `destination-unreachable`, `redirect`, `time-exceeded`, etc.
