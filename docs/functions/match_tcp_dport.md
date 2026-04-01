---
page_title: "match_tcp_dport function - nftables"
subcategory: ""
description: |-
  Match TCP destination port
---

# function: match_tcp_dport

Match TCP destination port

## Example Usage

```terraform
resource "nftables_rule" "allow_https" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(443),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_tcp_dport(port number) string
```

## Arguments

1. `port` (Number) TCP destination port number (0-65535).
