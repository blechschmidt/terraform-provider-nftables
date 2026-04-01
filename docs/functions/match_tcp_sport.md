---
page_title: "match_tcp_sport function - nftables"
subcategory: ""
description: |-
  Match TCP source port
---

# function: match_tcp_sport

Match TCP source port

## Example Usage

```terraform
resource "nftables_rule" "from_http" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_sport(80),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_tcp_sport(port number) string
```

## Arguments

1. `port` (Number) TCP source port number.
