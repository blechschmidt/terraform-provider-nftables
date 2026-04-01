---
page_title: "match_sctp_sport function - nftables"
subcategory: ""
description: |-
  Match SCTP source port
---

# function: match_sctp_sport

Match SCTP source port

## Example Usage

```terraform
resource "nftables_rule" "sctp_src" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_sctp_sport(5060),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_sctp_sport(port number) string
```

## Arguments

1. `port` (Number) SCTP source port number.
