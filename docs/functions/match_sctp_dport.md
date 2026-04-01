---
page_title: "match_sctp_dport function - nftables"
subcategory: ""
description: |-
  Match SCTP destination port
---

# function: match_sctp_dport

Match SCTP destination port

## Example Usage

```terraform
resource "nftables_rule" "sctp_sip" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_sctp_dport(5060),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_sctp_dport(port number) string
```

## Arguments

1. `port` (Number) SCTP destination port number.
