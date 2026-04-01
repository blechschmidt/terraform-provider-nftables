---
page_title: "match_nfproto function - nftables"
subcategory: ""
description: |-
  Match nfproto (ipv4 or ipv6)
---

# function: match_nfproto

Match nfproto (ipv4 or ipv6)

## Example Usage

```terraform
resource "nftables_rule" "v4_only" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_nfproto("ipv4"),
    provider::nftables::match_tcp_dport(22),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
match_nfproto(proto string) string
```

## Arguments

1. `proto` (String) Protocol: `ipv4` or `ipv6`.
