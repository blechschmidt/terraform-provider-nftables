---
page_title: "set_nftrace function - nftables"
subcategory: ""
description: |-
  Enable nftrace for debugging
---

# function: set_nftrace

Enable nftrace for debugging

## Example Usage

```terraform
resource "nftables_rule" "trace" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(22),
    provider::nftables::set_nftrace(),
  )
}
```

## Signature

```text
set_nftrace() string
```
