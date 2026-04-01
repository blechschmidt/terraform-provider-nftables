---
page_title: "counter function - nftables"
subcategory: ""
description: |-
  Inline packet and byte counter
---

# function: counter

Inline packet and byte counter

## Example Usage

```terraform
resource "nftables_rule" "count_http" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
counter() string
```
