---
page_title: "accept function - nftables"
subcategory: ""
description: |-
  Accept the packet
---

# function: accept

Accept the packet

## Example Usage

```terraform
resource "nftables_rule" "allow_ssh" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(22),
    provider::nftables::accept(),
  )
}
```

## Signature

```text
accept() string
```
