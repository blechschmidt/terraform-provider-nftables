---
page_title: "queue function - nftables"
subcategory: ""
description: |-
  Queue to userspace
---

# function: queue

Queue to userspace

## Example Usage

```terraform
resource "nftables_rule" "to_userspace" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(8080),
    provider::nftables::queue(1),
  )
}
```

## Signature

```text
queue(num number) string
```

## Arguments

1. `num` (Number) Queue number.
