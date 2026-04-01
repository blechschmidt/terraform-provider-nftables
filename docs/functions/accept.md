---
page_title: "accept function - nftables"
subcategory: ""
description: |-
  Accept the packet.
---

# function: accept

Returns an expression that accepts the packet (terminal verdict).

## Example Usage

```terraform
expr = provider::nftables::combine(
  provider::nftables::match_tcp_dport(22),
  provider::nftables::accept(),
)
```

## Signature

```text
accept() string
```
