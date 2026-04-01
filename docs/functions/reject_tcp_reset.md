---
page_title: "reject_tcp_reset function - nftables"
subcategory: ""
description: |-
  Reject with TCP RST
---

# function: reject_tcp_reset

Reject with TCP RST

## Example Usage

```terraform
resource "nftables_rule" "tcp_rst" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::reject_tcp_reset(),
  )
}
```

## Signature

```text
reject_tcp_reset() string
```
