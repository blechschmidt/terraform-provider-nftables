---
page_title: "drop function - nftables"
subcategory: ""
description: |-
  Drop the packet
---

# function: drop

Drop the packet

## Example Usage

```terraform
resource "nftables_rule" "block_rfc1918" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("192.168.0.0/16"),
    provider::nftables::drop(),
  )
}
```

## Signature

```text
drop() string
```
