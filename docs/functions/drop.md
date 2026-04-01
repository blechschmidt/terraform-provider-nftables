---
page_title: "drop function - nftables"
subcategory: ""
description: |-
  Drop the packet.
---

# function: drop

Returns an expression that drops the packet (terminal verdict).

## Example Usage

```terraform
expr = provider::nftables::combine(
  provider::nftables::match_ip_saddr("192.168.0.0/16"),
  provider::nftables::drop(),
)
```

## Signature

```text
drop() string
```
