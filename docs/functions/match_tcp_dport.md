---
page_title: "match_tcp_dport function - nftables"
subcategory: ""
description: |-
  Match TCP destination port.
---

# function: match_tcp_dport

Returns expressions that match the TCP destination port field.

## Example Usage

```terraform
# Accept SSH traffic
expr = provider::nftables::combine(
  provider::nftables::match_tcp_dport(22),
  provider::nftables::accept(),
)

# Accept HTTPS with counter
expr = provider::nftables::combine(
  provider::nftables::match_tcp_dport(443),
  provider::nftables::counter(),
  provider::nftables::accept(),
)
```

## Signature

```text
match_tcp_dport(port) string
```

## Arguments

- `port` (Number) TCP destination port number (0-65535).
