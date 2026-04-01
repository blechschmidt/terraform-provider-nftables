---
page_title: "match_iifname function - nftables"
subcategory: ""
description: |-
  Match input interface name.
---

# function: match_iifname

Returns expressions that match the input interface name.

## Example Usage

```terraform
# Accept all loopback traffic
expr = provider::nftables::combine(
  provider::nftables::match_iifname("lo"),
  provider::nftables::accept(),
)
```

## Signature

```text
match_iifname(name) string
```

## Arguments

- `name` (String) Interface name (e.g., `"eth0"`, `"lo"`, `"wlan0"`).
