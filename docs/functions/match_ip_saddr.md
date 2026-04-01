---
page_title: "match_ip_saddr function - nftables"
subcategory: ""
description: |-
  Match IPv4 source address or CIDR.
---

# function: match_ip_saddr

Returns expressions that match the IPv4 source address field. Supports single IP addresses and CIDR prefixes.

## Example Usage

```terraform
# Match a single IP
expr = provider::nftables::combine(
  provider::nftables::match_ip_saddr("192.168.1.1"),
  provider::nftables::accept(),
)

# Match a CIDR subnet
expr = provider::nftables::combine(
  provider::nftables::match_ip_saddr("10.0.0.0/8"),
  provider::nftables::drop(),
)
```

## Signature

```text
match_ip_saddr(addr) string
```

## Arguments

- `addr` (String) IPv4 address (`"192.168.1.1"`) or CIDR prefix (`"10.0.0.0/8"`).
