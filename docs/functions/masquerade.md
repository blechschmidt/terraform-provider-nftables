---
page_title: "masquerade function - nftables"
subcategory: ""
description: |-
  Masquerade (auto source NAT).
---

# function: masquerade

Returns an expression that masquerades outbound traffic (automatic source NAT using the output interface address). Use in postrouting nat chains.

## Example Usage

```terraform
resource "nftables_rule" "masq" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade(),
  )
}
```

## Signature

```text
masquerade() string
```

## Related

- `masquerade_random()` — Masquerade with random port selection.
- `masquerade_persistent()` — Masquerade with persistent mapping.
- `masquerade_fully_random()` — Masquerade with fully random port selection.
