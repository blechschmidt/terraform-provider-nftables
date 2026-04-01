---
page_title: "return_verdict function - nftables"
subcategory: ""
description: |-
  Return from current chain
---

# function: return_verdict

Return from current chain

## Example Usage

```terraform
resource "nftables_rule" "early_return" {
  family = "inet"
  table  = "filter"
  chain  = "web_traffic"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("10.0.0.0/8"),
    provider::nftables::return_verdict(),
  )
}
```

## Signature

```text
return_verdict() string
```
