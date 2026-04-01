---
page_title: "reject function - nftables"
subcategory: ""
description: |-
  Reject with default ICMP error
---

# function: reject

Reject with default ICMP error

## Example Usage

```terraform
resource "nftables_rule" "reject_all" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::reject(),
  )
}
```

## Signature

```text
reject() string
```
