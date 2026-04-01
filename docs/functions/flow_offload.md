---
page_title: "flow_offload function - nftables"
subcategory: ""
description: |-
  Offload flow to named flowtable
---

# function: flow_offload

Offload flow to named flowtable

## Example Usage

```terraform
resource "nftables_rule" "offload" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["established"]),
    provider::nftables::flow_offload("fastpath"),
  )
}
```

## Signature

```text
flow_offload(name string) string
```

## Arguments

1. `name` (String) Flowtable name.
