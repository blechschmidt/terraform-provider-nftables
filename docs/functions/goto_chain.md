---
page_title: "goto_chain function - nftables"
subcategory: ""
description: |-
  Goto another chain (no return)
---

# function: goto_chain

Goto another chain (no return)

## Example Usage

```terraform
resource "nftables_rule" "goto_web" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(443),
    provider::nftables::goto_chain("web_traffic"),
  )
}
```

## Signature

```text
goto_chain(chain string) string
```

## Arguments

1. `chain` (String) Target chain name.
