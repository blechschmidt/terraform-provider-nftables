---
page_title: "clamp_tcp_mss_pmtu function - nftables"
subcategory: ""
description: |-
  Clamp the TCP MSS option to the path MTU of the route
---

# function: clamp_tcp_mss_pmtu

Clamp the TCP MSS option to the path MTU of the route

## Example Usage

```terraform
resource "nftables_rule" "clamp_mss_pmtu" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_flags("syn"),
    provider::nftables::clamp_tcp_mss_pmtu(),
  )
}
```

## Signature

```text
clamp_tcp_mss_pmtu() string
```
