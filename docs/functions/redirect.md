---
page_title: "redirect function - nftables"
subcategory: ""
description: |-
  Redirect to local port
---

# function: redirect

Redirect to local port

## Example Usage

```terraform
resource "nftables_rule" "redir_proxy" {
  family = "ip"
  table  = "nat"
  chain  = "prerouting"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::redirect(3128),
  )
}
```

## Signature

```text
redirect(port number) string
```

## Arguments

1. `port` (Number) Target local port.
