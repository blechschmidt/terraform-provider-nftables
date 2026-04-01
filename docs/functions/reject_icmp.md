---
page_title: "reject_icmp function - nftables"
subcategory: ""
description: |-
  Reject with ICMP code
---

# function: reject_icmp

Reject with ICMP code

## Signature

```text
reject_icmp(code string) string
```

## Arguments

1. `code` (String) ICMP code: port-unreachable, host-unreachable, net-unreachable, admin-prohibited, etc.
