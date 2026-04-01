---
page_title: "reject_icmpv6 function - nftables"
subcategory: ""
description: |-
  Reject with ICMPv6 code
---

# function: reject_icmpv6

Reject with ICMPv6 code

## Signature

```text
reject_icmpv6(code string) string
```

## Arguments

1. `code` (String) ICMPv6 code: no-route, admin-prohibited, addr-unreachable, port-unreachable
