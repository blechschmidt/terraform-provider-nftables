---
page_title: "reject_icmpx function - nftables"
subcategory: ""
description: |-
  Reject with ICMPx code (inet family)
---

# function: reject_icmpx

Reject with ICMPx code (inet family)

## Signature

```text
reject_icmpx(code string) string
```

## Arguments

1. `code` (String) ICMPx code: port-unreachable, admin-prohibited, no-route, host-unreachable
